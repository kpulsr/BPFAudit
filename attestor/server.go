// bpfaudit-attestor — verifies hash chains, sequence numbers, heartbeat liveness
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"crypto/tls"
    "crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var hmacSecret []byte

func init() {
    raw := os.Getenv("AUDIT_HMAC_KEY")
    b, err := hex.DecodeString(raw)
    if err != nil || len(b) != 32 {
        log.Fatalf("AUDIT_HMAC_KEY must be 64 hex chars")
    }
    hmacSecret = b
}

const (
	LISTEN             = ":9000"
	LEDGER_FILE        = "ledger.json"
	ALERT_FILE         = "alerts.log"
	HEARTBEAT_DEADLINE = 35 * time.Second
)

type WireRecord struct {
	Seq         uint64 `json:"seq"`
	TimestampNs uint64 `json:"timestamp_ns"`
	PrevHash    uint64 `json:"prev_hash"`
	CurrHash    uint64 `json:"curr_hash"`
	Pid         uint32 `json:"pid"`
	Tgid        uint32 `json:"tgid"`
	Uid         uint32 `json:"uid"`
	Gid         uint32 `json:"gid"`
	CgroupId    uint64 `json:"cgroup_id"`
	PidNsId     uint64 `json:"pid_ns_id"`
	ProgId      uint32 `json:"prog_id"`
	ProgType    uint32 `json:"prog_type"`
	EventType   uint8  `json:"event_type"`
	Source      uint8  `json:"source"`
	ProgTag     string `json:"prog_tag"`
	Comm        string `json:"comm"`
	Path        string `json:"path"`
}

type Batch struct {
	IsHeartbeat bool         `json:"is_heartbeat"`
	KernelHash  string       `json:"kernel_hash,omitempty"`
	Signature   string       `json:"signature,omitempty"`
	Records     []WireRecord `json:"records"`
}

type LedgerEntry struct {
	ReceivedAt             time.Time    `json:"received_at"`
	IsHeartbeat            bool         `json:"is_heartbeat"`
	BatchSeqStart          uint64       `json:"batch_seq_start"`
	BatchSeqEnd            uint64       `json:"batch_seq_end"`
	SecsSinceLastHeartbeat float64      `json:"secs_since_last_heartbeat"`
	OK                     bool         `json:"ok"`
	Errors                 []string     `json:"errors,omitempty"`
	Records                []WireRecord `json:"records"`
	KernelHash             string       `json:"kernel_hash,omitempty"`
	Recomputed             string       `json:"recomputed,omitempty"`
	HashOK                 bool         `json:"hash_ok,omitempty"`
	SigOK                  bool         `json:"sig_ok,omitempty"`
}

type Attestor struct {
	mu              sync.Mutex
	lastSeq         uint64
	initialized     bool
	lastHeartbeatAt time.Time
	heartbeatSeen   bool
	ledger          *os.File
	alerts          *os.File
	epochK          [32]byte
	epochNum        uint64
}

func NewAttestor() (*Attestor, error) {
	ledger, err := os.OpenFile(LEDGER_FILE, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	alerts, err := os.OpenFile(ALERT_FILE, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("alerts: %w", err)
	}
	att := &Attestor{ledger: ledger, alerts: alerts}
	copy(att.epochK[:], hmacSecret)
	return att, nil 
}

func (a *Attestor) alert(format string, args ...any) {
	msg := fmt.Sprintf("[CRITICAL] "+format, args...)
	log.Print(msg)
	fmt.Fprintf(a.alerts, "%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}

func (a *Attestor) watchdog() {
	ticker := time.NewTicker(HEARTBEAT_DEADLINE)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		if !a.heartbeatSeen {
			a.mu.Unlock()
			continue
		}
		elapsed := time.Since(a.lastHeartbeatAt)
		if elapsed > HEARTBEAT_DEADLINE {
			a.alert("WATCHDOG: no heartbeat for %.1fs — LKM may be dropped or unloaded!", elapsed.Seconds())
		}
		a.mu.Unlock()
	}
}

func recomputeHash(recs []WireRecord) string {
	h := sha256.New()
	for _, r := range recs {
		var b [168]byte // zero-initialized = matches kernel's zero pad bytes

		binary.LittleEndian.PutUint64(b[0:8], r.Seq)
		binary.LittleEndian.PutUint64(b[8:16], r.TimestampNs)
		binary.LittleEndian.PutUint64(b[16:24], r.PrevHash)
		binary.LittleEndian.PutUint64(b[24:32], r.CurrHash)
		binary.LittleEndian.PutUint32(b[32:36], r.Pid)
		binary.LittleEndian.PutUint32(b[36:40], r.Tgid)
		binary.LittleEndian.PutUint32(b[40:44], r.Uid)
		binary.LittleEndian.PutUint32(b[44:48], r.Gid)
		binary.LittleEndian.PutUint64(b[48:56], r.CgroupId)
		binary.LittleEndian.PutUint64(b[56:64], r.PidNsId)
		binary.LittleEndian.PutUint32(b[64:68], r.ProgId)
		binary.LittleEndian.PutUint32(b[68:72], r.ProgType)
		b[72] = r.EventType
		b[73] = r.Source
		// b[74:80] = _pad[6] — already zero, matches kernel struct

		tag, _ := hex.DecodeString(r.ProgTag)
		copy(b[80:88], tag)      // prog_tag[8]  — exact 8 bytes
		copy(b[88:104], r.Comm)  // comm[16]     — null-padded by zero-init
		copy(b[104:168], r.Path) // path[64]     — null-padded by zero-init

		h.Write(b[:]) // stream into sha256, same as kernel's shash_update per record
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (a *Attestor) verify(batch Batch, now time.Time) LedgerEntry {
	entry := LedgerEntry{
		ReceivedAt:  now,
		IsHeartbeat: batch.IsHeartbeat,
		OK:          true,
		Records:     batch.Records,
	}

	if a.heartbeatSeen {
		entry.SecsSinceLastHeartbeat = now.Sub(a.lastHeartbeatAt).Seconds()
	} else {
		entry.SecsSinceLastHeartbeat = -1
	}

	if len(batch.Records) == 0 {
		entry.OK = false
		entry.Errors = append(entry.Errors, "empty batch")
		return entry
	}

	entry.BatchSeqStart = batch.Records[0].Seq
	entry.BatchSeqEnd = batch.Records[len(batch.Records)-1].Seq

	// ── HEARTBEAT ──
	if batch.IsHeartbeat {
		a.lastHeartbeatAt = now
		a.heartbeatSeen = true
		log.Printf("[ATTESTOR] heartbeat received — watchdog reset")
		return entry
	}

	// ── heartbeat freshness ──
	if a.heartbeatSeen && entry.SecsSinceLastHeartbeat > HEARTBEAT_DEADLINE.Seconds() {
		msg := fmt.Sprintf("batch arrived %.1fs after last heartbeat", entry.SecsSinceLastHeartbeat)
		entry.Errors = append(entry.Errors, msg)
		entry.OK = false
		a.alert("%s", msg)
	}

	first := batch.Records[0]

	// ── sequence gap ──
	if a.initialized && first.Seq != a.lastSeq+1 {
		msg := fmt.Sprintf("seq gap: expected %d got %d", a.lastSeq+1, first.Seq)
		entry.Errors = append(entry.Errors, msg)
		entry.OK = false
		a.alert("%s", msg)
	}

	// ── within-batch chain ──
	for i := 1; i < len(batch.Records); i++ {
		prev := batch.Records[i-1]
		cur := batch.Records[i]
		if cur.Seq != prev.Seq+1 {
			msg := fmt.Sprintf("within-batch seq break: %d → %d", prev.Seq, cur.Seq)
			entry.Errors = append(entry.Errors, msg)
			entry.OK = false
			a.alert("%s", msg)
		}
	}

	// ── advance state ──
	last := batch.Records[len(batch.Records)-1]
	a.lastSeq = last.Seq
	a.initialized = true

	// ── TPM batch hash verification (accumulate across batches) ──

	if batch.KernelHash != "" {
		recomputed := recomputeHash(batch.Records)
		entry.Recomputed = recomputed
		entry.KernelHash = batch.KernelHash
		if recomputed == batch.KernelHash {
			entry.HashOK = true
			log.Printf("[ATTESTOR] hash verified OK for seqs %d..%d",
				batch.Records[0].Seq, batch.Records[len(batch.Records)-1].Seq)
		} else {
			entry.HashOK = false
			entry.OK = false
			a.alert("HASH MISMATCH seqs=%d..%d recomputed=%s kernel=%s",
				batch.Records[0].Seq, batch.Records[len(batch.Records)-1].Seq, recomputed, batch.KernelHash)
		}
	}

	// SIGNATURE VERIFICATION ──
	if batch.Signature == "" {
		entry.SigOK = false
		entry.OK = false
		entry.Errors = append(entry.Errors, "missing signature")
		a.alert("missing signature")
	} else {
    	sigBytes, _ := hex.DecodeString(batch.Signature)
    	hashBytes, _ := hex.DecodeString(batch.KernelHash)

    	mac := hmac.New(sha256.New, a.epochK[:])
    	mac.Write(hashBytes)
    	expected := mac.Sum(nil)

    	if hmac.Equal(expected, sigBytes) {
        	entry.SigOK = true
			next := sha256.Sum256(a.epochK[:])
			copy(a.epochK[:], next[:])
			a.epochNum++
			log.Printf("[ATTESTOR] sig OK epoch=%d", a.epochNum)
    	} else {
        	entry.SigOK = false
        	entry.OK = false
        	entry.Errors = append(entry.Errors, "HMAC INVALID")
        	a.alert("HMAC INVALID seqs=%d..%d", entry.BatchSeqStart, entry.BatchSeqEnd)
    	}
	}

	return entry
}

func (a *Attestor) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var batch Batch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	a.mu.Lock()
	entry := a.verify(batch, now)
	line, _ := json.Marshal(entry)
	fmt.Fprintf(a.ledger, "%s\n", line)
	a.mu.Unlock()

	status := "OK"
	if !entry.OK {
		status = "FAIL"
	}
	log.Printf("[ATTESTOR] batch hb=%v seqs=%d..%d hb_age=%.1fs hash_ok=%v sig_ok=%v → %s",
		batch.IsHeartbeat, entry.BatchSeqStart, entry.BatchSeqEnd,
		entry.SecsSinceLastHeartbeat, entry.HashOK, entry.SigOK, status)

	w.WriteHeader(http.StatusOK)
}

func main() {
	att, err := NewAttestor()
	if err != nil {
		log.Fatalf("[ATTESTOR] init: %v", err)
	}
	defer att.ledger.Close()
	defer att.alerts.Close()

	go att.watchdog()

	caCert, err := os.ReadFile("/etc/bpfaudit/certs/ca-cert.pem")
	if err != nil {
        log.Fatalf("ca-cert.pem: %v", err)
    }

	caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(
		"/etc/bpfaudit/certs/server-cert.pem", "/etc/bpfaudit/certs/server-key.pem")
    if err != nil {
        log.Fatalf("server cert: %v", err)
    }


	tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientCAs:    caPool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }



	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", att.handle)


    server := &http.Server{
        Addr:      LISTEN,
        Handler:   mux,
        TLSConfig: tlsConfig,
    }

	log.Printf("[ATTESTOR] mTLS listening %s", LISTEN)
    if err := server.ListenAndServeTLS("", ""); err != nil {
        log.Fatalf("[ATTESTOR] server: %v", err)
    }

}
