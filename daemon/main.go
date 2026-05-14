// bpfaudit-daemon — reads /dev/bpfaudit, batches events, forwards to attestor
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"crypto/tls"
    "crypto/x509"
)

const (
	AUDIT_EVENT_HEARTBEAT = 10
	AUDIT_EVENT_BATCH_ANCHOR = 6
	RECORD_SIZE           = 152
	ATTESTOR_URL          = "http://127.0.0.1:9000/ingest"
	DEVICE                = "/dev/bpfaudit"
)

type AuditRecord struct {
    Seq         uint64
    TimestampNs uint64
    EventType   uint8
    Source      uint8
    Pad         [6]uint8   
    Pid         uint32
    Tgid        uint32
    Uid         uint32
    Gid         uint32
    CgroupId    uint64
    PidNsId     uint64
    ProgId      uint32
    ProgType    uint32
    ProgTag     [8]uint8
    Comm        [16]byte
    Path        [64]byte
}

type WireRecord struct {
	Seq         uint64 `json:"seq"`
	TimestampNs uint64 `json:"timestamp_ns"`
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

func toWire(r *AuditRecord) WireRecord {
	return WireRecord{
		Seq:         r.Seq,
		TimestampNs: r.TimestampNs,
		Pid:         r.Pid,
		Tgid:        r.Tgid,
		Uid:         r.Uid,
		Gid:         r.Gid,
		CgroupId:    r.CgroupId,
		PidNsId:     r.PidNsId,
		ProgId:      r.ProgId,
		ProgType:    r.ProgType,
		EventType:   r.EventType,
		Source:      r.Source,
		ProgTag:     fmt.Sprintf("%x", r.ProgTag),
		Comm:        nullStr(r.Comm[:]),
		Path:        nullStr(r.Path[:]),
	}
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}



/*------- mTLS ------- */
var tlsClient *http.Client
func init() {
    caCert, err := os.ReadFile("/etc/bpfaudit/certs/ca-cert.pem")
    if err != nil {
        log.Fatalf("ca-cert.pem: %v", err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

    cert, err := tls.LoadX509KeyPair(
	"/etc/bpfaudit/certs/client-cert.pem", "/etc/bpfaudit/certs/client-key.pem")
    if err != nil {
        log.Fatalf("client cert: %v", err)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caPool,
		InsecureSkipVerify: true,
    }

    tlsClient = &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
        Timeout:   10 * time.Second,
    }
}
/*---------------------*/

func send(batch Batch) {
	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("[DAEMON] marshal error: %v", err)
		return
	}

	req, err := http.NewRequest("POST", "https://127.0.0.1:9000/ingest", bytes.NewReader(data))
    if err != nil {
        log.Printf("[DAEMON] req error: %v", err)
        return
    }
	req.Header.Set("Content-Type", "application/json")

	resp, err := tlsClient.Do(req)
    if err != nil {
        log.Printf("[DAEMON] send error: %v", err)
        return
    }

	resp.Body.Close()
	log.Printf("[DAEMON] sent batch heartbeat=%v records=%d hash=%s",
		batch.IsHeartbeat, len(batch.Records), batch.KernelHash)
}


func main() {
	dev, err := os.Open(DEVICE)
	if err != nil {
		log.Fatalf("[DAEMON] open %s: %v", DEVICE, err)
	}
	defer dev.Close()
	log.Printf("[DAEMON] reading %s → %s", DEVICE, ATTESTOR_URL)


	var pendingRecords []WireRecord
    rawBuf := make([]byte, RECORD_SIZE)

	for {
		_, err := dev.Read(rawBuf)
		if err != nil {
			log.Printf("[DAEMON] read error: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}

		eventType := rawBuf[16]

		// chech if HEARTBEAT
		if eventType == AUDIT_EVENT_HEARTBEAT {
			var rec AuditRecord
			if err := binary.Read(bytes.NewReader(rawBuf), binary.LittleEndian, &rec); 
			   err != nil {
				log.Printf("[DAEMON] decode error: %v", err)
				continue
			}
			send(Batch{IsHeartbeat: true, Records: []WireRecord{toWire(&rec)}})
			continue
		}

		if eventType == AUDIT_EVENT_BATCH_ANCHOR {
			endSeq     := binary.LittleEndian.Uint64(rawBuf[24:32])
			kernelHash := fmt.Sprintf("%x", rawBuf[32:64])
			sig        := fmt.Sprintf("%x", rawBuf[64:96])
			split := 0

			log.Printf("[DAEMON] anchor endSeq=%d hash=%s sig=%s", endSeq, kernelHash, sig)
			log.Printf("[DAEMON] anchor received, pendingRecords=%d", len(pendingRecords))

			for i, wr := range pendingRecords {
        		if wr.Seq > endSeq {
            		break
        		}
        		split = i + 1
    		}

    		if split > 0 {
				log.Printf("split is = %d",split)
        		send(Batch{
            		IsHeartbeat: false,
            		KernelHash:  kernelHash,
            		Signature:   sig,
            		Records:     pendingRecords[:split],
        		})
        		pendingRecords = pendingRecords[split:]
    		} else if len(pendingRecords) > 0 {
                log.Printf("[DAEMON] GAP: anchor endSeq=%d but first pending=%d", 
					endSeq, pendingRecords[0].Seq)
			}
            continue
		}
		// regular event 
		var rec AuditRecord
		if err := binary.Read(bytes.NewReader(rawBuf), binary.LittleEndian, &rec); err != nil {
			log.Printf("[DAEMON] decode error: %v", err)
			continue
		}
		pendingRecords = append(pendingRecords, toWire(&rec))
	}
}
