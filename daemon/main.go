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
	"strings"
	"time"
)

const (
	AUDIT_EVENT_HEARTBEAT = 10
	RECORD_SIZE           = 168
	BATCH_MAX             = 32
	BATCH_TIMEOUT         = 60 * time.Second
	ATTESTOR_URL          = "http://127.0.0.1:9000/ingest"
	DEVICE                = "/dev/bpfaudit"
)

type AuditRecord struct {
	Seq         uint64
	TimestampNs uint64
	PrevHash    uint64
	CurrHash    uint64
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	CgroupId    uint64
	PidNsId     uint64
	ProgId      uint32
	ProgType    uint32
	EventType   uint8
	Source      uint8
	Pad         [6]uint8
	ProgTag     [8]uint8
	Comm        [16]byte
	Path        [64]byte
}

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
	Records     []WireRecord `json:"records"`
}

func getKernelHash() string {
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile("/sys/class/bpfaudit/bpfaudit/batch_hash")
		if err != nil {
			return ""
		}
		h := strings.TrimSpace(string(b))
		if h != "" {
			return h
		}
		time.Sleep(2 * time.Millisecond)
	}
	return ""
}

func toWire(r *AuditRecord) WireRecord {
	return WireRecord{
		Seq:         r.Seq,
		TimestampNs: r.TimestampNs,
		PrevHash:    r.PrevHash,
		CurrHash:    r.CurrHash,
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

func send(batch Batch) {
	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("[DAEMON] marshal error: %v", err)
		return
	}
	resp, err := http.Post(ATTESTOR_URL, "application/json", bytes.NewReader(data))
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

	var (
		buf   [BATCH_MAX]WireRecord
		count int
		//batchStart time.Time
	)

	//var lastKernelHash string
	rawBuf := make([]byte, RECORD_SIZE)

	for {
		_, err := dev.Read(rawBuf)
		if err != nil {
			log.Printf("[DAEMON] read error: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}

		var rec AuditRecord
		if err := binary.Read(bytes.NewReader(rawBuf), binary.LittleEndian, &rec); err != nil {
			log.Printf("[DAEMON] decode error: %v", err)
			continue
		}

		// chech if HEARTBEAT
		if rec.EventType == AUDIT_EVENT_HEARTBEAT {
			send(Batch{IsHeartbeat: true, Records: []WireRecord{toWire(&rec)}})
			continue
		}

		buf[count] = toWire(&rec)
		count++

		if count == BATCH_MAX {
			kernelHash := getKernelHash()
			toSend := Batch{IsHeartbeat: false, KernelHash: kernelHash, Records: make([]WireRecord, count)}
			copy(toSend.Records, buf[:count])
			count = 0
			send(toSend)
		}
	}
}
