package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// 208 Bytes Exact ABI Mapping
// record of the actuall current action
// ... could be {INTENT,LOAD,ATTACH,DETTACH,FREE,PIN}
type AuditRecord struct {
	Seq          uint64
	TimestampNs  uint64
	PrevHash     uint64
	CurrHash     uint64
	Pid          uint32
	Tgid         uint32
	Uid          uint32
	Gid          uint32
	CgroupId     uint64
	ReservedPad  uint64
	PidNsId      uint64
	ProgId       uint32
	ProgType     uint32
	EventType    uint8
	Source       uint8
	Pad          [6]byte
	ProgTag      [8]byte
	Comm         [16]byte
	BytecodeHash [32]byte
	Extra        [64]byte // union of data {prog_fd or path for pin event or raw data}
}

func main() {
	os.MkdirAll("/var/log/bpfaudit", 0755)
	ledgerLog, _ := os.OpenFile("/var/log/bpfaudit/ledger.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	alertLog, _ := os.OpenFile("/var/log/bpfaudit/alerts.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	defer ledgerLog.Close()
	defer alertLog.Close()

	dev, err := os.Open("/dev/bpfaudit")
	if err != nil {
		log.Fatalf("Failed to open /dev/bpfaudit: %v", err)
	}

	analyzer := NewAnalyzer("/var/lib/bpfaudit/baseline.db", ledgerLog, alertLog)

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Shutting down")
		dev.Close()
		os.Exit(0)
	}()

	/**
	 * Reader fuction is a function responsible for infit loop read syscall
	 * on a device character created by the LLKM
	 * it does :
	 * 		1. verify chain hash if broken, catching any possible tampering
	 * 		2. run an analyzer which will analyse the output BPF events
	 * 			and BPF programs lifecycle, looking for any suspecious action
	 * 			& logging it into an append only ledger
	 */
	RunReader(dev, analyzer)
}

func RunReader(dev *os.File, analyzer *Analyzer) {
	buf := make([]byte, 208)
	var chainPrevHash uint64 = 0 // SipHash

	for {
		_, err := dev.Read(buf)
		if err != nil {
			// future polling implementation (exists in the char dev fd file_operations)
			if err.Error() == "EAGAIN" || err.Error() == "EINTR" || err.Error() == "EOVERFLOW" {
				continue
			}
			log.Fatalf("Fatal device read error: %v", err)
		}

		var rec AuditRecord
		binary.Read(bytes.NewReader(buf), binary.LittleEndian, &rec)

		chainBroken := (rec.Seq > 0 && rec.PrevHash != chainPrevHash)
		if chainBroken {
			// TODO: log to an alert file  or SIEM interface
			log.Printf("[CRITICAL] CHAIN BREAK seq=%d! Exp=0x%016x Got=0x%016x", rec.Seq, chainPrevHash, rec.PrevHash)
		}
		chainPrevHash = rec.CurrHash

		analyzer.ProcessEvent(&rec, chainBroken)
	}
}
