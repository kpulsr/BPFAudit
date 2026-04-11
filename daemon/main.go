package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type AuditRecord struct {
	Seq         uint64
	TimestampNs uint64
	PrevHash    [32]byte
	CurrHash    [32]byte
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	CgroupId    uint64
	ProgId      uint32
	ProgType    uint32
	EventType   uint8
	Source      uint8
	ProgTag     [8]byte
	Comm        [16]byte
	Pad         [2]byte
}

func main() {
	ebpfPath := flag.String("ebpf",   "../ebpf/audit.bpf.o", "path to eBPF object file")
	devPath  := flag.String("device", "/dev/bpfledger",       "ledger device node")
	flag.Parse()

	// 1. Load BPF
	log.Printf("loading BPF from %s", *ebpfPath)
	spec, err := ebpf.LoadCollectionSpec(*ebpfPath)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()
	log.Println("BPF loaded")

	// 2. Attach both at the same time
	lsmProg    := coll.Programs["audit_lsm_prog_load"]
	kprobeProg := coll.Programs["audit_kprobe_prog_load"]

	if lsmProg == nil || kprobeProg == nil {
		log.Fatalf("programs not found in object: lsm=%v kprobe=%v", lsmProg, kprobeProg)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: lsmProg})
	if err != nil {
		log.Fatalf("LSM attach failed: %v", err)
	}
	defer lsmLink.Close()

	kprobeLink, err := link.Kprobe("bpf_prog_load", kprobeProg, nil)
	if err != nil {
		log.Fatalf("kprobe attach failed: %v", err)
	}
	defer kprobeLink.Close()

	log.Println("LSM and kprobe attached")

	lsmMap    := coll.Maps["lsm_counter"]
	kprobeMap := coll.Maps["kprobe_counter"]
	key       := uint32(0)

	// Reset both counters — LSM fired for the kprobe attach itself, start clean
	zero := uint64(0)
	if lsmMap != nil    { lsmMap.Update(&key, &zero, ebpf.UpdateAny) }
	if kprobeMap != nil { kprobeMap.Update(&key, &zero, ebpf.UpdateAny) }

	readCounters := func() (lsm, kprobe uint64) {
		if lsmMap != nil {
			lsmMap.Lookup(&key, &lsm)
		}
		if kprobeMap != nil {
			kprobeMap.Lookup(&key, &kprobe)
		}
		return
	}

	lsm, kprobe := readCounters()
	log.Printf("counters after attach: lsm=%d kprobe=%d", lsm, kprobe)

	// 3. Open device
	log.Printf("opening %s", *devPath)
	dev, err := os.Open(*devPath)
	if err != nil {
		log.Fatalf("open device: %v", err)
	}
	defer dev.Close()
	log.Println("device open, reading events...")

	// 4. Read and print events
	buf := make([]byte, 144)
	for {
		_, err := dev.Read(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}

		var rec AuditRecord
		if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &rec); err != nil {
			log.Printf("parse: %v", err)
			continue
		}

		lsm, kprobe := readCounters()
		fmt.Printf("seq=%-4d pid=%-6d uid=%-6d comm=%-16s event=%d source=%d hash=%s | lsm=%-4d kprobe=%-4d\n",
			rec.Seq,
			rec.Pid,
			rec.Uid,
			string(bytes.TrimRight(rec.Comm[:], "\x00")),
			rec.EventType,
			rec.Source,
			hex.EncodeToString(rec.CurrHash[:8]),
			lsm,
			kprobe,
		)
	}
}
