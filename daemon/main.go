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

type Config struct {
	BPF struct {
		LSM     link.Link
		BPFPATH *string
	}

	Logs struct {
		Event *os.File
		Alert *os.File
	}

	Device *os.File
}

func main() {
	cfg, err := ParseFlags()
	if err != nil {
		log.Fatalf("parsing flags: %v", err)
	}

	coll, lsmLink, err := LoadBPF(&cfg)
	if err != nil {
		log.Fatalf("load BPF: %v", err)
	}

	cfg.BPF.LSM = lsmLink

	defer coll.Close()
	defer cfg.Close()

	lsmMap := coll.Maps["lsm_counter"]
	key := uint32(0)

	readCounter := func() (lsm uint64) {
		if lsmMap != nil {
			lsmMap.Lookup(&key, &lsm)
		}
		return
	}

	RunReader(cfg.Device, readCounter, cfg.Logs.Event)
}

// ---------------- Reader ----------------

func RunReader(dev *os.File, readCounter func() (uint64), eventLog *os.File) {
	log.Println("device open, reading events...")

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

		lsm := readCounter()

		line := fmt.Sprintf(
			"seq=%-4d pid=%-6d uid=%-6d comm=%-16s event=%d source=%d hash=%s | lsm=%-4d \n",
			rec.Seq,
			rec.Pid,
			rec.Uid,
			string(bytes.TrimRight(rec.Comm[:], "\x00")),
			rec.EventType,
			rec.Source,
			hex.EncodeToString(rec.CurrHash[:8]),
			lsm,
		)

		// stdout
		fmt.Print(line)

		// file
		if eventLog != nil {
			if _, err := eventLog.WriteString(line); err != nil {
				log.Printf("log write failed: %v", err)
			}
		}
	}
}

// ---------------- Config ----------------

func ParseFlags() (Config, error) {
	var cfg Config

	ebpfPath := flag.String("ebpf", "../ebpf/audit.bpf.o", "path to eBPF object file")
	devPath := flag.String("device", "/dev/bpfledger", "ledger device node")
	eventLogPath := flag.String("eventLog", "/var/log/bpfaudit/event.log", "bpf events log")
	alertLogPath := flag.String("alertLog", "/var/log/bpfaudit/alert.log", "bpf alerts log")

	flag.Parse()

	dev, err := os.Open(*devPath)
	if err != nil {
		return cfg, fmt.Errorf("open device: %w", err)
	}
	cfg.Device = dev

	eventLog, err := os.OpenFile(*eventLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		dev.Close()
		return cfg, fmt.Errorf("open event log: %w", err)
	}

	alertLog, err := os.OpenFile(*alertLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		eventLog.Close()
		dev.Close()
		return cfg, fmt.Errorf("open alert log: %w", err)
	}

	cfg.Logs.Event = eventLog
	cfg.Logs.Alert = alertLog
	cfg.BPF.BPFPATH = ebpfPath

	return cfg, nil
}

func (c *Config) Close() {
	if c.BPF.LSM != nil {
		c.BPF.LSM.Close()
	}
	if c.Logs.Event != nil {
		c.Logs.Event.Close()
	}
	if c.Logs.Alert != nil {
		c.Logs.Alert.Close()
	}
	if c.Device != nil {
		c.Device.Close()
	}
}

// ---------------- BPF ----------------

func LoadBPF(cfg *Config) (*ebpf.Collection, link.Link, error) {

	path := *cfg.BPF.BPFPATH

	log.Printf("loading BPF from %s", path)

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}

	lsmProg := coll.Programs["audit_lsm_prog_load"]

	if lsmProg == nil {
		coll.Close()
		return nil, nil, fmt.Errorf("program not found")
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: lsmProg})
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("LSM attach failed: %w", err)
	}

	log.Println("LSM attached")

	return coll, lsmLink, nil
}
