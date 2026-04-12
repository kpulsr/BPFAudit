package main

import (
	"bytes"
	"unsafe"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
    "encoding/hex"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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
    ProgId       uint32
    ProgType     uint32
    EventType    uint8
    Source       uint8
    ProgTag      [8]byte
    Comm         [16]byte
    BytecodeHash [32]byte
	Extra        [64]byte
	Pad          [6]byte 
}

type Config struct {
	BPF struct {
		LSM     []link.Link
		BPFPATH *string
	}

	Logs struct {
		Event *os.File
		Alert *os.File
	}

	Device *os.File
}


func init() {
    if unsafe.Sizeof(AuditRecord{}) != 192 {
        panic(fmt.Sprintf("AuditRecord size mismatch: %d", unsafe.Sizeof(AuditRecord{})))
    }
}

func main() {
	cfg, err := ParseFlags()
	if err != nil {
		log.Fatalf("parsing flags: %v", err)
	}

	coll, links , err := LoadBPF(&cfg)
	if err != nil {
		log.Fatalf("load BPF: %v", err)
	}

	cfg.BPF.LSM = links

	defer coll.Close()
	defer cfg.Close()


	RunReader(cfg.Device, cfg.Logs.Event)
}

// ---------------- Reader ----------------

func RunReader(dev *os.File, eventLog *os.File) {
	log.Println("device open, reading events...")

	buf := make([]byte, 192)

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

        extraStr := ""
		switch rec.EventType {
			case 2, 3: // PIN, GET
    			extraStr = fmt.Sprintf("path=%s",
        		string(bytes.TrimRight(rec.Extra[:], "\x00")))
			case 4, 5: // ATTACH, DETACH
    			progFd := binary.LittleEndian.Uint32(rec.Extra[:4])
    			extraStr = fmt.Sprintf("prog_fd=%d", progFd)
		}

		line := fmt.Sprintf(
			"seq=%-4d pid=%-6d uid=%-6d comm=%-16s event=%d source=%d hash=%016x blake2b=%s %s \n",
			rec.Seq,
			rec.Pid,
			rec.Uid,
			string(bytes.TrimRight(rec.Comm[:], "\x00")),
			rec.EventType,
			rec.Source,
			rec.CurrHash,
			hex.EncodeToString(rec.BytecodeHash[:]),
			extraStr, 
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
    for _, l := range c.BPF.LSM {
        if l != nil {
            l.Close()
        }
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

func LoadBPF(cfg *Config) (*ebpf.Collection, []link.Link , error) {
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

    programs := []string{
        "audit_lsm_bpf",
        "audit_lsm_prog",
        "audit_lsm_prog_free",
    }

    var links []link.Link

    for _, name := range programs {
        prog := coll.Programs[name]
        if prog == nil {
            coll.Close()
            return nil, nil, fmt.Errorf("program not found: %s", name)
        }

        l, err := link.AttachLSM(link.LSMOptions{Program: prog})
        if err != nil {
            coll.Close()
            return nil, nil, fmt.Errorf("LSM attach failed for %s: %w", name, err)
        }

        links = append(links, l)
        log.Printf("LSM attached: %s", name)
    }

    return coll, links, nil
}
