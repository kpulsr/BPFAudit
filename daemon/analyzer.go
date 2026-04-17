package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

/** BPF lifecycle events
 * matches the existing LLKM events
 */

const (
	EventLoad   = 0
	EventFree   = 1
	EventPin    = 2
	EventGet    = 3
	EventAttach = 4
	EventDetach = 5
	EventIntent = 9
)

// BPF program lifecycle tracking string
type ProgramPhase string

const (
	PhasePending   ProgramPhase = "PENDING"
	PhaseActive    ProgramPhase = "ACTIVE"
	PhaseDetached  ProgramPhase = "DETACHED"
	PhaseDestroyed ProgramPhase = "DESTROYED" // FREE event
)

// BPF program data and tracking state
// for each BPF program
type ProgramState struct {
	ID          uint32       `json:"prog_id"`
	Tag         string       `json:"prog_tag"`
	Comm        string       `json:"comm"`
	Pid         uint32       `json:"pid"`
	Seq         uint64       `json:"seq"`
	PidNsId     uint64       `json:"pid_ns_id"`
	Hash        string       `json:"curr_hash"`
	Phase       ProgramPhase `json:"phase"`
	IsPinned    bool         `json:"is_pinned"`
	LoadTime    time.Time    `json:"-"`
	LastUpdate  time.Time    `json:"-"`
	HasAttached bool         `json:"-"`
}

type Analyzer struct {
	mu          sync.Mutex
	baseline    map[string]bool
	baselineDb  string
	tracker     map[uint32]*ProgramState
	ledgerLog   *os.File
	alertLog    *os.File
	Enforce     bool
	LearningEnd time.Time
}

/**
 * Analyzer instance :
 * 		1. reading the baseline programs TAGs (can be learned to extend it)
 * 		2. load tags to memory for fast check
 * 		3. save ti baseline if the Enforce memeber is 0 to learn new tags
 * 		4. runs anomaly sweeper goroutine whith a time ticker
 * 			to analyse for any GHOST programs + future heartbeat feature
 * 			for remote attestor for safety
 * 		5. process each record event
 * 		6. json logs to alert / ledger log for persistent data
 */
func NewAnalyzer(dbFile string, ledgerLog *os.File, alertLog *os.File) *Analyzer {
	a := &Analyzer{
		baseline:    make(map[string]bool),
		baselineDb:  dbFile,
		tracker:     make(map[uint32]*ProgramState),
		ledgerLog:   ledgerLog,
		alertLog:    alertLog,
		Enforce:     false,
		LearningEnd: time.Now().Add(2 * time.Minute),
	}
	a.loadBaseline()
	go a.anomalySweeper()
	return a
}

/**
 * Load tags to memory :
 * supposed we have 1000 BPF program tag in production server
 * 1000 x 8B = 8000B around 8KB, which is cheap
 */
func (a *Analyzer) loadBaseline() {
	data, err := os.ReadFile(a.baselineDb)
	if err != nil {
		log.Printf("[Analyzer] Starting fresh baseline. No %s found.", a.baselineDb)
		return
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		tag := strings.TrimSpace(string(line))
		if tag != "" {
			a.baseline[tag] = true
		}
	}
	log.Printf("[Analyzer] Baseline loaded: %d trusted program tags", len(a.baseline))
}

/**
 * save new learned data if Enforce member = 0
 * write + append only .db file
 */
func (a *Analyzer) saveBaseline(tag string) {
	if a.baseline[tag] {
		return
	}
	os.MkdirAll("/var/lib/bpfaudit", 0700)
	f, err := os.OpenFile(a.baselineDb, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(tag + "\n")
	a.baseline[tag] = true
}

/**
 * write logs in json with timestamps
 */
func (a *Analyzer) writeJSON(state *ProgramState, eventName string) {
	if a.ledgerLog == nil {
		return
	}
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"event":     eventName,
		"state":     state,
	}
	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[Warn] Failed to marshal JSON for event %s: %v", eventName, err)
		return
	}
	a.ledgerLog.Write(append(jsonData, '\n'))
}

/**
 * ProceeEvent :
 * 		1. extract program tag sent from the ledger
 * 		2. check if the tag exists in the tracker state
 * 			id does not exists! creates a pending state
 * 			assumption : it was loaded before our program loads
 * 		3. switch on Event type and handle event logic
 */
func (a *Analyzer) ProcessEvent(rec *AuditRecord, chainBroken bool) {
	if rec.ProgId == 0 && rec.EventType != EventIntent {
		return
	}

	tag := hex.EncodeToString(rec.ProgTag[:])
	comm := string(bytes.TrimRight(rec.Comm[:], "\x00"))

	a.mu.Lock()
	state, exists := a.tracker[rec.ProgId]
	if !exists && rec.EventType != EventIntent && rec.EventType != EventLoad {
		state = &ProgramState{ID: rec.ProgId, Tag: tag, Comm: comm, Phase: PhasePending, HasAttached: true}
		a.tracker[rec.ProgId] = state
	}
	a.mu.Unlock()

	if state == nil && rec.EventType != EventLoad && rec.EventType != EventIntent {
		log.Printf("[Warn] Event %d for untracked prog %d - skipping", rec.EventType, rec.ProgId)
		return
	}

	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	switch rec.EventType {
	case EventIntent:
		a.writeJSON(&ProgramState{ID: 0, Phase: "INTENT", Comm: comm}, "INTENT")

	case EventLoad:
		state = &ProgramState{
			ID: rec.ProgId, Tag: tag, Comm: comm, Pid: rec.Pid, Seq: rec.Seq,
			PidNsId: rec.PidNsId, Hash: fmt.Sprintf("%016x", rec.CurrHash),
			Phase: PhasePending, LoadTime: now, LastUpdate: now,
		}
		a.tracker[rec.ProgId] = state
		a.writeJSON(state, "LOADED")

	case EventAttach:
		state.Phase = PhaseActive
		state.HasAttached = true
		state.LastUpdate = now
		a.writeJSON(state, "ATTACHED")

		if !a.baseline[state.Tag] {
			alertMsg := fmt.Sprintf("[ALERT] UNAUTHORIZED EXECUTION! PID:%d Tag:%s\n", rec.Pid, tag)
			log.Print(alertMsg)
			if now.Before(a.LearningEnd) && !a.Enforce {
				a.saveBaseline(state.Tag)
			}
		}

	case EventPin:
		state.IsPinned = true
		state.LastUpdate = now
		a.writeJSON(state, "PINNED")

	case EventDetach:
		state.Phase = PhaseDetached
		state.LastUpdate = now
		a.writeJSON(state, "DETACHED")

	case EventFree:
		/** feature probe */
		if !state.HasAttached && now.Sub(state.LoadTime) < (50*time.Millisecond) {
			delete(a.tracker, rec.ProgId)
			return
		}
		state.Phase = PhaseDestroyed
		a.writeJSON(state, "FREED")
		delete(a.tracker, rec.ProgId)
	}
}

/**
 * Sweeper :
 *  will check for possible GHOST programs
 *  where a GHOST program is a program that
 * 	dettached and not pinned and not freed and X seconds window
 */
func (a *Analyzer) anomalySweeper() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		a.mu.Lock()

		for _, s := range a.tracker {
			if !s.IsPinned && s.Phase == PhaseDetached && now.Sub(s.LastUpdate) > 15*time.Second {
				log.Printf("[GHOST ALERT] ID:%d Tag:%s RCU Evasion Detected\n", s.ID, s.Tag)
			}
		}
		a.mu.Unlock()
	}
}
