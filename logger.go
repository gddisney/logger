package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/ultimate_db"
)

// LogItem represents a structured log entry for the Identity Fabric.
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
	Actor     string `json:"actor,omitempty"`
	Action    string `json:"action,omitempty"`
}

// Exporter defines the interface for custom log targets (SIEM, RPC, etc.)
// Register your custom exporters to make this logger part of your SIEM infrastructure.
type Exporter interface {
	Export(item LogItem) error
}

// LogDispatcher manages the async pipeline and exporter registry.
type LogDispatcher struct {
	exporters   []Exporter
	exportersMu sync.RWMutex
	db          *ultimate_db.DB
	logPage     ultimate_db.PageID
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewLogDispatcher initializes the pub/sub logging system backed by ultimate_db.
func NewLogDispatcher(serviceName string, db *ultimate_db.DB, logPage ultimate_db.PageID, bufferSize int) (*LogDispatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ld := &LogDispatcher{
		exporters:   []Exporter{},
		db:          db,
		logPage:     logPage,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	ld.wg.Add(1)
	go ld.processQueue()

	return ld, nil
}

// RegisterExporter adds a new destination (e.g., SIEM, RPC) to the dispatcher.
func (ld *LogDispatcher) RegisterExporter(e Exporter) {
	ld.exportersMu.Lock()
	defer ld.exportersMu.Unlock()
	ld.exporters = append(ld.exporters, e)
}

// send adds an item to the queue and triggers DB persistence.
func (ld *LogDispatcher) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = ld.serviceName

	// 1. Immediate transactional write to ultimate_db for indexing
	ld.persistToDB(item)

	// 2. Queue for asynchronous external export
	select {
	case ld.queue <- item:
	default:
		// Drop log if queue is full to prevent blocking the calling thread
	}
}

// persistToDB commits the log to the indexed ultimate_db store.
func (ld *LogDispatcher) persistToDB(item LogItem) {
	data, _ := json.Marshal(item)
	key := []byte(fmt.Sprintf("log:%d", item.Timestamp))
	
	txn := ld.db.BeginTxn()
	// Using 0 as TTL for permanent audit storage
	_ = ld.db.Write(ld.logPage, txn, key, data, 0)
	ld.db.CommitTxn(txn)
}

// processQueue handles the background pub/sub distribution.
func (ld *LogDispatcher) processQueue() {
	defer ld.wg.Done()
	for {
		select {
		case <-ld.ctx.Done():
			return
		case item, ok := <-ld.queue:
			if !ok {
				return
			}
			ld.dispatch(item)
		}
	}
}

// dispatch sends the item to all registered exporters.
func (ld *LogDispatcher) dispatch(item LogItem) {
	ld.exportersMu.RLock()
	defer ld.exportersMu.RUnlock()

	for _, exp := range ld.exporters {
		// Individual exporter failures are logged silently to avoid breaking the dispatcher
		_ = exp.Export(item)
	}
}

// --- Standard Logging Interface ---

func (ld *LogDispatcher) Info(message string) {
	ld.send(LogItem{Level: "INFO", Message: message})
}

func (ld *LogDispatcher) Error(message string) {
	ld.send(LogItem{Level: "ERROR", Message: message})
}

func (ld *LogDispatcher) Debug(message string) {
	ld.send(LogItem{Level: "DEBUG", Message: message})
}

func (ld *LogDispatcher) Audit(actor, action, message string) {
	ld.send(LogItem{Level: "AUDIT", Actor: actor, Action: action, Message: message})
}

// Close gracefully shuts down the dispatcher.
func (ld *LogDispatcher) Close() {
	ld.cancel()
	ld.wg.Wait()
}
