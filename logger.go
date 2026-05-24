package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
)

// LogItem represents a structured log entry sent across the mesh.
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
}

// RPCLogger provides an asynchronous logging client that falls back to a local WAL.
type RPCLogger struct {
	rpcManager  *secure_network.RPCManager
	localWAL    *ultimate_db.BatchingWAL
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewRPCLogger initializes a new async mesh logger with local WAL persistence.
func NewRPCLogger(rpc *secure_network.RPCManager, serviceName string, bufferSize int, walPath string) (*RPCLogger, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize the local WAL for offline buffering
	wal, err := ultimate_db.NewBatchingWAL(walPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize local logger WAL: %w", err)
	}

	l := &RPCLogger{
		rpcManager:  rpc,
		localWAL:    wal,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	l.wg.Add(1)
	go l.processQueue()

	return l, nil
}

// Info logs an informational message asynchronously.
func (l *RPCLogger) Info(message string) {
	l.SendAsync("INFO", message)
}

// Error logs an error message asynchronously.
func (l *RPCLogger) Error(message string) {
	l.SendAsync("ERROR", message)
}

// Debug logs a debug message asynchronously.
func (l *RPCLogger) Debug(message string) {
	l.SendAsync("DEBUG", message)
}

// SendAsync queues a log entry, falling back to disk if the channel is congested.
func (l *RPCLogger) SendAsync(level, message string) {
	item := LogItem{
		Timestamp: time.Now().UnixNano(),
		Level:     level,
		Message:   message,
		Service:   l.serviceName,
	}

	select {
	case l.queue <- item:
		// Queued in memory successfully
	default:
		// Queue is full. Do not drop the log, persist it locally.
		l.persistLocally(item, "queue_full")
	}
}

// processQueue handles transmitting logs via RPC.
func (l *RPCLogger) processQueue() {
	defer l.wg.Done()

	for {
		select {
		case <-l.ctx.Done():
			l.flush()
			return
		case item, ok := <-l.queue:
			if !ok {
				return
			}
			l.dispatchRPC(item)
		}
	}
}

// dispatchRPC attempts to send the log over the mesh. If it fails, it saves to the WAL.
func (l *RPCLogger) dispatchRPC(item LogItem) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := l.rpcManager.Call(ctx, "system.log", item)
	if err != nil {
		l.persistLocally(item, fmt.Sprintf("rpc_failed: %v", err))
	}
}

// persistLocally writes a failed log to the ultimate_db WAL.
func (l *RPCLogger) persistLocally(item LogItem, reason string) {
	data, err := json.Marshal(item)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to marshal log for WAL: %v\n", err)
		return
	}

	// Persist to local WAL using the engine signature:
	// Append(txnID uint64, expiresAt int64, id PageID, key, value []byte)
	txnID := uint64(0)
	expiresAt := time.Now().Add(24 * time.Hour).UnixNano()
	pageID := ultimate_db.PageID(999)
	key := []byte(fmt.Sprintf("offline_log:%d", item.Timestamp))

	err = l.localWAL.Append(txnID, expiresAt, pageID, key, data)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to append to local WAL: %v\n", err)
		return
	}
	
	fmt.Printf("[LOGGER OFFLINE] Log saved to local WAL due to: %s\n", reason)
}

// flush empties the queue safely during application shutdown.
func (l *RPCLogger) flush() {
	close(l.queue)
	for item := range l.queue {
		l.persistLocally(item, "node_shutdown")
	}
}

// Close safely flushes the logger and closes the local WAL.
func (l *RPCLogger) Close() {
	l.cancel()
	l.wg.Wait()
	l.localWAL.Close()
}
