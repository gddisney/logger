package logger

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// LogItem represents a structured log entry with stateless cryptographic attribution.
type LogItem struct {
	Timestamp   int64  `json:"timestamp"`
	Level       string `json:"level"`
	Message     string `json:"message"`
	Service     string `json:"service"`
	Actor       string `json:"actor,omitempty"`
	Action      string `json:"action,omitempty"`
	Attestation string `json:"attestation,omitempty"` // Base64 signature proving origin authenticity
}

// Exporter defines the interface for downstream log streams (SIEM, RPC collectors, etc.)
type Exporter interface {
	Export(item LogItem) error
}

// LogDispatcher manages the stateless, non-blocking attribution signing pipeline.
type LogDispatcher struct {
	exporters   []Exporter
	exportersMu sync.RWMutex
	signingKey  *rsa.PrivateKey
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewLogDispatcher initializes a zero-storage logging pipeline backed by stateless RSA signatures.
func NewLogDispatcher(serviceName string, bufferSize int, privKey *rsa.PrivateKey) (*LogDispatcher, error) {
	if privKey == nil {
		return nil, fmt.Errorf("cannot initialize attribution logging without an active private signing key")
	}

	ctx, cancel := context.WithCancel(context.Background())

	ld := &LogDispatcher{
		exporters:   []Exporter{},
		signingKey:  privKey,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	ld.wg.Add(1)
	go ld.processQueue()

	return ld, nil
}

// RegisterExporter attaches an external streaming target to the dispatcher.
func (ld *LogDispatcher) RegisterExporter(e Exporter) {
	ld.exportersMu.Lock()
	defer ld.exportersMu.Unlock()
	ld.exporters = append(ld.exporters, e)
}

// --- Standard Logging Interface ---

func (ld *LogDispatcher) Info(message string)  { ld.send(LogItem{Level: "INFO", Message: message}) }
func (ld *LogDispatcher) Error(message string) { ld.send(LogItem{Level: "ERROR", Message: message}) }
func (ld *LogDispatcher) Debug(message string) { ld.send(LogItem{Level: "DEBUG", Message: message}) }
func (ld *LogDispatcher) Audit(actor, action, message string) {
	ld.send(LogItem{Level: "AUDIT", Actor: actor, Action: action, Message: message})
}

func (ld *LogDispatcher) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = ld.serviceName

	select {
	case ld.queue <- item:
	default:
		// Drop/Backpressure block: If the queue is backed up, sign synchronously 
		// and attempt immediate delivery to prevent shedding attribution context
		ld.dispatch(item)
	}
}

func (ld *LogDispatcher) processQueue() {
	defer ld.wg.Done()
	for {
		select {
		case <-ld.ctx.Done():
			ld.drain()
			return
		case item, ok := <-ld.queue:
			if !ok {
				return
			}
			ld.dispatch(item)
		}
	}
}

// signForAttribution computes a deterministic hash of the log fields and signs it statelessly.
func (ld *LogDispatcher) signForAttribution(item *LogItem) {
	// Build a deterministic string block matching the log content
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		item.Timestamp,
		item.Level,
		item.Service,
		item.Message,
		item.Actor,
		item.Action,
	)

	hash := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, ld.signingKey, crypto.SHA256, hash[:])
	if err == nil {
		item.Attestation = base64.StdEncoding.EncodeToString(sig)
	}
}

func (ld *LogDispatcher) dispatch(item LogItem) {
	ld.signForAttribution(&item)

	ld.exportersMu.RLock()
	defer ld.exportersMu.RUnlock()

	for _, exp := range ld.exporters {
		_ = exp.Export(item) 
	}
}

// VerifyAttestation can be invoked downstream (e.g., inside your SIEM or analytics layer) 
// to confirm the log has not been modified since ingest.
func VerifyAttestation(item LogItem, pubKey *rsa.PublicKey) bool {
	if item.Attestation == "" || pubKey == nil {
		return false
	}

	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		item.Timestamp,
		item.Level,
		item.Service,
		item.Message,
		item.Actor,
		item.Action,
	)

	sigBytes, err := base64.StdEncoding.DecodeString(item.Attestation)
	if err != nil {
		return false
	}

	hash := sha256.Sum256([]byte(payload))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes)
	return err == nil
}

func (ld *LogDispatcher) drain() {
	close(ld.queue)
	for item := range ld.queue {
		ld.dispatch(item)
	}
}

func (ld *LogDispatcher) Close() {
	ld.cancel()
	ld.wg.Wait()
}
