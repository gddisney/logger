package logger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gddisney/secure_network"
)

// TestRPCLogger_Initialization verifies the logger and local WAL start correctly.
func TestRPCLogger_Initialization(t *testing.T) {
	tempDir := t.TempDir()
	walPath := filepath.Join(tempDir, "test_init.wal")

	// Initialize with a dummy RPC manager (assuming nil peerRoute is safe for init)
	rpcManager := secure_network.NewRPCManager(nil)

	logger, err := NewRPCLogger(rpcManager, "test-node", 100, walPath)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()

	if logger.serviceName != "test-node" {
		t.Errorf("Expected serviceName 'test-node', got %s", logger.serviceName)
	}
	
	if logger.localWAL == nil {
		t.Error("Expected localWAL to be initialized, got nil")
	}
}

// TestRPCLogger_QueueOverflow forces a queue congestion to verify local WAL persistence.
func TestRPCLogger_QueueOverflow(t *testing.T) {
	tempDir := t.TempDir()
	walPath := filepath.Join(tempDir, "test_overflow.wal")

	rpcManager := secure_network.NewRPCManager(nil)

	// Set buffer size to 0. This forces the select statement in SendAsync 
	// to immediately trigger the default case and persist locally.
	logger, err := NewRPCLogger(rpcManager, "test-node", 0, walPath)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Dispatch logs that will immediately overflow the 0-capacity channel
	logger.Info("Overflow message 1")
	logger.Error("Overflow message 2")

	// Close to ensure WAL file syncs correctly
	logger.Close()

	// Verify the WAL file was created and contains data
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Failed to stat WAL file: %v", err)
	}
	
	if info.Size() == 0 {
		t.Errorf("Expected WAL file to contain overflow logs, but file size is 0")
	}
}

// TestRPCLogger_RPCFailure simulates a mesh network failure to verify WAL fallback.
func TestRPCLogger_RPCFailure(t *testing.T) {
	tempDir := t.TempDir()
	walPath := filepath.Join(tempDir, "test_rpc_fail.wal")

	rpcManager := secure_network.NewRPCManager(nil)
	// Since we do not start the RPCManager or provide active mesh peers, 
	// any dispatched RPC calls will inherently fail/timeout.

	logger, err := NewRPCLogger(rpcManager, "test-node", 10, walPath)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// This goes into the queue successfully
	logger.Debug("Network failure message")

	// Close will wait for the queue to process, triggering the RPC attempt.
	// When the RPC fails, it will call persistLocally.
	logger.Close()

	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Failed to stat WAL file: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("Expected WAL file to contain failed RPC logs, but file size is 0")
	}
}

// TestRPCLogger_ShutdownFlush verifies the flush mechanism dumps pending logs to the WAL.
func TestRPCLogger_ShutdownFlush(t *testing.T) {
	tempDir := t.TempDir()
	walPath := filepath.Join(tempDir, "test_shutdown.wal")

	rpcManager := secure_network.NewRPCManager(nil)

	// We use a large buffer so logs sit in memory
	logger, err := NewRPCLogger(rpcManager, "test-node", 100, walPath)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Add logs directly to the queue to bypass the background processor momentarily
	logger.queue <- LogItem{Level: "INFO", Message: "Pending log 1", Service: "test-node"}
	logger.queue <- LogItem{Level: "INFO", Message: "Pending log 2", Service: "test-node"}

	// Trigger flush via shutdown
	logger.Close()

	// Verify the pending logs were dumped to the local disk rather than lost
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Failed to stat WAL file: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("Expected WAL file to contain flushed logs, but file size is 0")
	}
}
