package export

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// FileExporter writes events to a length-delimited protobuf file.
// Implements collector.Exporter.
type FileExporter struct {
	mu   sync.Mutex
	file *os.File
	path string
}

var _ collector.Exporter = (*FileExporter)(nil)

// NewFileExporter opens (or creates) the target file for writing.
func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("file exporter: open %s: %w", path, err)
	}
	return &FileExporter{file: f, path: path}, nil
}

// Export serializes a decoded event and appends it to the file.
func (e *FileExporter) Export(_ context.Context, event any) error {
	// Serialize the event as a type-tagged raw record.
	switch ev := event.(type) {
	case *collector.RubySampleEvent:
		return e.WriteRaw("rbscope.RubySampleEvent", ev.StackData)
	case *collector.RubySpanEvent:
		return e.WriteRaw("rbscope.RubySpanEvent", nil)
	case *collector.IOEvent:
		return e.WriteRaw("rbscope.IOEvent", nil)
	case *collector.SchedEvent:
		return e.WriteRaw("rbscope.SchedEvent", nil)
	default:
		return nil
	}
}

// Flush is a no-op — file writes are synchronous.
func (e *FileExporter) Flush(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.file.Sync()
}

// Write appends a protobuf-encoded event to the file. Each record is prefixed
// with a 4-byte little-endian length.
func (e *FileExporter) Write(msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("file exporter: marshal: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Write length prefix.
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := e.file.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("file exporter: write length: %w", err)
	}
	if _, err := e.file.Write(data); err != nil {
		return fmt.Errorf("file exporter: write data: %w", err)
	}
	return nil
}

// WriteRaw wraps arbitrary bytes in an anypb.Any and writes them.
func (e *FileExporter) WriteRaw(typeURL string, value []byte) error {
	msg := &anypb.Any{
		TypeUrl: typeURL,
		Value:   value,
	}
	return e.Write(msg)
}

// Close flushes pending data and closes the file.
func (e *FileExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.file.Sync(); err != nil {
		return fmt.Errorf("file exporter: sync: %w", err)
	}
	return e.file.Close()
}
