package export

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// FileExporter writes events to a length-delimited protobuf file.
type FileExporter struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// NewFileExporter opens (or creates) the target file for writing.
func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("file exporter: open %s: %w", path, err)
	}
	return &FileExporter{file: f, path: path}, nil
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
