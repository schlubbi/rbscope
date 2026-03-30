package offsets

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

// FrameInfo holds the resolved method name, file path, and line number
// for a Ruby stack frame.
type FrameInfo struct {
	Label string // method name (e.g., "index")
	Path  string // file path (e.g., "/app/controllers/posts_controller.rb")
	Line  uint32 // first line number of the method
}

// FrameResolver reads Ruby VM structs from /proc/pid/mem to resolve
// iseq addresses to human-readable frame info. Caches results since
// iseq structs are immutable once created.
type FrameResolver struct {
	mu         sync.RWMutex
	cache      map[frameKey]FrameInfo
	classMu    sync.RWMutex
	classCache map[classKey]string
	offsets    *RubyOffsets
}

type frameKey struct {
	pid      uint32
	iseqAddr uint64
}

type classKey struct {
	pid      uint32
	klassVal uint64
}

// NewFrameResolver creates a new resolver with the given Ruby offsets.
func NewFrameResolver(off *RubyOffsets) *FrameResolver {
	return &FrameResolver{
		cache:      make(map[frameKey]FrameInfo),
		classCache: make(map[classKey]string),
		offsets:    off,
	}
}

// Resolve reads the iseq struct at the given address from the target process
// and returns the method name, file path, and line number.
// Results are cached — iseq structs are immutable.
func (r *FrameResolver) Resolve(pid uint32, iseqAddr uint64) (FrameInfo, error) {
	key := frameKey{pid, iseqAddr}

	r.mu.RLock()
	if info, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return info, nil
	}
	r.mu.RUnlock()

	info, err := r.resolveFromMem(pid, iseqAddr)
	if err != nil {
		return FrameInfo{}, err
	}

	r.mu.Lock()
	r.cache[key] = info
	r.mu.Unlock()

	return info, nil
}

// resolveFromMem reads the iseq struct chain from /proc/pid/mem.
// Chain: iseq → body → location → {label, pathobj}
// Each VALUE string is either embedded or heap-allocated.
func (r *FrameResolver) resolveFromMem(pid uint32, iseqAddr uint64) (FrameInfo, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304
	if err != nil {
		return FrameInfo{}, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer func() { _ = f.Close() }()

	off := r.offsets
	info := FrameInfo{}

	// Read body pointer from iseq struct
	body, err := readPtr(f, iseqAddr+uint64(off.IseqBody))
	if err != nil {
		return info, fmt.Errorf("read iseq.body: %w", err)
	}
	if body == 0 {
		return info, nil
	}

	// Read location struct start address (body + location_offset)
	locAddr := body + uint64(off.BodyLocation)

	// Read label VALUE from location
	labelVal, err := readPtr(f, locAddr+uint64(off.LocLabel))
	if err != nil {
		return info, fmt.Errorf("read location.label: %w", err)
	}
	if labelVal != 0 {
		info.Label = readRString(f, labelVal, off)
	}

	// Read pathobj VALUE from location.
	// pathobj can be either a String (simple path) or an Array [path, realpath].
	// Check the type flag to determine which.
	pathobjVal, err := readPtr(f, locAddr+uint64(off.LocPathobj))
	if err != nil {
		return info, fmt.Errorf("read location.pathobj: %w", err)
	}
	if pathobjVal != 0 {
		info.Path = readPathobj(f, pathobjVal, off)
	}

	// Read first_lineno from location (it's a VALUE, might be a fixnum)
	lineVal, err := readPtr(f, locAddr+uint64(off.LocFirstLineno))
	if err == nil && lineVal != 0 {
		// Ruby fixnum: value is (n << 1) | 1
		if lineVal&1 == 1 {
			info.Line = uint32(lineVal >> 1)
		}
	}

	return info, nil
}

// readRString reads a Ruby String value from process memory.
// Handles both embedded and heap-allocated strings.
func readRString(f *os.File, addr uint64, off *RubyOffsets) string {
	// Ruby VALUEs have type tags in the lower bits
	// If it's a special value (nil, true, false, fixnum, symbol), skip
	if addr == 0 || addr&0x7 != 0 {
		// Could be a frozen string literal (symbol or special)
		return ""
	}

	// Read RBasic.flags (first 8 bytes of any Ruby object)
	var flags uint64
	if err := readUint64(f, addr, &flags); err != nil {
		return ""
	}

	// Check if it's actually a T_STRING (type 5)
	// Type is in bits 0-4 of flags: flags & 0x1f
	if flags&0x1f != 0x05 {
		return ""
	}

	// Read string length
	var strLen uint64
	if err := readUint64(f, addr+uint64(off.RStringLen), &strLen); err != nil {
		return ""
	}

	// Cap length to prevent reading huge amounts of data
	if strLen > 1024 {
		strLen = 1024
	}
	if strLen == 0 {
		return ""
	}

	// Check embed flag: if RSTRING_NOEMBED is NOT set, string data is embedded
	isEmbedded := (flags & off.RStringNoEmbed) == 0

	var dataAddr uint64
	if isEmbedded {
		// Embedded: data starts at RString.as.embed.ary (inline in the object)
		dataAddr = addr + uint64(off.RStringEmbedStart)
	} else {
		// Heap: read pointer from RString.as.heap.ptr
		if err := readUint64(f, addr+uint64(off.RStringHeapPtr), &dataAddr); err != nil {
			return ""
		}
	}

	if dataAddr == 0 {
		return ""
	}

	// Read the actual string bytes
	buf := make([]byte, strLen)
	n, err := f.ReadAt(buf, int64(dataAddr))
	if err != nil || n == 0 {
		return ""
	}

	return string(buf[:n])
}

// readPathobj handles the pathobj field which can be either a String or an Array.
// If it's an Array [path, realpath], we read the first element.
func readPathobj(f *os.File, addr uint64, off *RubyOffsets) string {
	if addr == 0 || addr&0x7 != 0 {
		return ""
	}

	// Read flags to determine type
	var flags uint64
	if err := readUint64(f, addr, &flags); err != nil {
		return ""
	}

	objType := flags & 0x1f
	switch objType {
	case 0x05: // T_STRING
		return readRString(f, addr, off)
	case 0x07: // T_ARRAY
		// Read first element: array data starts at offset 16 (after RBasic)
		// For embedded arrays, elements are inline
		// For heap arrays, there's a pointer to the elements
		// Check RARRAY_EMBED_FLAG (FL_USER1 = 1<<13)
		isEmbedded := (flags & (1 << 13)) != 0
		var elemAddr uint64
		if isEmbedded {
			// Embedded: first element at addr + 16 (after RBasic)
			if err := readUint64(f, addr+16, &elemAddr); err != nil {
				return ""
			}
		} else {
			// Heap: read ptr field, then first element
			var ptr uint64
			if err := readUint64(f, addr+24, &ptr); err != nil {
				return ""
			}
			if ptr == 0 {
				return ""
			}
			if err := readUint64(f, ptr, &elemAddr); err != nil {
				return ""
			}
		}
		if elemAddr != 0 {
			return readRString(f, elemAddr, off)
		}
	}

	return ""
}

// readUint64 reads a uint64 from the given address in a file.
func readUint64(f *os.File, addr uint64, out *uint64) error {
	var buf [8]byte
	n, err := f.ReadAt(buf[:], int64(addr))
	if err != nil || n != 8 {
		return fmt.Errorf("read at 0x%x: %w", addr, err)
	}
	*out = binary.LittleEndian.Uint64(buf[:])
	return nil
}

// ResolveClassName reads the class name for a given cfp->self VALUE.
// Chain: self → RBasic.klass → classext.classpath → RString
// Results are cached — class names don't change.
func (r *FrameResolver) ResolveClassName(pid uint32, selfVal uint64) string {
	if selfVal == 0 || selfVal&0x7 != 0 {
		return "" // not a heap object (fixnum, nil, true, false, symbol)
	}

	// Read klass from self (RBasic.klass at offset 8)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	var klassVal uint64
	if err := readUint64(f, selfVal+8, &klassVal); err != nil {
		return ""
	}
	if klassVal == 0 || klassVal&0x7 != 0 {
		return ""
	}

	// Check cache by klass pointer
	key := classKey{pid, klassVal}
	r.classMu.RLock()
	if name, ok := r.classCache[key]; ok {
		r.classMu.RUnlock()
		return name
	}
	r.classMu.RUnlock()

	// Read classpath VALUE from klass + ClassClasspath offset
	off := r.offsets
	if off.ClassClasspath == 0 {
		return ""
	}
	var classpathVal uint64
	if err := readUint64(f, klassVal+uint64(off.ClassClasspath), &classpathVal); err != nil {
		return ""
	}

	name := readRString(f, classpathVal, off)

	r.classMu.Lock()
	r.classCache[key] = name
	r.classMu.Unlock()

	return name
}
