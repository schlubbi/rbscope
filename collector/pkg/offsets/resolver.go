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
	cfuncMu    sync.RWMutex
	cfuncCache map[cfuncKey]string
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

type cfuncKey struct {
	pid    uint32
	epAddr uint64 // the ep value (not the cfp addr)
}

// NewFrameResolver creates a new resolver with the given Ruby offsets.
func NewFrameResolver(off *RubyOffsets) *FrameResolver {
	return &FrameResolver{
		cache:      make(map[frameKey]FrameInfo),
		classCache: make(map[classKey]string),
		cfuncCache: make(map[cfuncKey]string),
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
			info.Line = uint32(lineVal >> 1) //nolint:gosec // line numbers fit in uint32
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
	n, err := f.ReadAt(buf, int64(dataAddr)) //nolint:gosec // process addresses are valid offsets
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
	n, err := f.ReadAt(buf[:], int64(addr)) //nolint:gosec // process addresses are valid offsets
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

const (
	tIMEMO    = 0x1a // T_IMEMO
	imemoMent = 6    // imemo_ment subtype
	imemoIseq = 7    // imemo_iseq subtype
	flUShift  = 12   // FL_USHIFT

	idEntryUnit = 512 // Ruby's ID_ENTRY_UNIT for paged symbol table
)

// ResolveProfileFrame resolves a VALUE returned by rb_profile_frames.
// These VALUEs are T_IMEMO objects — either imemo_iseq (Ruby methods) or
// imemo_ment (C function method entries). The imemo subtype in bits 12-15
// of the flags word determines which resolution path to use.
//
// For iseq frames: reuses Resolve() → iseq.body.location.{label, pathobj}
// For cfunc frames: reads called_id from the method entry → symbol table
func (r *FrameResolver) ResolveProfileFrame(pid uint32, frameVal uint64, line int32) FrameInfo {
	if frameVal == 0 || frameVal&0x7 != 0 || frameVal < 0x1000 {
		return FrameInfo{}
	}

	// Check cache first — profile frame VALUEs are stable per method
	key := frameKey{pid, frameVal}
	r.mu.RLock()
	if info, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		// Override line with the actual call-site line from rb_profile_frames
		if line > 0 {
			info.Line = uint32(line)
		}
		return info
	}
	r.mu.RUnlock()

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304
	if err != nil {
		return FrameInfo{}
	}
	defer func() { _ = f.Close() }()

	// Read RBasic flags to determine imemo subtype
	var flags uint64
	if err := readUint64(f, frameVal, &flags); err != nil {
		return FrameInfo{}
	}

	// Must be T_IMEMO
	if flags&0x1f != tIMEMO {
		return FrameInfo{}
	}

	imemoType := (flags >> flUShift) & 0xf
	var info FrameInfo

	switch imemoType {
	case imemoIseq:
		// Raw iseq object — resolve via iseq.body.location
		resolved, err := r.resolveFromMem(pid, frameVal)
		if err != nil {
			return FrameInfo{}
		}
		info = resolved
		if line > 0 {
			info.Line = uint32(line)
		}

	case imemoMent:
		// Callable method entry (CME). In Ruby 4.0, rb_profile_frames returns
		// CMEs for BOTH Ruby methods and C methods. We must check def->type
		// to distinguish them:
		//   VM_METHOD_TYPE_ISEQ (0) → Ruby method: follow def->body.iseq.iseqptr
		//   VM_METHOD_TYPE_CFUNC (1) → C method: resolve via called_id
		off := r.offsets

		// Read def pointer from CME
		var defPtr uint64
		if err := readUint64(f, frameVal+uint64(off.MEDef), &defPtr); err != nil || defPtr == 0 {
			return FrameInfo{}
		}

		// Read def->type (first byte, bitfield)
		typeBuf := make([]byte, 1)
		if _, err := f.ReadAt(typeBuf, int64(defPtr+uint64(off.DefType))); err != nil {
			return FrameInfo{}
		}
		defType := typeBuf[0] & 0x0f // lower nibble holds the method type

		if defType == 0 { // VM_METHOD_TYPE_ISEQ
			// Ruby method — read iseq pointer from def->body.iseq.iseqptr
			var iseqPtr uint64
			if err := readUint64(f, defPtr+uint64(off.DefBodyIseq), &iseqPtr); err != nil || iseqPtr == 0 {
				return FrameInfo{}
			}
			// Resolve the iseq
			resolved, err := r.resolveFromMem(pid, iseqPtr)
			if err != nil {
				return FrameInfo{}
			}
			info = resolved
			if line > 0 {
				info.Line = uint32(line)
			}
		} else {
			// CFUNC or other method type — resolve via called_id
			name := r.resolveCfuncFromME(pid, f, frameVal)
			if name == "" {
				name = "[cfunc]"
			} else {
				name = name + " [cfunc]"
			}
			info = FrameInfo{Label: name}
		}

	default:
		return FrameInfo{}
	}

	r.mu.Lock()
	r.cache[key] = info
	r.mu.Unlock()

	return info
}

// ResolveCfuncName reads the method name for a cfunc frame via ep[-2] → method entry → called_id.
// The ep value comes from the BPF walker (carried in the pc field for cfunc frames).
func (r *FrameResolver) ResolveCfuncName(pid uint32, ep uint64) string {
	if ep == 0 {
		return ""
	}

	key := cfuncKey{pid, ep}
	r.cfuncMu.RLock()
	if name, ok := r.cfuncCache[key]; ok {
		r.cfuncMu.RUnlock()
		return name
	}
	r.cfuncMu.RUnlock()

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// Read ep[-2] → method entry (or cref)
	var meVal uint64
	if err := readUint64(f, ep-16, &meVal); err != nil {
		return ""
	}
	if meVal == 0 || meVal&0x7 != 0 {
		return ""
	}

	// Check flags: must be T_IMEMO with imemo_ment subtype
	var flags uint64
	if err := readUint64(f, meVal, &flags); err != nil {
		return ""
	}
	if flags&0x1f != tIMEMO {
		return ""
	}
	if (flags>>flUShift)&0xf != imemoMent {
		return ""
	}

	name := r.resolveCfuncFromME(pid, f, meVal)

	r.cfuncMu.Lock()
	r.cfuncCache[key] = name
	r.cfuncMu.Unlock()

	return name
}

// resolveCfuncFromME reads the method name from a validated method entry (imemo_ment).
// meVal must point to a T_IMEMO with imemo_ment subtype (caller validates).
func (r *FrameResolver) resolveCfuncFromME(pid uint32, f *os.File, meVal uint64) string {
	off := r.offsets

	// Read called_id from method entry
	var calledID uint64
	if err := readUint64(f, meVal+uint64(off.MECalledID), &calledID); err != nil {
		return ""
	}

	return r.resolveID(pid, calledID)
}

// resolveID converts a Ruby ID to a method name string using the global symbol table.
// The symbol table is a paged array: ids[serial / 512][serial % 512] → frozen String.
func (r *FrameResolver) resolveID(pid uint32, id uint64) string {
	off := r.offsets
	if off.GlobalSymbolsAddr == 0 || id == 0 {
		return ""
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	serial := id >> 3
	pageIdx := serial / idEntryUnit
	pageOff := serial % idEntryUnit

	// GlobalSymbolsAddr is already the runtime address (base + ELF offset),
	// adjusted in StackWalkerBPF.AttachPID().
	gsAddr := off.GlobalSymbolsAddr

	// Read ids (Array VALUE) from global_symbols + IDs offset
	var idsVal uint64
	if err := readUint64(f, gsAddr+uint64(off.GlobalSymbolsIDs), &idsVal); err != nil {
		return ""
	}

	// Read outer array: heap_len at offset 16, heap_ptr at offset 32
	var outerLen uint64
	if err := readUint64(f, idsVal+16, &outerLen); err != nil {
		return ""
	}
	if pageIdx >= outerLen {
		return ""
	}
	var outerPtr uint64
	if err := readUint64(f, idsVal+32, &outerPtr); err != nil {
		return ""
	}

	// Read page VALUE
	var pageVal uint64
	if err := readUint64(f, outerPtr+pageIdx*8, &pageVal); err != nil || pageVal == 0 {
		return ""
	}

	// Read inner array: len at offset 16, ptr at offset 32
	var innerLen uint64
	if err := readUint64(f, pageVal+16, &innerLen); err != nil {
		return ""
	}
	if pageOff >= innerLen {
		return ""
	}
	var innerPtr uint64
	if err := readUint64(f, pageVal+32, &innerPtr); err != nil {
		return ""
	}

	// Read the entry (frozen String VALUE)
	var entry uint64
	if err := readUint64(f, innerPtr+pageOff*8, &entry); err != nil || entry == 0 {
		return ""
	}

	return readRString(f, entry, off)
}
