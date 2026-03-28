// Package symbols resolves addresses to function names via /proc maps
// and ELF symbol tables.
package symbols

import (
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Mapping represents a single memory-mapped region from /proc/<pid>/maps.
type Mapping struct {
	StartAddr uint64
	EndAddr   uint64
	Offset    uint64
	Path      string
}

// Resolver translates instruction pointer addresses into function names
// by reading /proc/<pid>/maps and ELF symbol tables.
type Resolver struct {
	pid      uint32
	mappings []Mapping // sorted by StartAddr

	mu    sync.RWMutex
	cache map[uint64]string

	elfMu    sync.RWMutex
	elfCache map[string]*elfSymbols // path → sorted symbol table
}

// NewResolver creates a Resolver for the given pid by reading its /proc maps.
func NewResolver(pid uint32) (*Resolver, error) {
	r := &Resolver{
		pid:      pid,
		cache:    make(map[uint64]string),
		elfCache: make(map[string]*elfSymbols),
	}
	if err := r.Refresh(); err != nil {
		return nil, err
	}
	return r, nil
}

// Resolve translates an instruction pointer address into a human-readable
// string of the form "<path>+0x<offset>". Results are cached.
func (r *Resolver) Resolve(addr uint64) string {
	r.mu.RLock()
	if s, ok := r.cache[addr]; ok {
		r.mu.RUnlock()
		return s
	}
	r.mu.RUnlock()

	s := r.resolve(addr)

	r.mu.Lock()
	r.cache[addr] = s
	r.mu.Unlock()

	return s
}

func (r *Resolver) resolve(addr uint64) string {
	i := sort.Search(len(r.mappings), func(i int) bool {
		return r.mappings[i].StartAddr > addr
	})
	// i is the first mapping whose StartAddr > addr, so i-1 is the candidate.
	if i == 0 {
		return fmt.Sprintf("[unknown 0x%x]", addr)
	}
	m := r.mappings[i-1]
	if addr >= m.EndAddr {
		return fmt.Sprintf("[unknown 0x%x]", addr)
	}
	offset := addr - m.StartAddr + m.Offset
	name := m.Path
	if name == "" {
		name = "[anon]"
	}
	return fmt.Sprintf("%s+0x%x", name, offset)
}

// Refresh re-reads /proc/<pid>/maps to pick up dynamically loaded code.
func (r *Resolver) Refresh() error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return fmt.Errorf("reading proc maps: %w", err)
	}
	mappings, err := ParseProcMaps(data)
	if err != nil {
		return fmt.Errorf("parsing proc maps: %w", err)
	}
	r.mappings = mappings

	r.mu.Lock()
	r.cache = make(map[uint64]string)
	r.mu.Unlock()

	return nil
}

// ParseProcMaps parses the contents of a Linux /proc/<pid>/maps file,
// returning only executable mappings sorted by start address.
func ParseProcMaps(data []byte) ([]Mapping, error) {
	var mappings []Mapping
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m, executable, err := parseMapsLine(line)
		if err != nil {
			return nil, fmt.Errorf("bad maps line %q: %w", line, err)
		}
		if !executable {
			continue
		}
		mappings = append(mappings, m)
	}
	sort.Slice(mappings, func(i, j int) bool {
		return mappings[i].StartAddr < mappings[j].StartAddr
	})
	return mappings, nil
}

// parseMapsLine parses a single line from /proc/<pid>/maps.
// Format: 7f1234-7f5678 r-xp 00001000 08:01 12345  /path/to/lib.so
func parseMapsLine(line string) (Mapping, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Mapping{}, false, fmt.Errorf("too few fields (%d)", len(fields))
	}

	// Parse address range.
	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return Mapping{}, false, fmt.Errorf("bad address range %q", fields[0])
	}
	var start, end uint64
	if _, err := fmt.Sscanf(addrParts[0], "%x", &start); err != nil {
		return Mapping{}, false, fmt.Errorf("bad start addr: %w", err)
	}
	if _, err := fmt.Sscanf(addrParts[1], "%x", &end); err != nil {
		return Mapping{}, false, fmt.Errorf("bad end addr: %w", err)
	}

	// Check execute permission.
	perms := fields[1]
	executable := strings.Contains(perms, "x")

	// Parse offset.
	var offset uint64
	if _, err := fmt.Sscanf(fields[2], "%x", &offset); err != nil {
		return Mapping{}, false, fmt.Errorf("bad offset: %w", err)
	}

	// Path is optional (anonymous mappings have none).
	var path string
	if len(fields) >= 6 {
		path = fields[5]
	}

	return Mapping{
		StartAddr: start,
		EndAddr:   end,
		Offset:    offset,
		Path:      path,
	}, executable, nil
}

// ResolveFunc resolves an instruction pointer to a function name.
// Returns the function name, the library path, and whether the address
// belongs to a Ruby VM library (libruby.so or ruby binary).
func (r *Resolver) ResolveFunc(addr uint64) (funcName, libPath string, isRubyVM bool) {
	i := sort.Search(len(r.mappings), func(i int) bool {
		return r.mappings[i].StartAddr > addr
	})
	if i == 0 {
		return fmt.Sprintf("0x%x", addr), "", false
	}
	m := r.mappings[i-1]
	if addr >= m.EndAddr {
		return fmt.Sprintf("0x%x", addr), "", false
	}

	fileOffset := addr - m.StartAddr + m.Offset
	libPath = m.Path
	isRubyVM = isRubyLibrary(libPath)

	// Try ELF symbol lookup
	syms := r.getELFSymbols(libPath)
	if syms != nil {
		if name := syms.lookup(fileOffset); name != "" {
			return name, libPath, isRubyVM
		}
	}

	// Fallback to path+offset
	name := libPath
	if name == "" {
		name = "[anon]"
	}
	return fmt.Sprintf("%s+0x%x", name, fileOffset), libPath, isRubyVM
}

// isRubyLibrary returns true if the path looks like a Ruby VM library.
func isRubyLibrary(path string) bool {
	base := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		base = path[idx+1:]
	}
	return strings.HasPrefix(base, "libruby") ||
		base == "ruby" ||
		strings.HasPrefix(base, "ruby4") ||
		strings.HasPrefix(base, "ruby3")
}

// --- ELF symbol table cache ---

// elfSymbol is a single symbol from an ELF file.
type elfSymbol struct {
	Addr uint64 // file offset (value - section load addr, or just Value for ET_EXEC)
	Size uint64
	Name string
}

// elfSymbols holds a sorted symbol table for one ELF file.
type elfSymbols struct {
	syms []elfSymbol // sorted by Addr
}

// lookup finds the function containing the given file offset.
func (es *elfSymbols) lookup(fileOffset uint64) string {
	// Binary search for the last symbol whose Addr <= fileOffset.
	i := sort.Search(len(es.syms), func(i int) bool {
		return es.syms[i].Addr > fileOffset
	})
	if i == 0 {
		return ""
	}
	sym := es.syms[i-1]
	// Check if fileOffset is within the symbol's range.
	if sym.Size > 0 && fileOffset >= sym.Addr+sym.Size {
		return ""
	}
	// For symbols with size 0 (common in .dynsym), allow if within
	// a reasonable range (next symbol's address).
	if sym.Size == 0 && i < len(es.syms) && fileOffset >= es.syms[i].Addr {
		return ""
	}
	return sym.Name
}

func (r *Resolver) getELFSymbols(path string) *elfSymbols {
	if path == "" || strings.HasPrefix(path, "[") {
		return nil
	}

	r.elfMu.RLock()
	if syms, ok := r.elfCache[path]; ok {
		r.elfMu.RUnlock()
		return syms
	}
	r.elfMu.RUnlock()

	// Load and parse
	syms := loadELFSymbols(path)

	r.elfMu.Lock()
	r.elfCache[path] = syms
	r.elfMu.Unlock()

	return syms
}

// loadELFSymbols reads .symtab and .dynsym from an ELF file.
func loadELFSymbols(path string) *elfSymbols {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	var allSyms []elfSymbol

	// Try .symtab first (more complete, but stripped in many prod binaries)
	if symbols, err := f.Symbols(); err == nil {
		for _, s := range symbols {
			if s.Info&0xf == uint8(elf.STT_FUNC) && s.Value > 0 {
				allSyms = append(allSyms, elfSymbol{
					Addr: s.Value,
					Size: s.Size,
					Name: s.Name,
				})
			}
		}
	}

	// Also try .dynsym (always present in shared libs)
	if symbols, err := f.DynamicSymbols(); err == nil {
		for _, s := range symbols {
			if s.Info&0xf == uint8(elf.STT_FUNC) && s.Value > 0 {
				allSyms = append(allSyms, elfSymbol{
					Addr: s.Value,
					Size: s.Size,
					Name: s.Name,
				})
			}
		}
	}

	if len(allSyms) == 0 {
		return nil
	}

	// Sort by address and deduplicate
	sort.Slice(allSyms, func(i, j int) bool {
		return allSyms[i].Addr < allSyms[j].Addr
	})

	// Deduplicate (prefer .symtab entries with size over .dynsym without)
	deduped := make([]elfSymbol, 0, len(allSyms))
	for i, s := range allSyms {
		if i > 0 && s.Addr == allSyms[i-1].Addr {
			// Keep the one with size > 0
			if s.Size > 0 && deduped[len(deduped)-1].Size == 0 {
				deduped[len(deduped)-1] = s
			}
			continue
		}
		deduped = append(deduped, s)
	}

	return &elfSymbols{syms: deduped}
}
