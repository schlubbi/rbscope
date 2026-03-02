package symbols

import (
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
// by reading /proc/<pid>/maps and (optionally) ELF symbol tables.
type Resolver struct {
	pid      uint32
	mappings []Mapping // sorted by StartAddr

	mu    sync.RWMutex
	cache map[uint64]string
}

// NewResolver creates a Resolver for the given pid by reading its /proc maps.
func NewResolver(pid uint32) (*Resolver, error) {
	r := &Resolver{
		pid:   pid,
		cache: make(map[uint64]string),
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
