package symbols

import (
	"testing"
)

const realisticMaps = `00400000-00452000 r-xp 00000000 08:01 131077  /usr/bin/ruby
00651000-00652000 r--p 00051000 08:01 131077  /usr/bin/ruby
00652000-00653000 rw-p 00052000 08:01 131077  /usr/bin/ruby
01a3b000-01c1a000 rw-p 00000000 00:00 0       [heap]
7f8a10000000-7f8a10021000 rw-p 00000000 00:00 0
7f8a12340000-7f8a12540000 r-xp 00000000 08:01 265321  /usr/lib/libruby.so.3.2
7f8a12540000-7f8a12740000 ---p 00200000 08:01 265321  /usr/lib/libruby.so.3.2
7f8a12740000-7f8a12745000 r--p 00200000 08:01 265321  /usr/lib/libruby.so.3.2
7f8a12800000-7f8a12a00000 r-xp 00000000 08:01 132000  /usr/lib/libc.so.6
7fffd4000000-7fffd4021000 rw-p 00000000 00:00 0       [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0  [vsyscall]
`

func TestParseProcMaps(t *testing.T) {
	mappings, err := ParseProcMaps([]byte(realisticMaps))
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}

	// Only executable mappings should be returned.
	// Executable lines: ruby, libruby r-xp, libc r-xp, vsyscall
	if len(mappings) != 4 {
		t.Fatalf("expected 4 executable mappings, got %d", len(mappings))
	}

	// Verify they are sorted by start address.
	for i := 1; i < len(mappings); i++ {
		if mappings[i].StartAddr <= mappings[i-1].StartAddr {
			t.Errorf("mappings not sorted: [%d].Start=0x%x <= [%d].Start=0x%x",
				i, mappings[i].StartAddr, i-1, mappings[i-1].StartAddr)
		}
	}

	// Spot-check the libruby mapping.
	var libruby *Mapping
	for i := range mappings {
		if mappings[i].Path == "/usr/lib/libruby.so.3.2" {
			libruby = &mappings[i]
			break
		}
	}
	if libruby == nil {
		t.Fatal("libruby mapping not found")
	}
	if libruby.StartAddr != 0x7f8a12340000 {
		t.Errorf("libruby start = 0x%x, want 0x7f8a12340000", libruby.StartAddr)
	}
	if libruby.EndAddr != 0x7f8a12540000 {
		t.Errorf("libruby end = 0x%x, want 0x7f8a12540000", libruby.EndAddr)
	}
	if libruby.Offset != 0 {
		t.Errorf("libruby offset = 0x%x, want 0", libruby.Offset)
	}
}

func TestParseProcMaps_NonExecutableFiltered(t *testing.T) {
	data := []byte("01a3b000-01c1a000 rw-p 00000000 00:00 0       [heap]\n")
	mappings, err := ParseProcMaps(data)
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected 0 mappings for non-executable region, got %d", len(mappings))
	}
}

func TestParseProcMaps_AnonymousExecutable(t *testing.T) {
	// JIT-compiled code can be anonymous executable.
	data := []byte("7f0000-7f1000 r-xp 00000000 00:00 0\n")
	mappings, err := ParseProcMaps(data)
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if mappings[0].Path != "" {
		t.Errorf("expected empty path for anonymous mapping, got %q", mappings[0].Path)
	}
}

func TestResolve(t *testing.T) {
	mappings, err := ParseProcMaps([]byte(realisticMaps))
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}

	r := &Resolver{
		pid:      1,
		mappings: mappings,
		cache:    make(map[uint64]string),
	}

	tests := []struct {
		name string
		addr uint64
		want string
	}{
		{
			name: "hit in ruby binary",
			addr: 0x00410000,
			want: "/usr/bin/ruby+0x10000",
		},
		{
			name: "start of libruby",
			addr: 0x7f8a12340000,
			want: "/usr/lib/libruby.so.3.2+0x0",
		},
		{
			name: "inside libruby",
			addr: 0x7f8a1234a3f4,
			want: "/usr/lib/libruby.so.3.2+0xa3f4",
		},
		{
			name: "inside libc",
			addr: 0x7f8a12800100,
			want: "/usr/lib/libc.so.6+0x100",
		},
		{
			name: "before first mapping",
			addr: 0x00100000,
			want: "[unknown 0x100000]",
		},
		{
			name: "after last mapping",
			addr: 0xffffffffff700000,
			want: "[unknown 0xffffffffff700000]",
		},
		{
			name: "between mappings (gap)",
			addr: 0x00500000,
			want: "[unknown 0x500000]",
		},
		{
			name: "exact end address (exclusive)",
			addr: 0x00452000,
			want: "[unknown 0x452000]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Resolve(tt.addr)
			if got != tt.want {
				t.Errorf("Resolve(0x%x) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestResolve_Caching(t *testing.T) {
	r := &Resolver{
		pid: 1,
		mappings: []Mapping{
			{StartAddr: 0x1000, EndAddr: 0x2000, Offset: 0, Path: "/lib.so"},
		},
		cache: make(map[uint64]string),
	}

	first := r.Resolve(0x1500)
	second := r.Resolve(0x1500)
	if first != second {
		t.Errorf("cached result differs: %q vs %q", first, second)
	}
	if first != "/lib.so+0x500" {
		t.Errorf("unexpected result: %q", first)
	}
}

func TestResolve_AnonymousMapping(t *testing.T) {
	r := &Resolver{
		pid: 1,
		mappings: []Mapping{
			{StartAddr: 0x7f0000, EndAddr: 0x7f1000, Offset: 0, Path: ""},
		},
		cache: make(map[uint64]string),
	}

	got := r.Resolve(0x7f0100)
	want := "[anon]+0x100"
	if got != want {
		t.Errorf("Resolve(0x7f0100) = %q, want %q", got, want)
	}
}

func TestResolve_WithOffset(t *testing.T) {
	// Mapping with non-zero file offset (e.g., second mapping of a shared object).
	r := &Resolver{
		pid: 1,
		mappings: []Mapping{
			{StartAddr: 0x5000, EndAddr: 0x6000, Offset: 0x3000, Path: "/lib.so"},
		},
		cache: make(map[uint64]string),
	}

	got := r.Resolve(0x5200)
	want := "/lib.so+0x3200"
	if got != want {
		t.Errorf("Resolve(0x5200) = %q, want %q", got, want)
	}
}
