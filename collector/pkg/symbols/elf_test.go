package symbols

import (
	"testing"
)

func TestIsRubyLibrary(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/usr/lib/libruby.so.3.2", true},
		{"/usr/lib/libruby-static.a", true},
		{"/usr/local/bin/ruby", true},
		{"/usr/local/bin/ruby4.0", true},
		{"/usr/local/bin/ruby3.3", true},
		{"/usr/lib/libtrilogy.so", false},
		{"/usr/lib/libc.so.6", false},
		{"/usr/lib/libpthread.so.0", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isRubyLibrary(tt.path)
		if got != tt.expect {
			t.Errorf("isRubyLibrary(%q) = %v, want %v", tt.path, got, tt.expect)
		}
	}
}

func TestElfSymbolsLookup(t *testing.T) {
	syms := &elfSymbols{
		syms: []elfSymbol{
			{Addr: 0x1000, Size: 0x100, Name: "func_a"},
			{Addr: 0x1100, Size: 0x200, Name: "func_b"},
			{Addr: 0x1300, Size: 0x50, Name: "func_c"},
		},
	}

	tests := []struct {
		offset uint64
		expect string
	}{
		{0x1000, "func_a"}, // exact start
		{0x1050, "func_a"}, // inside func_a
		{0x10ff, "func_a"}, // last byte of func_a
		{0x1100, "func_b"}, // start of func_b
		{0x12ff, "func_b"}, // last byte of func_b
		{0x1300, "func_c"}, // start of func_c
		{0x0fff, ""},       // before first symbol
		{0x1350, ""},       // after func_c
		{0x2000, ""},       // way past end
	}
	for _, tt := range tests {
		got := syms.lookup(tt.offset)
		if got != tt.expect {
			t.Errorf("lookup(0x%x) = %q, want %q", tt.offset, got, tt.expect)
		}
	}
}

func TestElfSymbolsLookupZeroSize(t *testing.T) {
	// Symbols with size 0 (common in .dynsym)
	syms := &elfSymbols{
		syms: []elfSymbol{
			{Addr: 0x1000, Size: 0, Name: "func_a"},
			{Addr: 0x1100, Size: 0, Name: "func_b"},
		},
	}

	tests := []struct {
		offset uint64
		expect string
	}{
		{0x1000, "func_a"},
		{0x1050, "func_a"}, // between func_a and func_b, still func_a
		{0x10ff, "func_a"},
		{0x1100, "func_b"},
		{0x1200, "func_b"}, // past func_b, no next symbol
	}
	for _, tt := range tests {
		got := syms.lookup(tt.offset)
		if got != tt.expect {
			t.Errorf("lookup(0x%x) = %q, want %q", tt.offset, got, tt.expect)
		}
	}
}

func TestResolveFuncWithMappings(t *testing.T) {
	r := &Resolver{
		pid:      1,
		cache:    make(map[uint64]string),
		elfCache: make(map[string]*elfSymbols),
		mappings: []Mapping{
			{StartAddr: 0x400000, EndAddr: 0x500000, Offset: 0, Path: "/usr/lib/libtrilogy.so"},
			{StartAddr: 0x500000, EndAddr: 0x600000, Offset: 0, Path: "/usr/lib/libruby.so.4.0"},
			{StartAddr: 0x600000, EndAddr: 0x700000, Offset: 0, Path: "/usr/lib/libc.so.6"},
		},
	}

	// Pre-populate ELF cache with mock symbols
	r.elfCache["/usr/lib/libtrilogy.so"] = &elfSymbols{
		syms: []elfSymbol{
			{Addr: 0x1000, Size: 0x200, Name: "trilogy_query"},
			{Addr: 0x1200, Size: 0x100, Name: "trilogy_sock_write"},
		},
	}
	r.elfCache["/usr/lib/libruby.so.4.0"] = &elfSymbols{
		syms: []elfSymbol{
			{Addr: 0x2000, Size: 0x500, Name: "vm_exec_core"},
		},
	}

	// Test resolving trilogy function
	name, lib, isRuby := r.ResolveFunc(0x401000) // offset 0x1000 in libtrilogy
	if name != "trilogy_query" {
		t.Errorf("expected trilogy_query, got %q", name)
	}
	if lib != "/usr/lib/libtrilogy.so" {
		t.Errorf("expected libtrilogy path, got %q", lib)
	}
	if isRuby {
		t.Error("libtrilogy should not be Ruby VM")
	}

	// Test resolving Ruby VM function — should be marked as Ruby
	name, _, isRuby = r.ResolveFunc(0x502000) // offset 0x2000 in libruby
	if name != "vm_exec_core" {
		t.Errorf("expected vm_exec_core, got %q", name)
	}
	if !isRuby {
		t.Error("libruby should be Ruby VM")
	}

	// Test unknown address
	name, _, _ = r.ResolveFunc(0x100000) // before any mapping
	if name == "" {
		t.Error("expected non-empty fallback name")
	}
}
