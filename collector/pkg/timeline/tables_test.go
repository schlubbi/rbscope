package timeline

import (
	"testing"
)

func TestStringTableIntern(t *testing.T) {
	st := newStringTable()

	// Index 0 is always empty string
	if st.Table()[0] != "" {
		t.Errorf("index 0 = %q, want empty", st.Table()[0])
	}

	// First intern returns index 1
	idx := st.Intern("foo")
	if idx != 1 {
		t.Errorf("Intern(foo) = %d, want 1", idx)
	}

	// Same string returns same index
	idx2 := st.Intern("foo")
	if idx2 != 1 {
		t.Errorf("second Intern(foo) = %d, want 1", idx2)
	}

	// Different string returns new index
	idx3 := st.Intern("bar")
	if idx3 != 2 {
		t.Errorf("Intern(bar) = %d, want 2", idx3)
	}

	// Empty string returns 0
	idx4 := st.Intern("")
	if idx4 != 0 {
		t.Errorf("Intern('') = %d, want 0", idx4)
	}

	// Table has correct contents
	table := st.Table()
	if len(table) != 3 {
		t.Fatalf("table len = %d, want 3", len(table))
	}
	if table[0] != "" || table[1] != "foo" || table[2] != "bar" {
		t.Errorf("table = %v", table)
	}
}

func TestStringTableManyStrings(t *testing.T) {
	st := newStringTable()
	seen := make(map[uint32]string)

	strs := []string{"alpha", "beta", "gamma", "delta", "epsilon", "alpha", "beta"}
	for _, s := range strs {
		idx := st.Intern(s)
		if prev, ok := seen[idx]; ok && prev != s {
			t.Errorf("index %d maps to both %q and %q", idx, prev, s)
		}
		seen[idx] = s
	}

	// Should have 6 entries: "" + 5 unique strings
	if len(st.Table()) != 6 {
		t.Errorf("table len = %d, want 6", len(st.Table()))
	}
}

func TestFrameTableIntern(t *testing.T) {
	st := newStringTable()
	ft := newFrameTable(st)

	// First frame
	idx := ft.Intern("foo", "foo.rb", 42)
	if idx != 0 {
		t.Errorf("first frame idx = %d, want 0", idx)
	}

	// Same frame returns same index
	idx2 := ft.Intern("foo", "foo.rb", 42)
	if idx2 != 0 {
		t.Errorf("same frame idx = %d, want 0", idx2)
	}

	// Same function, different line → new frame
	idx3 := ft.Intern("foo", "foo.rb", 99)
	if idx3 != 1 {
		t.Errorf("different line idx = %d, want 1", idx3)
	}

	// Same function, different file → new frame
	idx4 := ft.Intern("foo", "bar.rb", 42)
	if idx4 != 2 {
		t.Errorf("different file idx = %d, want 2", idx4)
	}

	// Verify table contents
	table := ft.Table()
	if len(table) != 3 {
		t.Fatalf("frame table len = %d, want 3", len(table))
	}

	// Check first frame resolves through string table
	f := table[0]
	if st.Table()[f.FunctionNameIdx] != "foo" {
		t.Errorf("frame[0] func = %q", st.Table()[f.FunctionNameIdx])
	}
	if st.Table()[f.FileNameIdx] != "foo.rb" {
		t.Errorf("frame[0] file = %q", st.Table()[f.FileNameIdx])
	}
	if f.LineNumber != 42 {
		t.Errorf("frame[0] line = %d", f.LineNumber)
	}
}

func TestFrameTableSharesStringTable(t *testing.T) {
	st := newStringTable()
	ft := newFrameTable(st)

	ft.Intern("render", "view.rb", 10)
	ft.Intern("render", "other.rb", 20)

	// "render" should appear once in string table
	count := 0
	for _, s := range st.Table() {
		if s == "render" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("'render' appears %d times, want 1", count)
	}
}

func TestFrameTableIsNative(t *testing.T) {
	st := newStringTable()
	ft := newFrameTable(st)

	// Ruby source frame
	rubyIdx := ft.Intern("render", "app/views/posts/index.html.erb", 42)
	if ft.IsNative(rubyIdx) {
		t.Error("Ruby source frame should not be native")
	}

	// Native .so frame
	soIdx := ft.Intern("trilogy_query_send", "/usr/lib/trilogy.so", 0)
	if !ft.IsNative(soIdx) {
		t.Error("Expected .so frame to be native")
	}

	// Native .so with version
	soVerIdx := ft.Intern("read", "/usr/lib/aarch64-linux-gnu/libc.so.6", 0)
	if !ft.IsNative(soVerIdx) {
		t.Error("Expected .so.6 frame to be native")
	}

	// cfunc (no path) — not native
	cfuncIdx := ft.Intern("Hash#each", "", 0)
	if ft.IsNative(cfuncIdx) {
		t.Error("cfunc with empty path should not be native")
	}

	// Out of range
	if ft.IsNative(999) {
		t.Error("Out of range index should not be native")
	}
}

func TestStringTableLookup(t *testing.T) {
	st := newStringTable()
	idx := st.Intern("hello")

	if got := st.Lookup(idx); got != "hello" {
		t.Errorf("Lookup(%d) = %q, want %q", idx, got, "hello")
	}
	if got := st.Lookup(999); got != "" {
		t.Errorf("Lookup(999) = %q, want empty", got)
	}
	// Index 0 is always empty string
	if got := st.Lookup(0); got != "" {
		t.Errorf("Lookup(0) = %q, want empty", got)
	}
}
