package timeline

import pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"

// stringTable deduplicates strings and returns indices into a shared table.
// Index 0 is always the empty string (protobuf convention).
type stringTable struct {
	index map[string]uint32
	table []string
}

func newStringTable() *stringTable {
	st := &stringTable{
		index: make(map[string]uint32),
		table: []string{""},
	}
	st.index[""] = 0
	return st
}

// Intern returns the index for s, adding it to the table if new.
func (st *stringTable) Intern(s string) uint32 {
	if idx, ok := st.index[s]; ok {
		return idx
	}
	idx := uint32(len(st.table)) // #nosec G115 -- bounded by sample count
	st.index[s] = idx
	st.table = append(st.table, s)
	return idx
}

// Table returns the string table slice.
func (st *stringTable) Table() []string {
	return st.table
}

// frameTable deduplicates stack frames and returns indices.
type frameTable struct {
	strings *stringTable
	index   map[frameKey]uint32
	table   []*pb.StackFrame
}

type frameKey struct {
	funcIdx uint32
	fileIdx uint32
	line    uint32
}

func newFrameTable(strings *stringTable) *frameTable {
	return &frameTable{
		strings: strings,
		index:   make(map[frameKey]uint32),
	}
}

// Intern returns the index for a frame, adding it to the table if new.
func (ft *frameTable) Intern(funcName, fileName string, line uint32) uint32 {
	funcIdx := ft.strings.Intern(funcName)
	fileIdx := ft.strings.Intern(fileName)
	key := frameKey{funcIdx: funcIdx, fileIdx: fileIdx, line: line}
	if idx, ok := ft.index[key]; ok {
		return idx
	}
	idx := uint32(len(ft.table)) // #nosec G115 -- bounded by frame count
	ft.index[key] = idx
	ft.table = append(ft.table, &pb.StackFrame{
		FunctionNameIdx: funcIdx,
		FileNameIdx:     fileIdx,
		LineNumber:      line,
	})
	return idx
}

// Table returns the frame table slice.
func (ft *frameTable) Table() []*pb.StackFrame {
	return ft.table
}
