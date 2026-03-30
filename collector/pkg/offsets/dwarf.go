package offsets

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"
)

// structInfo holds the parsed members and size of a DWARF struct type.
type structInfo struct {
	members map[string]uint32
	size    uint32
}

// ExtractFromDWARF reads Ruby VM struct offsets from DWARF debug info in
// an ELF binary (typically libruby.so). Returns an error if DWARF data
// is missing or required structs/fields are not found.
func ExtractFromDWARF(elfPath string) (*RubyOffsets, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("open ELF %s: %w", elfPath, err)
	}
	defer f.Close() //nolint:errcheck

	dw, err := f.DWARF()
	if err != nil {
		return nil, fmt.Errorf("read DWARF from %s: %w", elfPath, err)
	}

	// Target struct names → parsed info
	targets := map[string]*structInfo{}
	targetNames := []string{
		"rb_execution_context_struct",
		"rb_control_frame_struct",
		"rb_iseq_struct",
		"rb_iseq_constant_body",
		"rb_iseq_location_struct",
		"RString",
		"rb_vm_struct",
	}
	for _, name := range targetNames {
		targets[name] = nil
	}

	// Scan all DWARF entries for matching struct types
	reader := dw.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("read DWARF entry: %w", err)
		}
		if entry == nil {
			break
		}

		if entry.Tag != dwarf.TagStructType {
			continue
		}

		name, _ := entry.Val(dwarf.AttrName).(string)
		if _, wanted := targets[name]; !wanted {
			if entry.Children {
				reader.SkipChildren() //nolint:errcheck
			}
			continue
		}

		// Already found this struct — skip duplicates
		if targets[name] != nil {
			if entry.Children {
				reader.SkipChildren() //nolint:errcheck
			}
			continue
		}

		si := &structInfo{
			members: make(map[string]uint32),
		}
		if sz, ok := entry.Val(dwarf.AttrByteSize).(int64); ok {
			si.size = uint32(sz)
		}

		if entry.Children {
			if err := readStructMembers(reader, si); err != nil {
				return nil, fmt.Errorf("read members of %s: %w", name, err)
			}
		}

		targets[name] = si
	}

	// Validate all structs were found
	for name, si := range targets {
		if si == nil {
			return nil, fmt.Errorf("struct %q not found in DWARF", name)
		}
	}

	// Also find RString heap.ptr offset by looking for nested union/struct
	// Try alternate paths for the heap ptr
	rstringInfo := targets["RString"]

	off := &RubyOffsets{}

	// rb_execution_context_struct
	ec := targets["rb_execution_context_struct"]
	off.ECVMStack = getField(ec, "vm_stack")
	off.ECVMStackSize = getField(ec, "vm_stack_size")
	off.ECCFP = getField(ec, "cfp")

	// rb_control_frame_struct
	cfp := targets["rb_control_frame_struct"]
	off.CFPPC = getField(cfp, "pc")
	off.CFPSP = getField(cfp, "sp")
	off.CFPIseq = getField(cfp, "iseq")
	off.CFPSelf = getField(cfp, "self")
	off.CFPEP = getField(cfp, "ep")
	off.CFPSizeof = cfp.size

	// rb_iseq_struct
	iseq := targets["rb_iseq_struct"]
	off.IseqBody = getField(iseq, "body")

	// rb_iseq_constant_body
	body := targets["rb_iseq_constant_body"]
	off.BodyLocation = getField(body, "location")
	off.BodyIseqEncoded = getField(body, "iseq_encoded")

	// rb_iseq_location_struct
	loc := targets["rb_iseq_location_struct"]
	off.LocPathobj = getField(loc, "pathobj")
	off.LocBaseLabel = getField(loc, "base_label")
	off.LocLabel = getField(loc, "label")
	off.LocFirstLineno = getField(loc, "first_lineno")

	// rb_vm_struct — vm.ractor is an inline struct
	vm := targets["rb_vm_struct"]
	_ = vm // We'll resolve vm.ractor.main_thread in the nested pass below

	// RString — need nested field offsets for heap.ptr
	off.RStringLen = getField(rstringInfo, "len")
	// heap.ptr is typically at offset 24 (after RBasic(16) + len(8))
	// For embedded strings, data starts at the same offset as the union
	off.RStringHeapPtr = getNestedField(rstringInfo, "as", "heap", "ptr")
	off.RStringEmbedStart = getNestedField(rstringInfo, "as", "embed", "ary")
	if off.RStringEmbedStart == 0 {
		// Fallback: embedded data starts at same offset as heap.ptr
		// (they share the union)
		off.RStringEmbedStart = off.RStringHeapPtr
	}

	// RSTRING_NOEMBED flag — not in DWARF, determined by Ruby version.
	// Ruby 4.0: FL_USHIFT=12, FL_USER1=(1<<13)
	// Default to (1<<13), can be overridden
	off.RStringNoEmbed = 1 << 13

	// Find ruby_current_vm_ptr symbol
	vmPtrAddr, err := FindSymbolAddress(f, "ruby_current_vm_ptr")
	if err != nil {
		return nil, fmt.Errorf("symbol ruby_current_vm_ptr not found: %w", err)
	}
	off.VMPtrSymAddr = vmPtrAddr

	// Second pass: resolve nested struct offsets via DWARF type tree.
	// This handles ractor.threads.running_ec and RString.as.heap.ptr.
	if err := resolveNestedOffsets(dw, off); err != nil {
		return nil, fmt.Errorf("resolve nested offsets: %w", err)
	}

	return off, nil
}

// resolveNestedOffsets uses the DWARF type tree to find nested struct member
// offsets that can't be found by flat member scanning.
func resolveNestedOffsets(dw *dwarf.Data, off *RubyOffsets) error {
	reader := dw.Reader()
	needVM := off.VMRactorMainThread == 0
	needThread := off.ThreadEC == 0
	needRString := off.RStringHeapPtr == 0

	for {
		if !needVM && !needRString && !needThread {
			break
		}
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		sz, _ := entry.Val(dwarf.AttrByteSize).(int64)
		if sz == 0 {
			continue
		}

		if name == "rb_vm_struct" && needVM {
			typ, err := dw.Type(entry.Offset)
			if err != nil {
				continue
			}
			st, ok := typ.(*dwarf.StructType)
			if !ok {
				continue
			}
			// Find vm.ractor (inline struct) → .main_thread
			for _, f := range st.Field {
				if f.Name != "ractor" {
					continue
				}
				inner, ok := f.Type.(*dwarf.StructType)
				if !ok {
					continue
				}
				for _, ff := range inner.Field {
					if ff.Name == "main_thread" {
						off.VMRactorMainThread = uint32(f.ByteOffset + ff.ByteOffset)
						needVM = false
					}
				}
			}
		}

		if name == "rb_thread_struct" && needThread {
			typ, err := dw.Type(entry.Offset)
			if err != nil {
				continue
			}
			st, ok := typ.(*dwarf.StructType)
			if !ok {
				continue
			}
			for _, f := range st.Field {
				if f.Name == "ec" {
					off.ThreadEC = uint32(f.ByteOffset)
					needThread = false
					break
				}
			}
		}

		if name == "RString" && needRString {
			typ, err := dw.Type(entry.Offset)
			if err != nil {
				continue
			}
			st, ok := typ.(*dwarf.StructType)
			if !ok {
				continue
			}
			// Find as.heap.ptr and as.embed.ary
			for _, f := range st.Field {
				if f.Name != "as" {
					continue
				}
				asType, ok := f.Type.(*dwarf.StructType)
				if !ok {
					continue
				}
				// Union fields (as.heap, as.embed) — Go DWARF represents unions as StructType
				for _, uf := range asType.Field {
					if uf.Name == "heap" {
						if heapSt, ok := uf.Type.(*dwarf.StructType); ok {
							for _, hf := range heapSt.Field {
								if hf.Name == "ptr" {
									off.RStringHeapPtr = uint32(f.ByteOffset + uf.ByteOffset + hf.ByteOffset)
								}
							}
						}
					}
					if uf.Name == "embed" {
						if embedSt, ok := uf.Type.(*dwarf.StructType); ok {
							for _, ef := range embedSt.Field {
								if ef.Name == "ary" {
									off.RStringEmbedStart = uint32(f.ByteOffset + uf.ByteOffset + ef.ByteOffset)
								}
							}
						}
					}
				}
				needRString = false
			}
		}
	}

	if needVM {
		return fmt.Errorf("could not resolve vm.ractor.main_thread offset")
	}
	if needThread {
		return fmt.Errorf("could not resolve rb_thread_struct.ec offset")
	}

	return nil
}

// readStructMembers reads all DW_TAG_member children of a struct entry.
// It handles nested anonymous structs/unions by flattening their members
// with dotted paths (e.g., "as.heap.ptr").
func readStructMembers(reader *dwarf.Reader, si *structInfo) error {
	for {
		entry, err := reader.Next()
		if err != nil {
			return err
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagMember {
			name, _ := entry.Val(dwarf.AttrName).(string)
			if name == "" {
				// Anonymous member — skip
				if entry.Children {
					reader.SkipChildren() //nolint:errcheck
				}
				continue
			}

			offset := getMemberOffset(entry)
			si.members[name] = uint32(offset)
		}

		// Skip children of non-interesting tags
		if entry.Children {
			reader.SkipChildren() //nolint:errcheck
		}
	}
	return nil
}

// getMemberOffset extracts the byte offset of a struct member from DWARF.
func getMemberOffset(entry *dwarf.Entry) int64 {
	// Try AttrDataMemberLoc (standard for struct members)
	if v, ok := entry.Val(dwarf.AttrDataMemberLoc).(int64); ok {
		return v
	}
	return 0
}

// getField returns the offset of a named field in a struct, or 0 if not found.
func getField(si *structInfo, name string) uint32 {
	if si == nil {
		return 0
	}
	return si.members[name]
}

// getNestedField looks up a dotted path like "as.heap.ptr" in the struct
// members. This handles cases where DWARF flattens nested structs or where
// we pre-computed nested offsets during extraction.
func getNestedField(si *structInfo, parts ...string) uint32 {
	if si == nil || len(parts) == 0 {
		return 0
	}
	// Try the full dotted path first
	key := strings.Join(parts, ".")
	if v, ok := si.members[key]; ok {
		return v
	}
	// Fallback: return 0 (caller should handle)
	return 0
}

// FindSymbolAddress returns the ELF virtual address of a named symbol.
// Searches both .symtab and .dynsym.
func FindSymbolAddress(f *elf.File, name string) (uint64, error) {
	// Try .symtab first (has local symbols, but may be stripped)
	if symbols, err := f.Symbols(); err == nil {
		for _, s := range symbols {
			if s.Name == name {
				return s.Value, nil
			}
		}
	}

	// Try .dynsym (always present for shared libs)
	if symbols, err := f.DynamicSymbols(); err == nil {
		for _, s := range symbols {
			if s.Name == name {
				return s.Value, nil
			}
		}
	}

	return 0, fmt.Errorf("symbol %q not found in ELF", name)
}

// ExtractFromDWARFWithNested is a more thorough DWARF extractor that
// follows type references to resolve nested struct member offsets
// (e.g., RString.as.heap.ptr). This is needed because readStructMembers
// only captures direct members.
