// Package offsets extracts Ruby VM struct field offsets from DWARF debug info.
// These offsets are used by the BPF stack walker to read Ruby's internal
// data structures (execution context, control frames, iseq, strings)
// directly from process memory without any instrumentation.
package offsets

// RubyOffsets contains all byte offsets needed to walk Ruby's VM stack.
// Field names match the Ruby C source (vm_core.h, iseq.h, string.h).
type RubyOffsets struct {
	// rb_execution_context_struct
	ECVMStack     uint32 // vm_stack field
	ECVMStackSize uint32 // vm_stack_size field
	ECCFP         uint32 // cfp field

	// rb_control_frame_struct
	CFPPC     uint32 // pc field
	CFPSP     uint32 // sp field
	CFPIseq   uint32 // iseq field
	CFPSelf   uint32 // self field
	CFPEP     uint32 // ep field
	CFPSizeof uint32 // sizeof(rb_control_frame_t)

	// rb_iseq_struct
	IseqBody uint32 // body field

	// rb_iseq_constant_body
	BodyLocation    uint32 // location field (VARIABLE across versions)
	BodyIseqEncoded uint32 // iseq_encoded field

	// rb_iseq_location_struct (offsets relative to start of location)
	LocPathobj     uint32 // pathobj field
	LocBaseLabel   uint32 // base_label field
	LocLabel       uint32 // label field
	LocFirstLineno uint32 // first_lineno field

	// rb_vm_struct — vm.ractor is an inline struct, not a pointer.
	// We need the absolute offset from vm base to ractor.main_thread.
	VMRactorMainThread uint32 // offset from vm to vm.ractor.main_thread pointer

	// rb_thread_struct
	ThreadEC uint32 // ec field offset in rb_thread_struct

	// RString
	RStringLen        uint32 // len field offset
	RStringHeapPtr    uint32 // as.heap.ptr field offset
	RStringEmbedStart uint32 // start of embedded string data
	RStringNoEmbed    uint64 // RSTRING_NOEMBED flag value (bit mask)

	// RClass (via RClass_and_rb_classext_t layout)
	ClassClasspath uint32 // absolute offset from class VALUE to classext.classpath

	// Symbol addresses (virtual addresses in ELF, add to base for runtime)
	VMPtrSymAddr uint64 // ruby_current_vm_ptr symbol address

	// Ruby version info
	MajorVersion uint32
	MinorVersion uint32
}

// BPFRubyOffsets is the wire format for the ruby_offsets BPF map.
// Layout must match struct ruby_offsets in ruby_stack_walker.c exactly.
// All fields are little-endian on the target architecture.
type BPFRubyOffsets struct {
	ECVMStack       uint32 // 0
	ECVMStackSize   uint32 // 4
	ECCFP           uint32 // 8
	CFPPC           uint32 // 12
	CFPSP           uint32 // 16
	CFPIseq         uint32 // 20
	CFPSelf         uint32 // 24
	CFPEP           uint32 // 28
	CFPSizeof       uint32 // 32
	IseqBody        uint32 // 36
	BodyLocation    uint32 // 40
	BodyIseqEncoded uint32 // 44
	LocPathobj      uint32 // 48
	LocBaseLabel    uint32 // 52
	LocLabel        uint32 // 56
	LocFirstLineno  uint32 // 60
	ThreadEC            uint32 // 64
	VMRactorMainThread  uint32 // 68
	RStringLen      uint32 // 72
	RStringHeapPtr  uint32 // 76
	RStringEmbedStart uint32 // 80
	_pad            uint32 // 84 (alignment padding)
	RStringNoEmbed  uint64 // 88
}
// Total: 96 bytes

// ToBPF converts RubyOffsets to the packed BPF map format.
func (o *RubyOffsets) ToBPF() BPFRubyOffsets {
	return BPFRubyOffsets{
		ECVMStack:         o.ECVMStack,
		ECVMStackSize:     o.ECVMStackSize,
		ECCFP:             o.ECCFP,
		CFPPC:             o.CFPPC,
		CFPSP:             o.CFPSP,
		CFPIseq:           o.CFPIseq,
		CFPSelf:           o.CFPSelf,
		CFPEP:             o.CFPEP,
		CFPSizeof:         o.CFPSizeof,
		IseqBody:          o.IseqBody,
		BodyLocation:      o.BodyLocation,
		BodyIseqEncoded:   o.BodyIseqEncoded,
		LocPathobj:        o.LocPathobj,
		LocBaseLabel:      o.LocBaseLabel,
		LocLabel:          o.LocLabel,
		LocFirstLineno:    o.LocFirstLineno,
		ThreadEC:            o.ThreadEC,
		VMRactorMainThread: o.VMRactorMainThread,
		RStringLen:        o.RStringLen,
		RStringHeapPtr:    o.RStringHeapPtr,
		RStringEmbedStart: o.RStringEmbedStart,
		RStringNoEmbed:    o.RStringNoEmbed,
	}
}

// BPFProcessInfo is the wire format for the target_processes BPF map.
// Layout must match struct process_info in ruby_stack_walker.c.
type BPFProcessInfo struct {
	ECAddr uint64 // execution context address for this PID
}
