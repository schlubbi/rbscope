package offsets

import (
	"os"
	"testing"
)

func TestExtractFromDWARF(t *testing.T) {
	// Use RBSCOPE_TEST_LIBRUBY env var, or fall back to Lima VM path
	rubyPath := os.Getenv("RBSCOPE_TEST_LIBRUBY")
	if rubyPath == "" {
		rubyPath = "/opt/ruby-4.0/lib/libruby.so.4.0.1"
	}
	if _, err := os.Stat(rubyPath); err != nil {
		t.Skipf("Ruby binary not found at %s (set RBSCOPE_TEST_LIBRUBY or run in Lima VM)", rubyPath)
	}

	off, err := ExtractFromDWARF(rubyPath)
	if err != nil {
		t.Fatalf("ExtractFromDWARF failed: %v", err)
	}

	// Sanity checks — these fields have been stable for 15+ years
	if off.ECVMStack != 0 {
		t.Errorf("EC.vm_stack offset = %d, want 0", off.ECVMStack)
	}
	if off.ECVMStackSize != 8 {
		t.Errorf("EC.vm_stack_size offset = %d, want 8", off.ECVMStackSize)
	}
	if off.ECCFP != 16 {
		t.Errorf("EC.cfp offset = %d, want 16", off.ECCFP)
	}

	// CFP fields — stable
	if off.CFPPC != 0 {
		t.Errorf("CFP.pc offset = %d, want 0", off.CFPPC)
	}
	if off.CFPIseq != 16 {
		t.Errorf("CFP.iseq offset = %d, want 16", off.CFPIseq)
	}
	if off.CFPEP != 32 {
		t.Errorf("CFP.ep offset = %d, want 32", off.CFPEP)
	}

	// CFP sizeof — 56 or 64 depending on debug flags
	if off.CFPSizeof < 48 || off.CFPSizeof > 80 {
		t.Errorf("CFP sizeof = %d, want 48-80", off.CFPSizeof)
	}

	// body.location — the variable offset that makes DWARF essential
	if off.BodyLocation < 40 || off.BodyLocation > 256 {
		t.Errorf("body.location offset = %d, looks wrong", off.BodyLocation)
	}

	// iseq.body
	if off.IseqBody != 16 {
		t.Errorf("iseq.body offset = %d, want 16", off.IseqBody)
	}

	// VM symbol address
	if off.VMPtrSymAddr == 0 {
		t.Error("ruby_current_vm_ptr symbol address is 0")
	}

	t.Logf("Extracted offsets:")
	t.Logf("  EC: vm_stack=%d vm_stack_size=%d cfp=%d", off.ECVMStack, off.ECVMStackSize, off.ECCFP)
	t.Logf("  CFP: pc=%d sp=%d iseq=%d self=%d ep=%d sizeof=%d",
		off.CFPPC, off.CFPSP, off.CFPIseq, off.CFPSelf, off.CFPEP, off.CFPSizeof)
	t.Logf("  Iseq: body=%d", off.IseqBody)
	t.Logf("  Body: location=%d iseq_encoded=%d", off.BodyLocation, off.BodyIseqEncoded)
	t.Logf("  Location: pathobj=%d base_label=%d label=%d first_lineno=%d",
		off.LocPathobj, off.LocBaseLabel, off.LocLabel, off.LocFirstLineno)
	t.Logf("  VM: ractor_main_thread=%d", off.VMRactorMainThread)
	t.Logf("  Thread: ec=%d", off.ThreadEC)
	t.Logf("  RString: len=%d heap_ptr=%d embed_start=%d noembed=0x%x",
		off.RStringLen, off.RStringHeapPtr, off.RStringEmbedStart, off.RStringNoEmbed)
	t.Logf("  Class: classpath=%d", off.ClassClasspath)
	t.Logf("  VMPtrSymAddr: 0x%x", off.VMPtrSymAddr)
}
