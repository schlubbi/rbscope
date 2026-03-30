# Ruby Version Support

rbscope uses DWARF debug info from `libruby.so` to discover Ruby VM struct offsets at runtime. This means **custom Ruby builds work automatically** — no configuration, no version-specific tables.

## How It Works

When rbscope attaches to a Ruby process, it:

1. Finds `libruby.so` from `/proc/pid/maps`
2. Reads DWARF debug info (`.debug_info` section) from the library
3. Extracts struct member offsets for Ruby's internal types
4. Uses those offsets to read the VM state from `/proc/pid/mem`

The structs rbscope reads:

| Struct | What it provides |
|---|---|
| `rb_execution_context_struct` | Current control frame pointer |
| `rb_control_frame_struct` | iseq, self, ep, sizeof (for walking the stack) |
| `rb_iseq_struct` | Body pointer |
| `rb_iseq_constant_body` | Location (method name, file path) |
| `rb_iseq_location_struct` | Label, pathobj, first_lineno |
| `rb_vm_struct` | Ractor → main_thread (for EC discovery) |
| `rb_thread_struct` | EC pointer |
| `RString` | Embedded vs heap string layout |
| `RClass_and_rb_classext_t` | Class name (classpath) |
| `rb_callable_method_entry_struct` | Cfunc called_id, def pointer |
| `rb_method_definition_struct` | Method type |

It also locates ELF symbols:
- `ruby_current_vm_ptr` — entry point for reading the VM state
- `ruby_global_symbols` — for resolving cfunc method names (like `require`, `each`)

## Using a Custom Ruby Build

Any Ruby built from source with debug info works:

```bash
# rbenv
RUBY_CONFIGURE_OPTS="--enable-debug-env" rbenv install 3.4.0

# ruby-build
CONFIGURE_OPTS="debugflags=-g" ruby-build 3.4.0 /opt/ruby-3.4

# From source
./configure --prefix=/opt/ruby-3.4 debugflags="-g"
make && make install
```

Verify debug info is present:

```bash
readelf -S /opt/ruby-3.4/lib/libruby.so | grep debug_info
# Should show: [XX] .debug_info PROGBITS ...
```

Then just run rbscope — it finds everything automatically:

```bash
sudo rbscope-collector capture --pid 12345 --mode bpf --duration 10s --format gecko --output profile.json
```

## Verifying Offset Extraction

To check that rbscope can read a specific Ruby build's offsets without attaching to a live process:

```bash
# From the collector directory, run the DWARF test with your libruby
RBSCOPE_TEST_LIBRUBY=/opt/ruby-3.4/lib/libruby.so go test ./pkg/offsets/ -run TestExtractFromDWARF -v
```

This prints all extracted offsets:

```
EC: vm_stack=0 vm_stack_size=8 cfp=16
CFP: pc=0 sp=8 iseq=16 self=40 ep=32 sizeof=56
Iseq: body=16
Body: location=64 iseq_encoded=40
Location: pathobj=0 base_label=8 label=16 first_lineno=24
VM: ractor_main_thread=40
Thread: ec=48
RString: len=16 heap_ptr=24 embed_start=24 noembed=0x2000
Class: classpath=152
VMPtrSymAddr: 0x826020
```

## When a New Ruby Version Breaks Things

The DWARF approach handles most version changes automatically. However, some changes require rbscope updates:

### Changes rbscope handles automatically

- **Member offsets moving** (e.g., `body.location` moves from offset 56 to 64) — DWARF has the new offset
- **New struct members added** — rbscope only reads the members it knows about
- **Struct sizes changing** — `CFPSizeof` is read from DWARF

### Changes that may require rbscope updates

| Change | Impact | What to fix |
|---|---|---|
| **Struct renamed** | DWARF lookup fails → error at startup | Add the new name to `targetNames` in `dwarf.go` |
| **Member renamed** | `getField()` returns 0 → incorrect offset | Update the field name in the offset mapping |
| **Struct removed or split** | DWARF lookup fails | Update the extraction logic |
| **EC discovery path changes** | Can't find the execution context | Update `ReadECAddress()` in `process.go` |
| **String representation changes** | Garbled method/class names | Update string reading in `resolver.go` |
| **Symbol table layout changes** | Cfunc names not resolved | Update `resolveID()` in `resolver.go` |
| **New RString embed flag** | Heap vs embedded detection wrong | Update `RStringNoEmbed` constant |

### Example: Ruby 4.0 Ractor Change

Ruby 4.0 changed `rb_vm_struct.ractor` from a **pointer** to an **inline struct**. The DWARF parser handled this automatically because it follows the nested struct layout:

```
rb_vm_struct
  └── ractor (inline rb_ractor_struct, offset 0)
        └── threads
              └── main (rb_thread_struct*, offset 40)
```

The `resolveNestedOffsets()` function walks this tree regardless of whether `ractor` is a pointer or inline.

### Testing Against a New Ruby

```bash
# 1. Build the new Ruby with debug info
./configure debugflags="-g" && make

# 2. Run the DWARF extraction test
RBSCOPE_TEST_LIBRUBY=/path/to/libruby.so go test ./pkg/offsets/ -run TestExtractFromDWARF -v

# 3. If the test passes, run a live capture test
sudo rbscope-collector capture --pid <ruby_pid> --mode bpf --duration 5s --format gecko --output test.json

# 4. Check the profile has frames
python3 -c "
import json
d = json.load(open('test.json'))
for t in d['threads']:
    s = len(t.get('samples', {}).get('data', []))
    if s > 0: print(f'{t[\"name\"]}: {s} samples')
"
```

### Fixing DWARF Extraction for a New Ruby

If the struct layout changed, the error message tells you exactly what's wrong:

```
error: struct "rb_execution_context_struct" not found in DWARF
```

Fix in `collector/pkg/offsets/dwarf.go`:

1. **Struct renamed**: Add the new name to `targetNames` and update the offset mapping
2. **Member renamed**: Update the field name in `getField()` calls
3. **New nested layout**: Update `resolveNestedOffsets()` to walk the new path

All struct names and member names come from Ruby's C source (`vm_core.h`, `internal/thread.h`, `ruby/ruby.h`). Check the Ruby changelog and source diff for the version that broke.

## Distro Ruby Packages

| Distro | Ruby | Debug info | Notes |
|---|---|---|---|
| **Ubuntu 22.04** | 3.0 | `apt install libruby3.0-dbg` | Uses system Ruby |
| **Ubuntu 24.04** | 3.2 | `apt install libruby3.2-dbg` | |
| **Debian 12** | 3.1 | `apt install ruby3.1-dbg` | |
| **Fedora 39+** | 3.3+ | `dnf debuginfo-install ruby` | |
| **RHEL 9** | 3.1 | `dnf debuginfo-install ruby` | |
| **Alpine** | ✗ | ✗ | musl libc, no DWARF — not supported |
| **Docker `ruby:*`** | varies | Included by default | Official images have DWARF |
| **Docker `ruby:*-slim`** | varies | May be stripped | Check with `readelf -S` |
| **Docker `ruby:*-alpine`** | ✗ | ✗ | musl — not supported |

### Alpine / musl Note

Alpine Linux uses musl libc and Ruby packages are typically built without DWARF debug info. rbscope does not currently support Alpine-based Ruby containers. Use `ruby:*` (Debian-based) images instead.
