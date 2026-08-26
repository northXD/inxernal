"""
Parse libzyte.so x86_64 ELF to find PLT/GOT.PLT offsets for detection functions.
This info is needed to patch them at runtime via /proc/pid/mem.
"""
import os, struct

TEMP = os.path.expandvars(r"%TEMP%")
path = os.path.join(TEMP, "libzyte_x64.so")

with open(path, "rb") as f:
    data = f.read()

print(f"libzyte_x64.so: {len(data):,} bytes")

# Parse ELF64 headers
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]
shstrtab_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]

sections = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from('<I', data, off)[0]
    sh_type = struct.unpack_from('<I', data, off + 4)[0]
    sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
    sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
    sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
    sh_size = struct.unpack_from('<Q', data, off + 32)[0]
    sh_link = struct.unpack_from('<I', data, off + 40)[0]
    sh_info = struct.unpack_from('<I', data, off + 44)[0]
    sh_entsize = struct.unpack_from('<Q', data, off + 56)[0]

    name_end = data.index(b'\x00', shstrtab_off + sh_name)
    name = data[shstrtab_off + sh_name:name_end].decode('ascii', errors='replace')
    sections[name] = {
        'offset': sh_offset, 'size': sh_size, 'addr': sh_addr,
        'type': sh_type, 'link': sh_link, 'info': sh_info,
        'entsize': sh_entsize, 'flags': sh_flags
    }

# Print relevant sections
for name in ['.dynsym', '.dynstr', '.rela.plt', '.plt', '.got.plt', '.got']:
    if name in sections:
        s = sections[name]
        print(f"  {name:15s} offset=0x{s['offset']:08x} size=0x{s['size']:08x} addr=0x{s['addr']:016x} entsize={s['entsize']}")

# Parse .dynstr
ds = sections['.dynstr']
dynstr_data = data[ds['offset']:ds['offset']+ds['size']]

# Parse .dynsym
dynsym = sections['.dynsym']
sym_count = dynsym['size'] // 24

symbols = {}
for i in range(sym_count):
    off = dynsym['offset'] + i * 24
    st_name = struct.unpack_from('<I', data, off)[0]
    st_info = data[off + 4]
    st_shndx = struct.unpack_from('<H', data, off + 6)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]

    name_end = dynstr_data.index(b'\x00', st_name)
    name = dynstr_data[st_name:name_end].decode('ascii', errors='replace')
    symbols[i] = {'name': name, 'shndx': st_shndx, 'value': st_value, 'bind': st_info >> 4}

# Parse .rela.plt - maps GOT.PLT slots to symbols
rela_plt = sections['.rela.plt']
rela_count = rela_plt['size'] // 24  # Elf64_Rela is 24 bytes

print(f"\n=== .rela.plt: {rela_count} relocations ===")

targets = ['kill', '_exit', 'abort', 'exit', 'raise', 'tgkill',
           'open', 'openat', 'read', 'fopen', 'fgets', 'fread', 'fclose',
           'strstr', 'strcmp', 'strncmp', 'memcmp', 'memmem',
           'dl_iterate_phdr', 'dlopen', 'dlsym',
           'access', 'stat', 'lstat', 'fstat',
           'syscall', 'ptrace', 'prctl',
           'pthread_create', 'sigaction',
           'socket', 'connect', 'popen',
           '__system_property_get',
           'mmap', 'mprotect']

plt_base = sections['.plt']['addr']
plt_offset = sections['.plt']['offset']
got_plt_base = sections['.got.plt']['addr']
got_plt_offset = sections['.got.plt']['offset']

print(f"PLT base addr: 0x{plt_base:x}, GOT.PLT base addr: 0x{got_plt_base:x}")
print(f"PLT file offset: 0x{plt_offset:x}, GOT.PLT file offset: 0x{got_plt_offset:x}")

# PLT entry 0 is the resolver stub (16 bytes), then each entry is 16 bytes
# GOT.PLT[0..2] are reserved, entries start at GOT.PLT[3]

found = {}
all_relocs = []

for i in range(rela_count):
    off = rela_plt['offset'] + i * 24
    r_offset = struct.unpack_from('<Q', data, off)[0]      # GOT.PLT entry address
    r_info = struct.unpack_from('<Q', data, off + 8)[0]
    r_addend = struct.unpack_from('<q', data, off + 16)[0]

    sym_idx = r_info >> 32
    rel_type = r_info & 0xFFFFFFFF

    sym = symbols.get(sym_idx, {'name': f'?{sym_idx}'})
    name = sym['name']

    # PLT entry index (0-based, PLT[0] is resolver)
    plt_idx = i + 1  # PLT entries are 1-indexed (PLT[0] = resolver)
    plt_entry_addr = plt_base + plt_idx * 16
    plt_entry_offset = plt_offset + plt_idx * 16

    # GOT.PLT entry
    got_entry_offset = r_offset - got_plt_base + got_plt_offset

    entry = {
        'name': name,
        'plt_addr': plt_entry_addr,
        'plt_offset': plt_entry_offset,
        'got_addr': r_offset,
        'got_offset': got_entry_offset,
        'plt_idx': plt_idx,
    }
    all_relocs.append(entry)

    if name in targets:
        found[name] = entry
        # Read the PLT stub bytes
        plt_bytes = data[plt_entry_offset:plt_entry_offset+16]
        print(f"\n  [{i:3d}] {name:30s}")
        print(f"        PLT entry:   addr=0x{plt_entry_addr:x}  file=0x{plt_entry_offset:x}")
        print(f"        GOT.PLT:     addr=0x{r_offset:x}  file=0x{got_entry_offset:x}")
        print(f"        PLT bytes:   {plt_bytes.hex()}")

        # Decode PLT stub: FF 25 xx xx xx xx = jmp *disp32(%rip)
        if plt_bytes[0] == 0xFF and plt_bytes[1] == 0x25:
            disp = struct.unpack_from('<i', plt_bytes, 2)[0]
            target_addr = plt_entry_addr + 6 + disp  # RIP + 6 + displacement
            print(f"        jmp target:  0x{target_addr:x} (should == GOT.PLT 0x{r_offset:x})")

print(f"\n\n=== PATCH PLAN ===")
print(f"Total .rela.plt entries: {rela_count}")
print(f"Found {len(found)}/{len(targets)} target functions")

# Critical functions to patch
critical = ['kill', '_exit', 'abort', 'exit', 'raise', 'tgkill']
detection = ['strstr', 'strcmp', 'strncmp', 'memcmp', 'open', 'openat', 'fopen',
             'read', 'fgets', 'fread', 'dl_iterate_phdr', 'access', 'stat',
             'syscall', 'popen', 'socket', 'connect']

print(f"\n--- CRITICAL (anti-kill) ---")
for name in critical:
    if name in found:
        e = found[name]
        got_rva = e['got_addr'] - sections['.got.plt']['addr'] + (sections['.got.plt']['addr'] - sections[list(sections.keys())[1]]['addr'] if False else 0)
        plt_rva = e['plt_addr'] - plt_base + (plt_base - 0)
        print(f"  {name:15s} PLT_RVA=0x{e['plt_addr']:x}  GOT_RVA=0x{e['got_addr']:x}")
        print(f"                  PLT_offset=0x{e['plt_offset']:x}  GOT_offset=0x{e['got_offset']:x}")
    else:
        print(f"  {name:15s} NOT FOUND in .rela.plt")

print(f"\n--- DETECTION (stealth) ---")
for name in detection:
    if name in found:
        e = found[name]
        print(f"  {name:20s} PLT_addr=0x{e['plt_addr']:x}  GOT_addr=0x{e['got_addr']:x}")
    else:
        print(f"  {name:20s} NOT FOUND")

# Calculate RVAs (offsets from module base for runtime patching)
# Module base = first LOAD segment vaddr
# For shared libraries, base address needs to be added at runtime
print(f"\n\n=== RUNTIME PATCH TABLE ===")
print("# Add libzyte.so base address to these RVAs at runtime")
print("# PLT patch: write 'xor eax,eax; ret' (31 C0 C3) at PLT entry addr")
print("# GOT patch: write address of benign function at GOT.PLT addr")

# Parse program headers to find base vaddr
e_phoff = struct.unpack_from('<Q', data, 32)[0]
e_phentsize = struct.unpack_from('<H', data, 54)[0]
e_phnum = struct.unpack_from('<H', data, 56)[0]

min_vaddr = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    if p_type == 1:  # PT_LOAD
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        if min_vaddr is None or p_vaddr < min_vaddr:
            min_vaddr = p_vaddr

print(f"\nBase vaddr (min LOAD): 0x{min_vaddr:x}")
print(f"PLT section vaddr: 0x{plt_base:x}")
print(f"GOT.PLT section vaddr: 0x{got_plt_base:x}")

print(f"\n# For runtime: runtime_addr = libzyte_base + (vaddr - {min_vaddr:#x})")

all_patches = {}
for name in critical + detection:
    if name in found:
        e = found[name]
        plt_rva = e['plt_addr'] - min_vaddr
        got_rva = e['got_addr'] - min_vaddr
        all_patches[name] = {'plt_rva': plt_rva, 'got_rva': got_rva}
        print(f"  {name:20s} plt_rva=0x{plt_rva:08x}  got_rva=0x{got_rva:08x}")

# Generate the patch data for a shell script
print(f"\n\n=== SHELL PATCH COMMANDS ===")
print("# Usage: ZYTE_BASE=<hex base from /proc/pid/maps>")
print("# PLT patch: 31 C0 C3 = xor eax,eax; ret (returns 0)")
print("# For kill/exit: EB FE = jmp $-2 (infinite loop - safer than ret for noreturn)")

for name in critical:
    if name in found:
        e = found[name]
        plt_rva = e['plt_addr'] - min_vaddr
        if name in ('_exit', 'abort', 'exit'):
            patch = "eb fe"  # infinite loop for noreturn functions
            print(f"# {name}: printf '\\xeb\\xfe' | dd of=/proc/$PID/mem bs=1 seek=$((ZYTE_BASE + 0x{plt_rva:x})) conv=notrunc")
        else:
            patch = "31 c0 c3"  # xor eax,eax; ret
            print(f"# {name}: printf '\\x31\\xc0\\xc3' | dd of=/proc/$PID/mem bs=1 seek=$((ZYTE_BASE + 0x{plt_rva:x})) conv=notrunc")
