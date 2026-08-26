"""
Deep scan of libzyte.so - extract imports, analyze syscall patterns,
find detection functions via PLT/GOT analysis.
"""
import os, struct

TEMP = os.path.expandvars(r"%TEMP%")

def read_dynstr(data, sections):
    if '.dynstr' not in sections:
        return {}
    ds = sections['.dynstr']
    dynstr_data = data[ds['offset']:ds['offset']+ds['size']]
    strings = {}
    pos = 0
    while pos < len(dynstr_data):
        end = dynstr_data.index(b'\x00', pos)
        s = dynstr_data[pos:end].decode('ascii', errors='replace')
        if s:
            strings[pos] = s
        pos = end + 1
    return strings

def parse_elf64(data):
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
        sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size = struct.unpack_from('<Q', data, off + 32)[0]
        sh_link = struct.unpack_from('<I', data, off + 40)[0]
        sh_entsize = struct.unpack_from('<Q', data, off + 56)[0]

        name_end = data.index(b'\x00', shstrtab_off + sh_name)
        name = data[shstrtab_off + sh_name:name_end].decode('ascii', errors='replace')
        sections[name] = {
            'offset': sh_offset, 'size': sh_size, 'addr': sh_addr,
            'type': sh_type, 'link': sh_link, 'entsize': sh_entsize
        }
    return sections

# ── x86_64 analysis ──
print("="*60)
print("x86_64 libzyte.so - IMPORT ANALYSIS")
print("="*60)

with open(os.path.join(TEMP, "libzyte_x64.so"), "rb") as f:
    x64_data = f.read()

x64_sections = parse_elf64(x64_data)
x64_dynstr = read_dynstr(x64_data, x64_sections)

# Parse .dynsym to get imported functions
if '.dynsym' in x64_sections:
    dynsym = x64_sections['.dynsym']
    sym_count = dynsym['size'] // 24  # Elf64_Sym is 24 bytes
    print(f"\nDynamic symbols: {sym_count}")

    imports = []
    exports = []
    for i in range(sym_count):
        off = dynsym['offset'] + i * 24
        st_name = struct.unpack_from('<I', x64_data, off)[0]
        st_info = x64_data[off + 4]
        st_other = x64_data[off + 5]
        st_shndx = struct.unpack_from('<H', x64_data, off + 6)[0]
        st_value = struct.unpack_from('<Q', x64_data, off + 8)[0]
        st_size = struct.unpack_from('<Q', x64_data, off + 16)[0]

        bind = st_info >> 4
        stype = st_info & 0xF

        name = x64_dynstr.get(st_name, "")
        if not name:
            continue

        if st_shndx == 0:  # SHN_UNDEF = import
            imports.append(name)
        else:
            exports.append(name)

    # Detection-related imports
    detection_imports = [
        'kill', 'exit', '_exit', 'abort', 'raise', 'tgkill',
        'open', 'openat', 'read', 'write', 'close',
        'fopen', 'fread', 'fgets', 'fclose',
        'mmap', 'mprotect', 'munmap',
        'ptrace', 'prctl',
        'dlopen', 'dlsym', 'dladdr', 'dl_iterate_phdr',
        'strstr', 'strcmp', 'strncmp', 'strlen', 'memcmp', 'memmem',
        'getpid', 'gettid', 'getppid',
        'pthread_create', 'pthread_exit', 'pthread_self',
        'syscall', 'clone',
        'stat', 'lstat', 'fstat', 'access', 'faccessat',
        'readlink', 'readlinkat',
        'opendir', 'readdir', 'closedir',
        'fork', 'vfork', 'execve',
        'signal', 'sigaction', 'sigprocmask',
        'connect', 'socket', 'bind', 'listen',
        'inotify_init', 'inotify_add_watch',
        '__system_property_get',
    ]

    print(f"\n--- DETECTION-RELATED IMPORTS ---")
    found_detection = []
    for name in sorted(imports):
        for det in detection_imports:
            if name == det or name.startswith(det + '@') or name == '__' + det:
                found_detection.append(name)
                print(f"  IMPORT: {name}")
                break

    print(f"\n--- ALL IMPORTS ({len(imports)}) ---")
    for name in sorted(imports):
        if any(x in name.lower() for x in ['kill', 'exit', 'open', 'read', 'proc', 'ptrace', 'map', 'str', 'mem', 'thread', 'clone', 'fork', 'sig', 'dlopen', 'dl_', 'syscall', 'prctl', 'access', 'stat', 'link', 'dir', 'connect', 'socket', 'inotify', 'property']):
            print(f"  {name}")

    print(f"\n--- ALL EXPORTS ({len(exports)}) ---")
    for name in sorted(exports)[:50]:
        print(f"  {name}")
    if len(exports) > 50:
        print(f"  ... and {len(exports)-50} more")

# ── x86_64 SYSCALL analysis ──
print(f"\n--- x86_64 SYSCALL/INT80 detailed analysis ---")
text = x64_sections.get('.text', {})
if text:
    text_data = x64_data[text['offset']:text['offset']+text['size']]
    print(f"Scanning .text: {len(text_data):,} bytes")

    # Find ALL SYSCALL instructions and analyze surrounding code
    for i in range(len(text_data) - 1):
        is_syscall = (text_data[i] == 0x0F and text_data[i+1] == 0x05)
        is_int80 = (text_data[i] == 0xCD and text_data[i+1] == 0x80)

        if is_syscall or is_int80:
            instr_type = "SYSCALL" if is_syscall else "INT 0x80"
            file_off = text['offset'] + i
            vaddr = text['addr'] + i

            # Read 32 bytes before and 16 after
            ctx_start = max(0, i - 32)
            ctx_end = min(len(text_data), i + 16)
            ctx = text_data[ctx_start:ctx_end]

            # Try to find syscall number setup
            # Look for MOV EAX, imm (B8 xx xx xx xx)
            # or MOV RAX, imm (48 C7 C0 xx xx xx xx)
            # or XOR EAX,EAX + MOV AL, imm
            sysno = None
            for back in range(1, 32):
                if i - back < 0:
                    break
                b = text_data[i-back]
                if back >= 5 and text_data[i-back] == 0xB8:
                    sysno = struct.unpack_from('<I', text_data, i - back + 1)[0]
                    break
                if back >= 7 and text_data[i-back] == 0x48 and text_data[i-back+1] == 0xC7 and text_data[i-back+2] == 0xC0:
                    sysno = struct.unpack_from('<I', text_data, i - back + 3)[0]
                    break
                # MOV EAX via LEA
                if back >= 3 and text_data[i-back] == 0x8D and (text_data[i-back+1] & 0xC7) == 0x04:
                    pass  # complex addressing

            names_x64 = {
                0: 'read', 1: 'write', 2: 'open', 3: 'close',
                9: 'mmap', 10: 'mprotect', 11: 'munmap',
                56: 'clone', 57: 'fork', 59: 'execve',
                60: 'exit', 62: 'kill', 63: 'uname',
                101: 'ptrace', 110: 'getppid',
                186: 'gettid', 200: 'tkill', 234: 'tgkill',
                231: 'exit_group', 257: 'openat',
                302: 'prlimit64',
            }

            sysname = names_x64.get(sysno, f"#{sysno}" if sysno is not None else "?")
            print(f"\n  {instr_type} at 0x{vaddr:x} (file: 0x{file_off:x}): sys_{sysname}")
            print(f"    context: {ctx.hex()}")

# ── ARM64 analysis (quick) ──
print(f"\n\n{'='*60}")
print("ARM64 libzyte.so - IMPORT ANALYSIS")
print("="*60)

with open(os.path.join(TEMP, "libzyte_arm64.so"), "rb") as f:
    arm64_data = f.read()

arm64_sections = parse_elf64(arm64_data)
arm64_dynstr = read_dynstr(arm64_data, arm64_sections)

if '.dynsym' in arm64_sections:
    dynsym = arm64_sections['.dynsym']
    sym_count = dynsym['size'] // 24

    arm64_imports = []
    for i in range(sym_count):
        off = dynsym['offset'] + i * 24
        st_name = struct.unpack_from('<I', arm64_data, off)[0]
        st_info = arm64_data[off + 4]
        st_shndx = struct.unpack_from('<H', arm64_data, off + 6)[0]
        name = arm64_dynstr.get(st_name, "")
        if name and st_shndx == 0:
            arm64_imports.append(name)

    print(f"\n--- ARM64 DETECTION-RELATED IMPORTS ---")
    for name in sorted(arm64_imports):
        if any(x in name.lower() for x in ['kill', 'exit', 'open', 'read', 'proc', 'ptrace', 'map', 'str', 'mem', 'thread', 'clone', 'fork', 'sig', 'dlopen', 'dl_', 'syscall', 'prctl', 'access', 'stat', 'link', 'dir', 'connect', 'socket', 'inotify', 'property']):
            print(f"  {name}")

# ARM64 SVC detail
if '.text' in arm64_sections:
    atext = arm64_sections['.text']
    atext_data = arm64_data[atext['offset']:atext['offset']+atext['size']]
    print(f"\n--- ARM64 SVC instructions ---")
    for i in range(0, len(atext_data) - 3, 4):
        instr = struct.unpack_from('<I', atext_data, i)[0]
        if instr == 0xD4000001:
            off = atext['offset'] + i
            vaddr = atext['addr'] + i
            ctx = atext_data[max(0,i-16):min(len(atext_data),i+16)]
            print(f"  SVC at 0x{vaddr:x} (file: 0x{off:x})")
            print(f"    context: {ctx.hex()}")

            if i >= 4:
                prev = struct.unpack_from('<I', atext_data, i-4)[0]
                if (prev & 0xFFE0001F) == 0xD2800008:
                    sysno = (prev >> 5) & 0xFFFF
                    names_a64 = {94: 'exit_group', 129: 'kill', 56: 'openat', 172: 'getpid', 117: 'ptrace', 178: 'gettid'}
                    print(f"    syscall: {names_a64.get(sysno, sysno)}")

            # Find function start
            for k in range(4, 256, 4):
                if i - k < 0:
                    break
                pi = struct.unpack_from('<I', atext_data, i - k)[0]
                if (pi & 0xFFE07FFF) == 0xA9007BFD:
                    func_off = atext['offset'] + i - k
                    func_sig = atext_data[i-k:i-k+16]
                    print(f"    func_start: 0x{func_off:x} sig: {func_sig.hex()}")
                    break
