"""
Scan libg.so for Promon SHIELD detection signatures.
Look for: frida strings, /proc/self/maps refs, ARM64 syscall patterns,
exit_group inline asm, and 0xdead1007 integrity code.
"""
import os, struct, re

LIBG = os.path.expandvars(r"%TEMP%\libg.so")
with open(LIBG, "rb") as f:
    data = f.read()

print(f"libg.so size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")

# ── ELF header parsing ──
assert data[:4] == b'\x7fELF', "Not an ELF"
is_64 = data[4] == 2
is_le = data[5] == 1
e_machine = struct.unpack_from('<H', data, 18)[0]
print(f"ELF: {'64-bit' if is_64 else '32-bit'}, machine=0x{e_machine:x} ({'AArch64' if e_machine==183 else 'unknown'})")

# Parse section headers to find .text, .rodata, .data
e_shoff = struct.unpack_from('<Q', data, 40)[0] if is_64 else struct.unpack_from('<I', data, 32)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0] if is_64 else struct.unpack_from('<H', data, 46)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0] if is_64 else struct.unpack_from('<H', data, 48)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0] if is_64 else struct.unpack_from('<H', data, 50)[0]

# Get section name string table
if is_64:
    shstrtab_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
else:
    shstrtab_off = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 16)[0]

sections = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    if is_64:
        sh_name = struct.unpack_from('<I', data, off)[0]
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
        sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size = struct.unpack_from('<Q', data, off + 32)[0]
    else:
        sh_name = struct.unpack_from('<I', data, off)[0]
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        sh_flags = struct.unpack_from('<I', data, off + 8)[0]
        sh_addr = struct.unpack_from('<I', data, off + 12)[0]
        sh_offset = struct.unpack_from('<I', data, off + 16)[0]
        sh_size = struct.unpack_from('<I', data, off + 20)[0]

    name_end = data.index(b'\x00', shstrtab_off + sh_name)
    name = data[shstrtab_off + sh_name:name_end].decode('ascii', errors='replace')
    sections[name] = {'addr': sh_addr, 'offset': sh_offset, 'size': sh_size, 'type': sh_type, 'flags': sh_flags}

print(f"\nSections: {len(sections)}")
for name in ['.text', '.rodata', '.data', '.bss', '.plt', '.got', '.dynstr', '.dynsym']:
    if name in sections:
        s = sections[name]
        print(f"  {name}: offset=0x{s['offset']:x} size=0x{s['size']:x} ({s['size']:,}) addr=0x{s['addr']:x}")

# ── Search for detection-related strings ──
print("\n=== STRING SEARCH ===")
targets = [
    b"/proc/self/maps",
    b"/proc/self/status",
    b"/proc/self/task",
    b"/proc/net/tcp",
    b"/proc/net/unix",
    b"frida",
    b"xposed",
    b"substrate",
    b"SHIELD",
    b"Promon",
    b"promon",
    b"tampering",
    b"tamper",
    b"integrity",
    b"memfd:",
    b"TracerPid",
    b"exit_group",
    b"libinjector",
    b"gum-js-loop",
    b"re.frida",
]

for target in targets:
    positions = []
    start = 0
    while True:
        pos = data.find(target, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"  '{target.decode('ascii',errors='replace')}': {len(positions)} occurrences")
        for p in positions[:5]:
            # Get surrounding context
            ctx_start = max(0, p - 16)
            ctx_end = min(len(data), p + len(target) + 32)
            ctx = data[ctx_start:ctx_end]
            # Find which section
            sec_name = "?"
            for sn, sv in sections.items():
                if sv['offset'] <= p < sv['offset'] + sv['size']:
                    sec_name = sn
                    break
            print(f"    offset=0x{p:x} section={sec_name}")
            # Show context as printable string
            ctx_str = ctx.decode('ascii', errors='replace').replace('\x00', '|').replace('\n', '\\n')
            print(f"    context: ...{ctx_str}...")
    else:
        pass  # Don't print misses

# ── Search for ARM64 inline syscall patterns ──
print("\n=== ARM64 SYSCALL PATTERNS ===")

if '.text' in sections:
    text = sections['.text']
    text_data = data[text['offset']:text['offset'] + text['size']]
    print(f"Scanning .text ({text['size']:,} bytes)...")

    # SVC #0 = 0xD4000001
    svc_count = 0
    svc_positions = []
    for i in range(0, len(text_data) - 3, 4):
        instr = struct.unpack_from('<I', text_data, i)[0]
        if instr == 0xD4000001:  # SVC #0
            svc_count += 1
            svc_positions.append(text['offset'] + i)
    print(f"  SVC #0 instructions: {svc_count}")

    # Search for exit_group pattern: MOV X8, #94 followed by SVC #0
    # MOV X8, #94 = MOVZ X8, #0x5E = 0xD2800BC8
    exit_group_pattern = struct.pack('<I', 0xD2800BC8)
    eg_positions = []
    pos = 0
    while True:
        pos = text_data.find(exit_group_pattern, pos)
        if pos == -1:
            break
        # Check if SVC #0 follows within next 4 instructions
        for j in range(1, 5):
            next_off = pos + j * 4
            if next_off + 4 <= len(text_data):
                next_instr = struct.unpack_from('<I', text_data, next_off)[0]
                if next_instr == 0xD4000001:
                    file_off = text['offset'] + pos
                    vaddr = text['addr'] + pos
                    # Read 16 bytes as signature
                    sig = text_data[pos:pos+16]
                    sig_hex = sig.hex()
                    eg_positions.append((file_off, vaddr, sig_hex, j))
                    break
        pos += 4

    print(f"  exit_group (MOV X8, #94 + SVC #0): {len(eg_positions)} found")
    for foff, va, sig, dist in eg_positions:
        print(f"    file_offset=0x{foff:x} vaddr=0x{va:x} sig={sig} (SVC at +{dist*4})")
        # Read surrounding context - 8 instructions before and after
        ctx_start = max(0, foff - text['offset'] - 32)
        ctx_end = min(len(text_data), foff - text['offset'] + 48)
        ctx_instrs = text_data[ctx_start:ctx_end]
        print(f"    surrounding ({len(ctx_instrs)} bytes): {ctx_instrs.hex()}")

    # Search for kill syscall: MOV X8, #129 (0x81)
    # MOV X8, #129 = MOVZ X8, #0x81 = 0xD2801028
    kill_pattern = struct.pack('<I', 0xD2801028)
    kill_positions = []
    pos = 0
    while True:
        pos = text_data.find(kill_pattern, pos)
        if pos == -1:
            break
        for j in range(1, 5):
            next_off = pos + j * 4
            if next_off + 4 <= len(text_data):
                next_instr = struct.unpack_from('<I', text_data, next_off)[0]
                if next_instr == 0xD4000001:
                    file_off = text['offset'] + pos
                    vaddr = text['addr'] + pos
                    sig = text_data[pos:pos+16]
                    kill_positions.append((file_off, vaddr, sig.hex(), j))
                    break
        pos += 4

    print(f"  kill syscall (MOV X8, #129 + SVC #0): {len(kill_positions)} found")
    for foff, va, sig, dist in kill_positions:
        print(f"    file_offset=0x{foff:x} vaddr=0x{va:x} sig={sig} (SVC at +{dist*4})")
        ctx_start = max(0, foff - text['offset'] - 32)
        ctx_end = min(len(text_data), foff - text['offset'] + 48)
        ctx_instrs = text_data[ctx_start:ctx_end]
        print(f"    surrounding ({len(ctx_instrs)} bytes): {ctx_instrs.hex()}")

    # Search for 0xdead1007 in code
    # MOVZ W0, #0x1007 = various encodings depending on destination register
    # Let's just search for the raw bytes
    dead_pattern = struct.pack('<I', 0xdead1007)
    dead_positions = []
    pos = 0
    while True:
        pos = data.find(dead_pattern, pos)
        if pos == -1:
            break
        dead_positions.append(pos)
        pos += 1
    print(f"\n  0xdead1007 raw bytes: {len(dead_positions)} found")

    # Also search for MOV Wn, #0x1007 instructions
    # MOVZ Wn, #0x1007 = 0x52820xxE where xx depends on register
    mov_1007_count = 0
    for i in range(0, len(text_data) - 3, 4):
        instr = struct.unpack_from('<I', text_data, i)[0]
        # MOVZ Wn, #imm16 = 0101 0010 100 imm16 Rd
        if (instr & 0xFFE00000) == 0x52800000:  # MOVZ Wn
            imm16 = (instr >> 5) & 0xFFFF
            if imm16 == 0x1007:
                rd = instr & 0x1F
                file_off = text['offset'] + i
                vaddr = text['addr'] + i
                print(f"    MOVZ W{rd}, #0x1007 at file_offset=0x{file_off:x} vaddr=0x{vaddr:x}")
                # Check for MOVK Wn, #0xDEAD, LSL #16 nearby
                for j in range(1, 4):
                    next_off = i + j * 4
                    if next_off + 4 <= len(text_data):
                        next_instr = struct.unpack_from('<I', text_data, next_off)[0]
                        if (next_instr & 0xFFE00000) == 0x72A00000:  # MOVK Wn, #imm16, LSL #16
                            imm2 = (next_instr >> 5) & 0xFFFF
                            if imm2 == 0xDEAD:
                                print(f"      + MOVK W{next_instr & 0x1F}, #0xDEAD, LSL #16 at +{j*4}")
                                # Read 16-byte signature at the MOVZ
                                sig = text_data[i:i+16]
                                print(f"      SIGNATURE: {sig.hex()}")
                mov_1007_count += 1

    # Also search for openat syscall: MOV X8, #56
    # MOVZ X8, #56 = MOVZ X8, #0x38 = 0xD2800708
    openat_pattern = struct.pack('<I', 0xD2800708)
    oa_positions = []
    pos = 0
    while True:
        pos = text_data.find(openat_pattern, pos)
        if pos == -1:
            break
        for j in range(1, 5):
            next_off = pos + j * 4
            if next_off + 4 <= len(text_data):
                next_instr = struct.unpack_from('<I', text_data, next_off)[0]
                if next_instr == 0xD4000001:
                    file_off = text['offset'] + pos
                    vaddr = text['addr'] + pos
                    sig = text_data[pos:pos+16]
                    oa_positions.append((file_off, vaddr, sig.hex(), j))
                    break
        pos += 4

    print(f"\n  openat syscall (MOV X8, #56 + SVC #0): {len(oa_positions)} found")
    for foff, va, sig, dist in oa_positions[:10]:
        print(f"    file_offset=0x{foff:x} vaddr=0x{va:x} sig={sig} (SVC at +{dist*4})")

# ── Look for function prologues near detection strings ──
print("\n=== CROSS-REFERENCE ANALYSIS ===")
# Find all locations of "/proc/self/maps" and look for nearby code references
maps_str = b"/proc/self/maps"
pos = 0
while True:
    pos = data.find(maps_str, pos)
    if pos == -1:
        break
    print(f"\n'/proc/self/maps' at file offset 0x{pos:x}")
    # Find what section this is in
    for sn, sv in sections.items():
        if sv['offset'] <= pos < sv['offset'] + sv['size']:
            vaddr = sv['addr'] + (pos - sv['offset'])
            print(f"  Section: {sn}, vaddr: 0x{vaddr:x}")

            # Search .text for references to this address (ADRP + ADD pattern)
            # ADRP Xn, page = (vaddr >> 12) << 12
            page = vaddr & ~0xFFF
            page_offset = vaddr & 0xFFF
            print(f"  Page: 0x{page:x}, page_offset: 0x{page_offset:x}")
            break
    pos += 1

print("\n=== PROMON SHIELD SPECIFIC ===")
# Look for known Promon patterns
promon_strings = [
    b"shield", b"SHIELD", b"Shield",
    b"tampering detected",
    b"integrity check",
    b"hook detected",
    b"debug",
    b"ptrace",
    b"PTRACE",
    b"TracerPid",
    b"debuggable",
    b"ro.debuggable",
]
for s in promon_strings:
    count = data.count(s)
    if count > 0:
        positions = []
        start = 0
        while True:
            p = data.find(s, start)
            if p == -1:
                break
            positions.append(p)
            start = p + 1
        print(f"  '{s.decode('ascii',errors='replace')}': {count} at offsets {', '.join('0x'+hex(p)[2:] for p in positions[:5])}")
