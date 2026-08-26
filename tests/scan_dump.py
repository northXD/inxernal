"""
Scan memory dump of libg.so for Promon SHIELD detection patterns.
Finds: ARM64 inline syscalls (exit_group, kill, openat),
/proc/self/maps strings, frida strings, 0xdead1007 values.
"""
import os, struct, sys

DUMP_DIR = os.path.expandvars(r"%TEMP%\promon_dump\pdump")

# Load all dumps
code = open(os.path.join(DUMP_DIR, "code.bin"), "rb").read()
data1 = open(os.path.join(DUMP_DIR, "data1.bin"), "rb").read()
data2 = open(os.path.join(DUMP_DIR, "data2.bin"), "rb").read()
data3 = open(os.path.join(DUMP_DIR, "data3.bin"), "rb").read()

# Memory layout from maps:
# 05058000-06477000 r--p (code.bin) offset 0 in file = base address 0x05058000
# 0647a000-0655f000 r--p (data1.bin)
# 06562000-0660f000 rw-p (data2.bin)
# 06654000-066a9000 rw-p (data3.bin)

CODE_BASE = 0x05058000
DATA1_BASE = 0x0647a000
DATA2_BASE = 0x06562000
DATA3_BASE = 0x06654000

LIBG_BASE = CODE_BASE  # libg.so base address

print(f"Code dump: {len(code):,} bytes (0x{CODE_BASE:x} - 0x{CODE_BASE + len(code):x})")
print(f"Data1 dump: {len(data1):,} bytes")
print(f"Data2 dump: {len(data2):,} bytes")
print(f"Data3 dump: {len(data3):,} bytes")

all_data = code + data1 + data2 + data3

# ── STRING SEARCH ──
print("\n" + "="*60)
print("STRING SEARCH")
print("="*60)

string_targets = [
    b"/proc/self/maps",
    b"/proc/self/status",
    b"/proc/self/task",
    b"/proc/net/tcp",
    b"/proc/net/unix",
    b"frida",
    b"xposed",
    b"substrate",
    b"TracerPid",
    b"memfd:",
    b"ptrace",
    b"PTRACE",
    b"debuggable",
    b"ro.debuggable",
    b"hook",
    b"inject",
    b"tampering",
    b"integrity",
    b"SHIELD",
    b"shield",
    b"Promon",
    b"promon",
    b"dead1007",
    b"0xdead",
]

for target in string_targets:
    positions = []
    start = 0
    while True:
        pos = code.find(target, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    # Also search data ranges
    for dname, ddata, dbase in [("data1", data1, DATA1_BASE),
                                 ("data2", data2, DATA2_BASE),
                                 ("data3", data3, DATA3_BASE)]:
        start = 0
        while True:
            pos = ddata.find(target, start)
            if pos == -1:
                break
            positions.append(dbase - CODE_BASE + pos)
            start = pos + 1

    if positions:
        print(f"\n  '{target.decode('ascii', errors='replace')}': {len(positions)} occurrences")
        for p in positions[:10]:
            abs_addr = CODE_BASE + p
            # Read surrounding context as string
            ctx_start = max(0, p)
            ctx_end = min(len(code) if p < len(code) else len(all_data), p + len(target) + 64)
            if p < len(code):
                ctx = code[ctx_start:ctx_end]
            else:
                continue
            # Find null-terminated string
            null_pos = ctx.find(b'\x00', len(target))
            if null_pos > 0:
                full_str = ctx[:null_pos].decode('ascii', errors='replace')
            else:
                full_str = ctx[:64].decode('ascii', errors='replace')
            safe_str = full_str[:80].encode('ascii', errors='replace').decode()
            print(f"    file_off=0x{p:x} addr=0x{abs_addr:x} libg+0x{p:x}: {safe_str}")

# ── ARM64 INSTRUCTION SCAN ──
print("\n" + "="*60)
print("ARM64 INSTRUCTION SCAN (code section)")
print("="*60)

# We'll scan the code dump for ARM64 instructions
# SVC #0 = 0xD4000001
svc_count = 0
exit_groups = []
kill_syscalls = []
openat_syscalls = []
getpid_syscalls = []

for i in range(0, len(code) - 4, 4):
    instr = struct.unpack_from('<I', code, i)[0]

    if instr == 0xD4000001:  # SVC #0
        svc_count += 1

        # Check preceding instruction for syscall number (MOV X8, #imm)
        if i >= 4:
            prev = struct.unpack_from('<I', code, i - 4)[0]
            # MOVZ X8, #imm16 = 1101 0010 100x xxxx xxxx xxxx xxx0 1000
            if (prev & 0xFFE0001F) == 0xD2800008:
                sysno = (prev >> 5) & 0xFFFF
                addr = CODE_BASE + i - 4

                if sysno == 94:  # exit_group
                    sig = code[i-4:i+12]  # 16 bytes starting from MOV
                    # Find function start (STP x29, x30)
                    func_start = None
                    func_sig = None
                    for k in range(4, 1024, 4):
                        if i - 4 - k < 0:
                            break
                        pi = struct.unpack_from('<I', code, i - 4 - k)[0]
                        if (pi & 0xFFE07FFF) == 0xA9007BFD:  # STP x29, x30, [sp, #imm]!
                            func_start = i - 4 - k
                            func_sig = code[func_start:func_start+16]
                            break

                    exit_groups.append({
                        'off': i - 4,
                        'addr': addr,
                        'sig': sig.hex(),
                        'func_off': func_start,
                        'func_sig': func_sig.hex() if func_sig else None
                    })

                elif sysno == 129:  # kill
                    sig = code[i-4:i+12]
                    func_start = None
                    func_sig = None
                    for k in range(4, 1024, 4):
                        if i - 4 - k < 0:
                            break
                        pi = struct.unpack_from('<I', code, i - 4 - k)[0]
                        if (pi & 0xFFE07FFF) == 0xA9007BFD:
                            func_start = i - 4 - k
                            func_sig = code[func_start:func_start+16]
                            break

                    kill_syscalls.append({
                        'off': i - 4,
                        'addr': addr,
                        'sig': sig.hex(),
                        'func_off': func_start,
                        'func_sig': func_sig.hex() if func_sig else None
                    })

                elif sysno == 56:  # openat
                    openat_syscalls.append({'off': i - 4, 'addr': addr})

                elif sysno == 172:  # getpid
                    getpid_syscalls.append({'off': i - 4, 'addr': addr})

            # Also check for MOV W8, #imm (32-bit variant)
            elif (prev & 0xFFE0001F) == 0x52800008:
                sysno = (prev >> 5) & 0xFFFF
                if sysno == 94 or sysno == 129:
                    addr = CODE_BASE + i - 4
                    sig = code[i-4:i+12]
                    func_start = None
                    func_sig = None
                    for k in range(4, 1024, 4):
                        if i - 4 - k < 0:
                            break
                        pi = struct.unpack_from('<I', code, i - 4 - k)[0]
                        if (pi & 0xFFE07FFF) == 0xA9007BFD:
                            func_start = i - 4 - k
                            func_sig = code[func_start:func_start+16]
                            break

                    entry = {
                        'off': i - 4,
                        'addr': addr,
                        'sig': sig.hex(),
                        'sysno': sysno,
                        'func_off': func_start,
                        'func_sig': func_sig.hex() if func_sig else None,
                        'note': 'W8 variant'
                    }
                    if sysno == 94:
                        exit_groups.append(entry)
                    elif sysno == 129:
                        kill_syscalls.append(entry)

print(f"\nTotal SVC #0 instructions: {svc_count}")

print(f"\n--- exit_group (SYS 94) inline syscalls: {len(exit_groups)} ---")
for eg in exit_groups:
    print(f"  libg+0x{eg['off']:x} (addr=0x{eg['addr']:x})")
    print(f"    16-byte sig: {eg['sig']}")
    if eg.get('func_off') is not None:
        print(f"    func start: libg+0x{eg['func_off']:x} sig: {eg['func_sig']}")
    # Show surrounding instructions
    start = max(0, eg['off'] - 16)
    end = min(len(code), eg['off'] + 32)
    surrounding = code[start:end]
    print(f"    context ({end-start} bytes): {surrounding.hex()}")
    # Decode a few instructions
    for j in range(0, min(48, end - start), 4):
        instr = struct.unpack_from('<I', surrounding, j)[0]
        off_label = eg['off'] - 16 + j
        prefix = ">>>" if off_label == eg['off'] else "   "
        print(f"    {prefix} +0x{off_label:x}: 0x{instr:08x}")

print(f"\n--- kill (SYS 129) inline syscalls: {len(kill_syscalls)} ---")
for ks in kill_syscalls:
    print(f"  libg+0x{ks['off']:x} (addr=0x{ks['addr']:x})")
    print(f"    16-byte sig: {ks['sig']}")
    if ks.get('func_off') is not None:
        print(f"    func start: libg+0x{ks['func_off']:x} sig: {ks['func_sig']}")
    start = max(0, ks['off'] - 16)
    end = min(len(code), ks['off'] + 32)
    surrounding = code[start:end]
    print(f"    context ({end-start} bytes): {surrounding.hex()}")
    for j in range(0, min(48, end - start), 4):
        instr = struct.unpack_from('<I', surrounding, j)[0]
        off_label = ks['off'] - 16 + j
        prefix = ">>>" if off_label == ks['off'] else "   "
        print(f"    {prefix} +0x{off_label:x}: 0x{instr:08x}")

print(f"\n--- openat (SYS 56) inline syscalls: {len(openat_syscalls)} ---")
for oa in openat_syscalls[:5]:
    print(f"  libg+0x{oa['off']:x} (addr=0x{oa['addr']:x})")

print(f"\n--- getpid (SYS 172) inline syscalls: {len(getpid_syscalls)} ---")
for gp in getpid_syscalls[:5]:
    print(f"  libg+0x{gp['off']:x} (addr=0x{gp['addr']:x})")

# ── SEARCH FOR 0xdead1007 ──
print(f"\n--- 0xdead1007 search ---")
dead_bytes = struct.pack('<I', 0xdead1007)
pos = 0
while True:
    pos = code.find(dead_bytes, pos)
    if pos == -1:
        break
    print(f"  Found at libg+0x{pos:x} (addr=0x{CODE_BASE+pos:x})")
    pos += 1

# Also search as an ARM64 immediate (MOVZ/MOVK pairs)
# Look for instructions that load 0x1007 and 0xDEAD
print(f"\n--- MOVZ+MOVK 0xdead1007 pattern search ---")
for i in range(0, len(code) - 8, 4):
    instr1 = struct.unpack_from('<I', code, i)[0]
    # MOVZ Wn, #0x1007 = 0x528200Ex where x is register
    if (instr1 & 0xFFFFFFE0) == 0x528200E0:
        rd = instr1 & 0x1F
        # Check next few instructions for MOVK Wrd, #0xDEAD, LSL #16
        for j in range(1, 4):
            if i + j * 4 + 4 > len(code):
                break
            instr2 = struct.unpack_from('<I', code, i + j * 4)[0]
            # MOVK Wn, #0xDEAD, LSL #16 = 0x72BD5A0x where x matches rd
            if (instr2 & 0xFFFFFFE0) == 0x72BD5A00 and (instr2 & 0x1F) == rd:
                print(f"  MOVZ+MOVK 0xdead1007 at libg+0x{i:x} (W{rd})")
                # Read surrounding for context
                ctx = code[max(0,i-8):i+24]
                print(f"    bytes: {ctx.hex()}")

# ── CROSS-REFERENCE: Find code near string references ──
print(f"\n--- Cross-reference: /proc/self/maps string refs in code ---")
maps_str = b"/proc/self/maps"
for dname, ddata, dbase in [("code", code, CODE_BASE)]:
    pos = 0
    while True:
        pos = ddata.find(maps_str, pos)
        if pos == -1:
            break
        str_addr = dbase + pos
        print(f"  String at addr 0x{str_addr:x} (libg+0x{pos:x})")

        # On ARM64, strings are typically referenced via ADRP + ADD
        # ADRP calculates page of target: page = (str_addr >> 12) << 12
        str_page = str_addr & ~0xFFF
        str_page_off = str_addr & 0xFFF

        # Search code for ADRP instructions pointing to this page
        # ADRP Xd, label = 1 immlo[1:0] 10000 immhi[18:0] Rd[4:0]
        # The page offset from PC: (immhi:immlo) << 12
        # We need to find instructions where PC_page + offset = str_page

        adrp_refs = 0
        for ci in range(0, len(code) - 4, 4):
            ci_instr = struct.unpack_from('<I', code, ci)[0]
            if (ci_instr & 0x9F000000) == 0x90000000:  # ADRP
                rd = ci_instr & 0x1F
                immlo = (ci_instr >> 29) & 0x3
                immhi = (ci_instr >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                # Sign extend 21-bit
                if imm & (1 << 20):
                    imm -= (1 << 21)
                pc_page = (CODE_BASE + ci) & ~0xFFF
                target_page = pc_page + (imm << 12)

                if target_page == str_page:
                    # Check next instruction for ADD with page_offset
                    if ci + 4 < len(code):
                        add_instr = struct.unpack_from('<I', code, ci + 4)[0]
                        # ADD Xd, Xn, #imm12
                        if (add_instr & 0xFFC00000) == 0x91000000:
                            add_imm = (add_instr >> 10) & 0xFFF
                            add_rd = add_instr & 0x1F
                            add_rn = (add_instr >> 5) & 0x1F
                            if add_rn == rd and add_imm == str_page_off:
                                print(f"    ADRP+ADD ref at libg+0x{ci:x} (X{rd})")
                                adrp_refs += 1

                                # Find the function containing this reference
                                for k in range(4, 1024, 4):
                                    if ci - k < 0:
                                        break
                                    pi = struct.unpack_from('<I', code, ci - k)[0]
                                    if (pi & 0xFFE07FFF) == 0xA9007BFD:
                                        func_off = ci - k
                                        func_sig = code[func_off:func_off+16]
                                        print(f"      func at libg+0x{func_off:x} sig: {func_sig.hex()}")
                                        # Show some instructions from func start
                                        for ii in range(0, min(64, ci - func_off + 16), 4):
                                            inst = struct.unpack_from('<I', code, func_off + ii)[0]
                                            marker = " <<<" if func_off + ii == ci else ""
                                            print(f"        +0x{func_off+ii:x}: 0x{inst:08x}{marker}")
                                        break
                                if adrp_refs >= 5:
                                    break

        if adrp_refs == 0:
            print(f"    No ADRP+ADD references found")
        pos += 1

print("\n=== SCAN COMPLETE ===")
