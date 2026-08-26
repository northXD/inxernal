"""
Scan libzyte.so (Promon SHIELD runtime) for detection patterns.
Analyze both x86_64 and ARM64 versions.
"""
import os, struct

def scan_elf(path, label):
    with open(path, "rb") as f:
        data = f.read()

    print(f"\n{'='*60}")
    print(f"{label}: {os.path.basename(path)} ({len(data):,} bytes)")
    print(f"{'='*60}")

    assert data[:4] == b'\x7fELF'
    is_64 = data[4] == 2
    e_machine = struct.unpack_from('<H', data, 18)[0]
    machines = {0x3E: 'x86_64', 0xB7: 'AArch64', 0x03: 'x86', 0x28: 'ARM'}
    print(f"Arch: {machines.get(e_machine, hex(e_machine))}, {'64-bit' if is_64 else '32-bit'}")

    # Parse section headers
    if is_64:
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
    else:
        e_shoff = struct.unpack_from('<I', data, 32)[0]
        e_shentsize = struct.unpack_from('<H', data, 46)[0]
        e_shnum = struct.unpack_from('<H', data, 48)[0]
        e_shstrndx = struct.unpack_from('<H', data, 50)[0]

    if e_shnum == 0 or e_shstrndx >= e_shnum:
        print("No section headers or stripped")
    else:
        if is_64:
            shstrtab_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
        else:
            shstrtab_off = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 16)[0]

        sections = {}
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is_64:
                sh_name = struct.unpack_from('<I', data, off)[0]
                sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
                sh_size = struct.unpack_from('<Q', data, off + 32)[0]
                sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
            else:
                sh_name = struct.unpack_from('<I', data, off)[0]
                sh_offset = struct.unpack_from('<I', data, off + 16)[0]
                sh_size = struct.unpack_from('<I', data, off + 20)[0]
                sh_addr = struct.unpack_from('<I', data, off + 12)[0]

            name_end = data.index(b'\x00', shstrtab_off + sh_name)
            name = data[shstrtab_off + sh_name:name_end].decode('ascii', errors='replace')
            sections[name] = {'offset': sh_offset, 'size': sh_size, 'addr': sh_addr}

        print(f"\nSections ({len(sections)}):")
        for name in sorted(sections.keys()):
            s = sections[name]
            if s['size'] > 0:
                print(f"  {name:20s} offset=0x{s['offset']:08x} size=0x{s['size']:08x} ({s['size']:>10,}) addr=0x{s['addr']:x}")

    # String search
    print(f"\n--- String Search ---")
    targets = [
        b"/proc/self/maps", b"/proc/self/status", b"/proc/self/task",
        b"/proc/net/tcp", b"/proc/net/unix",
        b"frida", b"xposed", b"substrate", b"TracerPid",
        b"memfd:", b"ptrace", b"debug", b"hook",
        b"inject", b"tamper", b"integrity", b"shield",
        b"promon", b"Promon", b"SHIELD",
        b"dead1007", b"0xdead", b"exit_group",
        b"kill", b"/proc/", b"maps",
        b"agent", b"gadget", b"server",
        b"su\x00", b"magisk", b"supersu",
        b"zygote", b"linjector",
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
            display = target.decode('ascii', errors='replace').rstrip('\x00')
            print(f"  '{display}': {len(positions)} at", end="")
            for p in positions[:5]:
                # Read context
                ctx_end = min(len(data), p + len(target) + 40)
                null = data.find(b'\x00', p + len(target), ctx_end)
                if null > 0:
                    ctx = data[p:null]
                else:
                    ctx = data[p:ctx_end]
                safe_ctx = ctx.decode('ascii', errors='replace')[:60]
                print(f"\n    0x{p:x}: \"{safe_ctx}\"", end="")
            if len(positions) > 5:
                print(f"\n    ... and {len(positions)-5} more", end="")
            print()

    # x86_64 specific: search for SYSCALL instruction (0x0F 0x05)
    if e_machine == 0x3E:
        print(f"\n--- x86_64 SYSCALL Instructions ---")
        syscall_count = 0
        syscall_positions = []
        for i in range(len(data) - 1):
            if data[i] == 0x0F and data[i+1] == 0x05:
                syscall_count += 1
                # Check preceding bytes for MOV EAX/RAX, imm (syscall number)
                # Common patterns:
                # MOV EAX, imm32 = B8 xx xx xx xx
                # MOV RAX, imm32 = 48 C7 C0 xx xx xx xx
                for back in range(2, 20):
                    if i - back < 0:
                        break
                    if data[i-back] == 0xB8 and back >= 5:  # MOV EAX, imm32
                        sysno = struct.unpack_from('<I', data, i - back + 1)[0]
                        if sysno in [62, 231, 56, 257, 101]:  # kill, exit_group, clone, openat, ptrace
                            names = {62: 'kill', 231: 'exit_group', 56: 'clone', 257: 'openat', 101: 'ptrace'}
                            syscall_positions.append((i, sysno, names.get(sysno, str(sysno))))
                        break

        print(f"  Total SYSCALL instructions: {syscall_count}")
        for pos, sysno, name in syscall_positions:
            print(f"    SYSCALL at 0x{pos:x}: sys_{name} ({sysno})")
            ctx = data[max(0,pos-16):pos+8]
            print(f"      bytes: {ctx.hex()}")

        # Search for INT 0x80 (legacy syscall)
        int80_count = 0
        for i in range(len(data) - 1):
            if data[i] == 0xCD and data[i+1] == 0x80:
                int80_count += 1
        print(f"  Total INT 0x80 instructions: {int80_count}")

    # ARM64 specific
    if e_machine == 0xB7:
        print(f"\n--- ARM64 SVC Instructions ---")
        svc_count = 0
        for i in range(0, len(data) - 3, 4):
            instr = struct.unpack_from('<I', data, i)[0]
            if instr == 0xD4000001:
                svc_count += 1

                # Check previous instruction for syscall number
                if i >= 4:
                    prev = struct.unpack_from('<I', data, i-4)[0]
                    if (prev & 0xFFE0001F) == 0xD2800008:  # MOVZ X8, #imm16
                        sysno = (prev >> 5) & 0xFFFF
                        names = {94: 'exit_group', 129: 'kill', 56: 'openat', 172: 'getpid', 117: 'ptrace'}
                        if sysno in names:
                            print(f"    SVC at 0x{i:x}: sys_{names[sysno]} ({sysno})")
                            # Find function start
                            for k in range(4, 512, 4):
                                if i - k < 0:
                                    break
                                pi = struct.unpack_from('<I', data, i - k)[0]
                                if (pi & 0xFFE07FFF) == 0xA9007BFD:
                                    func_start = i - k
                                    func_sig = data[func_start:func_start+16]
                                    print(f"      func_start=0x{func_start:x} sig: {func_sig.hex()}")
                                    break

        print(f"  Total SVC #0: {svc_count}")

    return data

# Scan both versions
TEMP = os.path.expandvars(r"%TEMP%")
data_x64 = scan_elf(os.path.join(TEMP, "libzyte_x64.so"), "x86_64 Promon")
data_arm64 = scan_elf(os.path.join(TEMP, "libzyte_arm64.so"), "ARM64 Promon")

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"x86_64 libzyte.so: {len(data_x64):,} bytes")
print(f"ARM64 libzyte.so: {len(data_arm64):,} bytes")
