"""
Static analysis of a memory-dumped libg.so (ARM64, Titan/Logic engine).

Input: a raw memory image from the loader's `dumpso` command, where
file offset == (virtual address - module base). Load address is 0.

Manual ARM64 instruction decoding (no capstone operand quirks):
  - ADRP + ADD/LDR string cross-references
  - BL call-target set -> reliable function-start boundaries

Usage:
    python analyze_libg.py libg_dump.so                 # keyword sweep
    python analyze_libg.py libg_dump.so --find SUBSTR   # xref a substring
    python analyze_libg.py libg_dump.so --exec          # map *::execute() via
                                                          "failed to execute"
"""
import bisect
import re
import sys

CODE_START = 0x1000          # skip ELF header/phdrs
CODE_END = 0x141e010         # PH1 LOAD (r-x) end, from program headers
MIN_STR_LEN = 4
PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STR_LEN)

DEFAULT_KEYWORDS = [
    "crop", "plant", "harvest", "field", "seed", "grow", "command",
]


def sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= (1 << bits)
    return value


def extract_strings(data):
    out = {}
    for m in PRINTABLE.finditer(data):
        out[m.start()] = m.group().decode("ascii", "replace")
    return out


def decode(data):
    """One linear pass: string xrefs + call targets, via manual bit decoding."""
    xrefs = {}
    calls = set()
    reg_page = [None] * 32
    end = min(CODE_END, len(data))
    for a in range(CODE_START, end - 3, 4):
        word = int.from_bytes(data[a:a + 4], "little")
        top = word & 0x9F000000
        if top == 0x90000000:  # ADRP
            rd = word & 0x1F
            immlo = (word >> 29) & 0x3
            immhi = (word >> 5) & 0x7FFFF
            imm = sx((immhi << 2) | immlo, 21) << 12
            reg_page[rd] = (a & ~0xFFF) + imm
            continue
        if (word & 0xFF800000) == 0x91000000:  # ADD (imm, 64-bit)
            rd = word & 0x1F
            rn = (word >> 5) & 0x1F
            imm12 = (word >> 10) & 0xFFF
            if (word >> 22) & 1:
                imm12 <<= 12
            page = reg_page[rn]
            if page is not None:
                t = page + imm12
                if 0 <= t < len(data):
                    xrefs.setdefault(t, []).append(a)
            reg_page[rd] = None
            continue
        if (word & 0xFFC00000) == 0xF9400000:  # LDR (imm unsigned, 64-bit)
            rt = word & 0x1F
            rn = (word >> 5) & 0x1F
            imm12 = ((word >> 10) & 0xFFF) * 8
            page = reg_page[rn]
            if page is not None:
                t = page + imm12
                if 0 <= t < len(data):
                    xrefs.setdefault(t, []).append(a)
            reg_page[rt] = None
            continue
        if (word & 0xFC000000) == 0x94000000:  # BL
            calls.add(a + (sx(word & 0x03FFFFFF, 26) << 2))
            continue
    return xrefs, sorted(calls)


def func_start(calls, addr):
    i = bisect.bisect_right(calls, addr) - 1
    return calls[i] if i >= 0 else None


def report_xrefs(label, offset, text, xrefs, calls):
    refs = xrefs.get(offset)
    snippet = text if len(text) <= 50 else text[:47] + "..."
    if not refs:
        print(f"  {label} 0x{offset:08x} \"{snippet}\"  (no code xref)")
        return
    print(f"  {label} 0x{offset:08x} \"{snippet}\"")
    seen = set()
    for ref in refs[:8]:
        fn = func_start(calls, ref)
        key = fn if fn is not None else ref
        if key in seen:
            continue
        seen.add(key)
        fn_txt = f"func 0x{fn:08x}" if fn is not None else "func ?"
        print(f"      xref @ 0x{ref:08x}  ->  {fn_txt}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    data = open(path, "rb").read()
    print(f"[+] Loaded {len(data)} bytes")

    strings = extract_strings(data)
    print(f"[+] {len(strings)} strings")
    print("[*] Decoding ARM64 (xrefs + call targets) ...")
    xrefs, calls = decode(data)
    print(f"[+] {len(xrefs)} referenced offsets, {len(calls)} call targets\n")

    args = sys.argv[2:]
    if args and args[0] == "--find":
        needle = args[1].lower()
        print(f"=== strings containing '{needle}' with xrefs ===")
        for off in sorted(strings):
            if needle in strings[off].lower():
                report_xrefs("str", off, strings[off], xrefs, calls)
        return 0

    if args and args[0] == "--exec":
        print("=== *::execute() via 'failed to execute' strings ===")
        for off in sorted(strings):
            if "failed to execute" in strings[off].lower():
                report_xrefs("cmd", off, strings[off], xrefs, calls)
        return 0

    keywords = [k.lower() for k in args] or DEFAULT_KEYWORDS
    for kw in keywords:
        print(f"\n########## '{kw}' ##########")
        for off in sorted(strings):
            if kw in strings[off].lower():
                report_xrefs("str", off, strings[off], xrefs, calls)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
