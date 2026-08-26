"""
Interactive-ish RE helper over the libg.so memory dump (ARM64).

Builds (and caches) a call graph + string xref map via manual ARM64 decoding,
so we can navigate: who calls a function, what a function references/calls,
and where a string is used.

First run decodes (~seconds) and caches to rev_cache.pkl.

Commands:
    python rev.py callers 0xADDR        functions that BL into ADDR
    python rev.py func    0xADDR [n]     strings + calls inside the function
    python rev.py disasm  0xADDR [n]     raw disassembly
    python rev.py strxref SUBSTR         strings matching SUBSTR + owning funcs
    python rev.py calls   0xADDR         call targets made from the function
"""
import bisect
import os
import pickle
import re
import sys

DUMP = "libg_dump.so"
CACHE = "rev_cache.pkl"
CODE_START = 0x1000
CODE_END = 0x141e010
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def sx(v, b):
    return v - (1 << b) if v & (1 << (b - 1)) else v


def build(data):
    strings = {m.start(): m.group().decode("ascii", "replace")
               for m in PRINTABLE.finditer(data)}
    xrefs = {}          # data/string target -> [insn addr]
    bl_edges = {}       # callee -> [caller site addr]
    calls = set()       # function starts (BL targets)
    reg_page = [None] * 32
    end = min(CODE_END, len(data))
    for a in range(CODE_START, end - 3, 4):
        w = int.from_bytes(data[a:a + 4], "little")
        if w & 0x9F000000 == 0x90000000:                    # ADRP
            rd = w & 0x1F
            imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21) << 12
            reg_page[rd] = (a & ~0xFFF) + imm
        elif w & 0xFF800000 == 0x91000000:                  # ADD imm
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            imm = (w >> 10) & 0xFFF
            if (w >> 22) & 1:
                imm <<= 12
            p = reg_page[rn]
            if p is not None and 0 <= p + imm < len(data):
                xrefs.setdefault(p + imm, []).append(a)
            reg_page[rd] = None
        elif w & 0xFFC00000 == 0xF9400000:                  # LDR imm
            rt, rn = w & 0x1F, (w >> 5) & 0x1F
            p = reg_page[rn]
            if p is not None:
                t = p + ((w >> 10) & 0xFFF) * 8
                if 0 <= t < len(data):
                    xrefs.setdefault(t, []).append(a)
            reg_page[rt] = None
        elif w & 0xFC000000 == 0x94000000:                  # BL
            t = a + (sx(w & 0x03FFFFFF, 26) << 2)
            calls.add(t)
            bl_edges.setdefault(t, []).append(a)
    return {"strings": strings, "xrefs": xrefs,
            "bl_edges": bl_edges, "calls": sorted(calls)}


def load():
    data = open(DUMP, "rb").read()
    if os.path.exists(CACHE) and os.path.getmtime(CACHE) >= os.path.getmtime(DUMP):
        with open(CACHE, "rb") as f:
            db = pickle.load(f)
    else:
        print("[*] decoding (first run) ...", file=sys.stderr)
        db = build(data)
        with open(CACHE, "wb") as f:
            pickle.dump(db, f)
    db["data"] = data
    return db


def func_of(calls, a):
    i = bisect.bisect_right(calls, a) - 1
    return calls[i] if i >= 0 else None


def next_func(calls, f):
    i = bisect.bisect_right(calls, f)
    return calls[i] if i < len(calls) else CODE_END


def parse_addr(s):
    return int(s, 16) if s.startswith("0x") else int(s, 0)


def cmd_callers(db, a):
    sites = db["bl_edges"].get(a, [])
    print(f"{len(sites)} caller site(s) of 0x{a:08x}:")
    seen = set()
    for s in sorted(sites):
        f = func_of(db["calls"], s)
        if f in seen:
            continue
        seen.add(f)
        print(f"  site 0x{s:08x}  in func 0x{f:08x}" if f else f"  site 0x{s:08x}")


def cmd_func(db, f, _n=None):
    nf = next_func(db["calls"], f)
    print(f"func 0x{f:08x} .. 0x{nf:08x}  ({(nf - f)} bytes)")
    print("  -- strings referenced --")
    for off in sorted(db["strings"]):
        for site in db["xrefs"].get(off, []):
            if f <= site < nf:
                s = db["strings"][off]
                print(f"    0x{site:08x} -> \"{s[:70]}\"")
                break
    print("  -- calls made --")
    made = set()
    for callee, sites in db["bl_edges"].items():
        for s in sites:
            if f <= s < nf:
                made.add((s, callee))
    for s, callee in sorted(made):
        print(f"    0x{s:08x} -> 0x{callee:08x}")


def cmd_disasm(db, a, n=60):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    code = db["data"][a:a + n * 4]
    for ins in md.disasm(code, a):
        print(f"  0x{ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}")


def cmd_strxref(db, needle):
    needle = needle.lower()
    for off in sorted(db["strings"]):
        s = db["strings"][off]
        if needle in s.lower():
            sites = db["xrefs"].get(off, [])
            if sites:
                funcs = sorted({func_of(db["calls"], x) for x in sites})
                ftxt = " ".join(f"0x{x:08x}" for x in funcs if x)
                print(f"  0x{off:06x} \"{s[:55]}\"  <- {ftxt}")
            else:
                print(f"  0x{off:06x} \"{s[:55]}\"  (no xref)")


def cmd_calls(db, f, _n=None):
    cmd_func(db, f)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    db = load()
    cmd = sys.argv[1]
    if cmd == "strxref":
        cmd_strxref(db, sys.argv[2])
    elif cmd == "callers":
        cmd_callers(db, parse_addr(sys.argv[2]))
    elif cmd in ("func", "calls"):
        cmd_func(db, parse_addr(sys.argv[2]))
    elif cmd == "disasm":
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 60
        cmd_disasm(db, parse_addr(sys.argv[2]), n)
    else:
        print("unknown command:", cmd)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
