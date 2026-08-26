"""
Patch frida-server v5: add frida-agent-*.so memfd name patches
to the existing v4 binary.
"""
import os, sys, shutil

SRC = os.path.expandvars(r"%TEMP%\system_service_v4")
DST = os.path.expandvars(r"%TEMP%\system_service_v5")

if not os.path.exists(SRC):
    print(f"Source not found: {SRC}")
    sys.exit(1)

shutil.copy2(SRC, DST)

with open(DST, "rb") as f:
    data = f.read()

print(f"Binary size: {len(data):,} bytes")

# New patches on top of v4.
# Frida 17 derives the final memfd name from templates such as
# "frida-agent-<arch>.so".  Patching only the already-expanded 32/64 names
# leaves that template intact and the target still gets mapped as
# /memfd:frida-agent-64.so.  Replace the common, equal-length prefixes so all
# concrete names and templates are covered without changing binary offsets.
patches = [
    (b"frida-agent",  b"nxrth-agent"),
]

total_patches = 0
for old, new in patches:
    assert len(old) == len(new), f"Length mismatch: {old} ({len(old)}) vs {new} ({len(new)})"
    count = data.count(old)
    if count > 0:
        data = data.replace(old, new)
        print(f"  {old.decode()} => {new.decode()}: {count} replacements")
        total_patches += count
    else:
        print(f"  {old.decode()}: not found (skip)")

with open(DST, "wb") as f:
    f.write(data)

print(f"\nTotal patches applied: {total_patches}")
print(f"Output: {DST}")
print(f"Size: {len(data):,} bytes")
