"""
Dump libg.so from running game process memory (no Frida involved).
1. Start game normally
2. Wait for it to load
3. Get PID
4. Read /proc/pid/maps to find libg.so ranges
5. Dump executable sections via /proc/pid/mem
6. Pull dump to PC for analysis
"""
import subprocess, time, sys, os, struct

ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
DEV = "emulator-5554"
PKG = "com.supercell.hayday"
DUMP_DIR = "/data/local/tmp/promon_dump"

def adb(*a, timeout=10):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True, text=True, timeout=timeout)

def adb_shell(cmd, timeout=10):
    return adb("shell", f"su -c '{cmd}'", timeout=timeout)

def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

# Kill any existing game
adb("shell", f"am force-stop {PKG}")
time.sleep(1)

# Start game normally (NO Frida)
log("Starting game normally (no Frida)...")
adb("shell", f"am start -n {PKG}/com.supercell.hayday.GameApp")
time.sleep(2)

# Get PID
r = adb_shell(f"pidof {PKG}")
pid = r.stdout.strip()
if not pid:
    log("Game not running, trying monkey launch...")
    adb("shell", f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1")
    time.sleep(3)
    r = adb_shell(f"pidof {PKG}")
    pid = r.stdout.strip()

if not pid:
    log("ERROR: Could not get game PID")
    sys.exit(1)

log(f"Game PID: {pid}")

# Wait for libg.so to load (check every second)
log("Waiting for libg.so to load...")
libg_loaded = False
for i in range(20):
    r = adb_shell(f"cat /proc/{pid}/maps 2>/dev/null | grep libg.so | head -1")
    if r.stdout.strip():
        libg_loaded = True
        log(f"libg.so loaded after {i+1}s")
        break
    # Check if process is still alive
    r2 = adb_shell(f"kill -0 {pid} 2>&1")
    if "No such process" in r2.stderr or r2.returncode != 0:
        # Try to get new PID (game might have restarted)
        r3 = adb_shell(f"pidof {PKG}")
        new_pid = r3.stdout.strip()
        if new_pid and new_pid != pid:
            log(f"PID changed: {pid} -> {new_pid}")
            pid = new_pid
        elif not new_pid:
            log(f"Game died at +{i+1}s!")
            sys.exit(1)
    time.sleep(1)

if not libg_loaded:
    log("libg.so not loaded after 20s, checking maps...")
    r = adb_shell(f"cat /proc/{pid}/maps 2>/dev/null | head -20")
    log(r.stdout)
    sys.exit(1)

# Wait a bit more for full initialization
log("Waiting 3 more seconds for full init...")
time.sleep(3)

# Get all libg.so memory ranges
log("Reading libg.so memory ranges...")
r = adb_shell(f"cat /proc/{pid}/maps | grep libg.so")
maps_output = r.stdout.strip()
log(f"libg.so maps entries:\n{maps_output}")

# Parse ranges
ranges = []
for line in maps_output.split('\n'):
    if not line.strip():
        continue
    parts = line.split()
    addrs = parts[0].split('-')
    perms = parts[1]
    start = int(addrs[0], 16)
    end = int(addrs[1], 16)
    size = end - start
    ranges.append({'start': start, 'end': end, 'size': size, 'perms': perms, 'line': line.strip()})
    log(f"  0x{start:x}-0x{end:x} ({size:,} bytes) {perms}")

# Create dump directory
adb_shell(f"mkdir -p {DUMP_DIR}")

# Dump executable ranges (r-xp)
rx_ranges = [r for r in ranges if 'x' in r['perms']]
log(f"\nDumping {len(rx_ranges)} executable ranges...")

dump_files = []
for i, rng in enumerate(rx_ranges):
    dump_file = f"{DUMP_DIR}/libg_rx_{i}_0x{rng['start']:x}.bin"
    log(f"  Dumping 0x{rng['start']:x} ({rng['size']:,} bytes)...")

    # Use dd to read from /proc/pid/mem
    # dd on Android may not support large skip values well, so use a helper
    cmd = f"dd if=/proc/{pid}/mem bs=4096 skip={rng['start'] // 4096} count={rng['size'] // 4096 + 1} of={dump_file} 2>/dev/null"
    r = adb_shell(cmd, timeout=30)

    # Verify dump
    r2 = adb_shell(f"ls -la {dump_file}")
    log(f"    {r2.stdout.strip()}")
    dump_files.append({
        'file': dump_file,
        'start': rng['start'],
        'size': rng['size'],
        'perms': rng['perms']
    })

# Also dump readable ranges (for string references)
r_ranges = [r for r in ranges if 'r' in r['perms'] and 'x' not in r['perms']]
log(f"\nDumping {len(r_ranges)} readable (data) ranges...")

for i, rng in enumerate(r_ranges):
    dump_file = f"{DUMP_DIR}/libg_r_{i}_0x{rng['start']:x}.bin"
    log(f"  Dumping 0x{rng['start']:x} ({rng['size']:,} bytes)...")
    cmd = f"dd if=/proc/{pid}/mem bs=4096 skip={rng['start'] // 4096} count={rng['size'] // 4096 + 1} of={dump_file} 2>/dev/null"
    r = adb_shell(cmd, timeout=30)
    r2 = adb_shell(f"ls -la {dump_file}")
    log(f"    {r2.stdout.strip()}")
    dump_files.append({
        'file': dump_file,
        'start': rng['start'],
        'size': rng['size'],
        'perms': rng['perms']
    })

# Pull all dumps to PC
LOCAL_DUMP = os.path.expandvars(r"%TEMP%\promon_dump")
os.makedirs(LOCAL_DUMP, exist_ok=True)

log(f"\nPulling dumps to {LOCAL_DUMP}...")
r = adb("pull", DUMP_DIR, LOCAL_DUMP, timeout=60)
log(r.stdout.strip() if r.stdout else r.stderr.strip())

# List what we got
for f in os.listdir(os.path.join(LOCAL_DUMP, "promon_dump")):
    fpath = os.path.join(LOCAL_DUMP, "promon_dump", f)
    fsize = os.path.getsize(fpath)
    log(f"  {f}: {fsize:,} bytes")

# Save metadata
import json
meta = {
    'pid': pid,
    'ranges': ranges,
    'dump_files': dump_files
}
with open(os.path.join(LOCAL_DUMP, "meta.json"), "w") as f:
    json.dump(meta, f, indent=2, default=str)

log(f"\nDump complete. PID={pid}, {len(dump_files)} files")
log("Now run scan_dump.py to find Promon signatures")
