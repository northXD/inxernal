"""
Test: Start game without Frida, patch libzyte.so via /proc/pid/mem, then attach Frida.
Step 1: Just test if we can attach to a running game (no patching yet).
"""
import frida, subprocess, time, sys

ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
DEV = "emulator-5554"
PKG = "com.supercell.hayday"
PORT = 31337
BIN = "/data/local/tmp/system_service"

def adb(*a, timeout=10):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True, text=True, timeout=timeout)

def log(m):
    m = str(m).encode('ascii', errors='replace').decode()
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

# Kill everything
adb("shell", "su -c 'killall system_service 2>/dev/null'")
adb("shell", f"am force-stop {PKG}")
time.sleep(1)

# Start frida-server
subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
log(f"Connected ({len(device.enumerate_processes())} procs)")

# Start game normally (NOT through Frida spawn)
log("Starting game normally (no Frida injection)...")
adb("shell", f"am start -n {PKG}/.GameApp")
time.sleep(8)  # Wait for game to start and pass initial checks

# Find the game PID
r = adb("shell", f"pidof {PKG}")
game_pid = r.stdout.strip()
if not game_pid:
    log("Game not running after 8s!")
    sys.exit(1)

game_pid = int(game_pid)
log(f"Game PID: {game_pid}")

# Check libzyte.so is loaded
r = adb("shell", f"su -c 'cat /proc/{game_pid}/maps | grep zyte'")
log(f"libzyte.so maps:\n{r.stdout.strip()}")

# Get libzyte.so x86_64 base address
zyte_base = None
for line in r.stdout.strip().split('\n'):
    if 'x86_64' in line and 'r-xp' in line:
        zyte_base = int(line.split('-')[0], 16)
        break

if zyte_base:
    log(f"libzyte.so x86_64 base: 0x{zyte_base:x}")
else:
    log("WARNING: libzyte.so x86_64 not found")

# Now try to attach Frida to the running game
log("Attempting Frida attach to running game...")
alive = True

def on_msg(m, d):
    if m["type"] == "send":
        payload = str(m['payload']).encode('ascii', errors='replace').decode()
        log(f"  JS: {payload}")
    elif m["type"] == "error":
        log(f"  ERR: {m.get('description','?')}")

def on_det(r):
    global alive
    log(f"DETACHED: {r}"); alive = False

try:
    sess = device.attach(game_pid)
    sess.on("detached", on_det)
    log("Attach successful!")

    # Load a minimal script
    MINIMAL_JS = """
    send("[ATTACH] Frida attached to PID " + Process.id);
    send("[ATTACH] Arch: " + Process.arch);
    send("[ATTACH] Modules: " + Process.enumerateModules().length);

    var libg = Process.findModuleByName("libg.so");
    if (libg) send("[ATTACH] libg.so at " + libg.base);

    rpc.exports = {
        ping: function() { return "alive"; }
    };
    """

    scr = sess.create_script(MINIMAL_JS)
    scr.on("message", on_msg)
    scr.load()
    time.sleep(1)

    log("Monitoring (30s)...")
    start = time.time()
    for i in range(30):
        time.sleep(1)
        e = int(time.time() - start)
        if not alive:
            log(f"Detached at +{e}s after attach")
            break
        if e % 5 == 0:
            try:
                r = scr.exports_sync.ping()
                log(f"+{e}s alive")
            except Exception as ex:
                log(f"+{e}s RPC failed: {ex}")

    if alive:
        log("SURVIVED 30s after attach!")

except frida.ProcessNotFoundError:
    log("ERROR: Process not found")
except frida.ServerNotRunningError:
    log("ERROR: Frida server not running")
except Exception as e:
    log(f"ERROR: {e}")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
