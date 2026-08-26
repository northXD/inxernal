import frida, subprocess, time, sys

ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
DEV = "emulator-5554"
PKG = "com.supercell.hayday"
PORT = 31337
BIN = "/data/local/tmp/system_service"

def adb(*a):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True, text=True, timeout=10)

def log(m):
    m = str(m).encode('ascii', errors='replace').decode()
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

adb("shell", "su -c 'killall system_service 2>/dev/null; killall frida-server 2>/dev/null'")
adb("shell", f"am force-stop {PKG}")
adb("shell", "su -c 'rm -f /data/local/tmp/frida-* /data/local/tmp/nxrth-* 2>/dev/null'")
time.sleep(1)

subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -D -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
log(f"Connected ({len(device.enumerate_processes())} procs)")

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

pid = device.spawn(PKG)
log(f"Spawned PID {pid}")
sess = device.attach(pid)
sess.on("detached", on_det)

with open("hook.js", "r", encoding="utf-8") as f:
    code = f.read()
scr = sess.create_script(code)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

if not alive:
    log("DEAD before resume")
    sys.exit(1)

# DETACH hooks before resume — Promon checks libc integrity on startup
log("Detaching hooks for clean libc...")
scr.exports_sync.detachhooks()
time.sleep(0.5)

log("Resuming with clean libc...")
device.resume(pid)

# Wait for Promon's integrity check to pass (3 seconds)
log("Waiting 5s for Promon init to pass...")
for i in range(5):
    time.sleep(1)
    if not alive:
        log(f"DEAD at +{i+1}s (hooks were detached!)")
        break

if alive:
    log("Process survived Promon init! Re-attaching hooks...")
    scr.exports_sync.reattachhooks()
    time.sleep(1)

    if alive:
        log("Hooks re-attached! Testing agent...")
        try:
            scr.exports_sync.init()
            log("init() OK!")
            base = scr.exports_sync.getbase()
            log(f"libg.so base: {base}")
        except Exception as e:
            log(f"init/getbase: {e}")

    log("Monitoring (30s)...")
    start = time.time()
    for i in range(30):
        time.sleep(1)
        e = int(time.time() - start)
        if not alive:
            log(f"DEAD at +{e}s after reattach")
            break
        if e % 10 == 0:
            log(f"+{e}s alive, session OK")

    if alive:
        log("SURVIVED! Game running with hooks active!")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
