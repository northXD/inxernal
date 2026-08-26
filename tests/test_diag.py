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

def on_msg(m, d):
    if m["type"] == "send":
        payload = str(m['payload']).encode('ascii', errors='replace').decode()
        log(f"  JS: {payload}")

pid = device.spawn(PKG)
log(f"Spawned PID {pid}")
sess = device.attach(pid)
sess.on("detached", lambda r: log(f"DETACHED: {r}"))

with open("hook.js", "r", encoding="utf-8") as f:
    code = f.read()
scr = sess.create_script(code)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

log("=== MODULES (before resume) ===")
try:
    mods = scr.exports_sync.diagmodules()
    for m in mods:
        m = str(m).encode('ascii', errors='replace').decode()
        if any(x in m.lower() for x in ['frida', 'gum', 'shield', 'promon', 'guard', 'secure', 'protect', 'tamper']):
            log(f"  *** {m}")
        elif 'libg.so' in m or 'hayday' in m or 'supercell' in m:
            log(f"  [GAME] {m}")
except Exception as e:
    log(f"diagmodules failed: {e}")

log("=== THREADS (before resume) ===")
try:
    threads = scr.exports_sync.diagthreads()
    log(f"  {len(threads)} threads")
    for t in threads[:10]:
        log(f"  {t}")
except Exception as e:
    log(f"diagthreads failed: {e}")

log("=== ALL MODULES ===")
try:
    mods = scr.exports_sync.diagmodules()
    for m in mods:
        m = str(m).encode('ascii', errors='replace').decode()
        log(f"  {m}")
except Exception as e:
    log(f"failed: {e}")

log("Cleanup")
device.kill(pid)
adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
