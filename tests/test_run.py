import frida
import subprocess
import time
import sys

ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
DEV = "emulator-5554"
PKG = "com.supercell.hayday"
PORT = 31337
BIN = "/data/local/tmp/system_service"

def adb(*args):
    return subprocess.run([ADB, "-s", DEV] + list(args), capture_output=True, text=True, timeout=10)

def ts():
    return time.strftime("%H:%M:%S")

def log(msg):
    print(f"[{ts()}] {msg}", flush=True)

log("Killing server + game")
adb("shell", "su -c 'killall system_service 2>/dev/null; killall frida-server 2>/dev/null'")
adb("shell", f"am force-stop {PKG}")
adb("shell", "su -c 'rm -f /data/local/tmp/frida-* /data/local/tmp/nxrth-* /data/local/tmp/re.frida.* 2>/dev/null'")
time.sleep(1)

log("Starting server")
subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -D -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

r = adb("shell", "pidof system_service")
if not r.stdout.strip():
    log("Server failed to start!")
    sys.exit(1)
log(f"Server PID: {r.stdout.strip()}")

log("Connecting")
adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
mgr = frida.get_device_manager()
device = mgr.add_remote_device(f"127.0.0.1:{PORT}")
log(f"Connected ({len(device.enumerate_processes())} procs)")

alive = True
kill_count = 0

def on_msg(message, data):
    global kill_count
    if message["type"] == "send":
        payload = message['payload']
        log(f"  JS: {payload}")
        if "[ANTI-KILL]" in payload:
            kill_count += 1
    elif message["type"] == "error":
        log(f"  ERR: {message.get('description', str(message))}")

def on_detach(reason):
    global alive
    log(f"DETACHED: {reason}")
    alive = False

log("Spawning")
pid = device.spawn(PKG)
log(f"PID: {pid}")

log("Attaching")
session = device.attach(pid)
session.on("detached", on_detach)

log("Loading hooks")
with open("hook.js", "r", encoding="utf-8") as f:
    code = f.read()
script = session.create_script(code)
script.on("message", on_msg)
script.load()
time.sleep(1)

if not alive:
    log("DEAD before resume")
    sys.exit(1)

log("Resuming")
device.resume(pid)

log("Monitoring (90s)...")
start = time.time()

init_done = False
for i in range(90):
    time.sleep(1)
    elapsed = int(time.time() - start)

    if not alive:
        log(f"DEAD at +{elapsed}s (kill_count={kill_count})")
        break

    if elapsed == 3 and not init_done:
        log("Calling init() early...")
        try:
            script.exports_sync.init()
            init_done = True
            log("init() OK")
        except Exception as e:
            log(f"init() failed: {e}")

    if elapsed == 5 and init_done:
        try:
            base = script.exports_sync.getbase()
            log(f"libg.so base: {base}")
        except Exception as e:
            log(f"getbase failed: {e}")

    if elapsed % 10 == 0:
        r = adb("shell", f"ls /proc/{pid}/cmdline 2>/dev/null && cat /proc/{pid}/cmdline 2>/dev/null || echo GONE")
        status = r.stdout.strip()
        log(f"+{elapsed}s alive={alive} kills={kill_count} proc={status[:60]}")

if alive:
    log(f"SURVIVED 90s! kills={kill_count}")

log("Cleanup")
adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
