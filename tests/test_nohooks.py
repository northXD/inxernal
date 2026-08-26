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
def on_det(r):
    global alive
    log(f"DETACHED: {r}"); alive = False

pid = device.spawn(PKG)
log(f"Spawned PID {pid}")
sess = device.attach(pid)
sess.on("detached", on_det)

# MINIMAL script: only patch linker data + detach everything
MINIMAL_JS = """
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent"];

function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }
function hasFridaSig(s) { var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

function findExport(name) {
    var libs = ["libc.so","libdl.so"];
    for (var i=0;i<libs.length;i++) { try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){} }
    return null;
}

// Patch linker data (rename frida modules)
var dlAddr = findExport("dl_iterate_phdr");
if (dlAddr) {
    var dlFn = new NativeFunction(dlAddr, 'int', ['pointer', 'pointer']);
    var patchCount = 0;
    dlFn(new NativeCallback(function(info, size, data) {
        try {
            var namePtr = info.add(Process.pointerSize).readPointer();
            var name = safeRead(namePtr);
            if (name && hasFridaSig(name)) {
                var newName = name.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth");
                try { Memory.protect(namePtr, newName.length+1, 'rwx'); namePtr.writeUtf8String(newName); patchCount++; } catch(e){}
            }
        } catch(e){}
        return 0;
    }, 'int', ['pointer','int','pointer']), ptr(0));
    send("[PATCH] Renamed " + patchCount + " modules");
}

send("[MINIMAL] No hooks installed. Clean libc. Ready to resume.");

rpc.exports = {
    ping: function() { return "alive"; }
};
"""

scr = sess.create_script(MINIMAL_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

log("Resuming with ZERO hooks (only linker patch)...")
device.resume(pid)

log("Monitoring (30s)...")
start = time.time()
for i in range(30):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s (NO hooks were active!)")
        log("=> Promon detects frida AGENT presence, not just hooks")
        break
    if e % 5 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive, RPC OK: {r}")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")

if alive:
    log("SURVIVED 30s with NO hooks!")
    log("=> Promon only detects hook modifications, not agent presence")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
