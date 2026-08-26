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

# Check if v5 is working by verifying server identity
r = adb("shell", "su -c 'cat /proc/$(pidof system_service)/maps | head -5'")
log(f"Server maps (first 5):\n{r.stdout.strip()}")

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

MINIMAL_V5_JS = r"""
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent"];

function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }
function hasFridaSig(s) { var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

function findExport(name) {
    var libs = ["libc.so","libdl.so"];
    for (var i=0;i<libs.length;i++) { try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){} }
    return null;
}

// 1. Patch linker data (rename frida modules in dl_iterate_phdr)
var dlAddr = findExport("dl_iterate_phdr");
if (dlAddr) {
    var dlFn = new NativeFunction(dlAddr, 'int', ['pointer', 'pointer']);
    var patchCount = 0;
    dlFn(new NativeCallback(function(info, size, data) {
        try {
            var namePtr = info.add(Process.pointerSize).readPointer();
            var name = safeRead(namePtr);
            if (name && hasFridaSig(name)) {
                var newName = name
                    .replace(/frida-agent/g,"system-agent")
                    .replace(/frida-gadget/g,"system-gadgt")
                    .replace(/frida-helper/g,"system-hlper")
                    .replace(/frida/g,"nxrth")
                    .replace(/gum-js-loop/g,"app-js-loop");
                try { Memory.protect(namePtr, newName.length+1, 'rwx'); namePtr.writeUtf8String(newName); patchCount++; } catch(e){}
            }
        } catch(e){}
        return 0;
    }, 'int', ['pointer','int','pointer']), ptr(0));
    send("[PATCH] Renamed " + patchCount + " modules in linker data");
}

// 2. Rename Frida thread names via prctl(PR_SET_NAME)
var prctlAddr = findExport("prctl");
if (prctlAddr) {
    var prctlFn = new NativeFunction(prctlAddr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
    var threadRenames = {
        "gum-js-loop": "app-js-loop",
        "gmain": "binder:main",
        "gdbus": "binder:dbus",
        "pool-frida": "pool-system",
        "frida-gadget": "system-gadgt"
    };
    var threadsRenamed = 0;
    Process.enumerateThreads().forEach(function(t) {
        try {
            var commPath = "/proc/self/task/" + t.id + "/comm";
            var f = new File(commPath, "r");
            var name = f.readLine().trim();
            f.close();
            for (var pattern in threadRenames) {
                if (name.indexOf(pattern) !== -1) {
                    var newName = threadRenames[pattern];
                    // Write new name to /proc/self/task/TID/comm
                    var fw = new File("/proc/self/task/" + t.id + "/comm", "w");
                    fw.write(newName + "\n");
                    fw.close();
                    threadsRenamed++;
                    send("[PATCH] Thread " + t.id + ": " + name + " => " + newName);
                }
            }
        } catch(e) {}
    });
    send("[PATCH] Renamed " + threadsRenamed + " threads");
}

// 3. Check what the game sees in /proc/self/maps for our agent
try {
    var maps = new File("/proc/self/maps", "r");
    var content = "";
    var line;
    var fridaLines = [];
    while ((line = maps.readLine()) !== "") {
        if (line.toLowerCase().indexOf("frida") !== -1 ||
            line.toLowerCase().indexOf("nxrth") !== -1 ||
            line.indexOf("memfd:") !== -1 ||
            line.indexOf("system-agent") !== -1) {
            fridaLines.push(line.trim());
        }
    }
    maps.close();
    send("[MAPS] Suspicious entries: " + fridaLines.length);
    for (var i = 0; i < fridaLines.length; i++) {
        send("[MAPS]   " + fridaLines[i]);
    }
} catch(e) {
    send("[MAPS] Failed to read: " + e.message);
}

// 4. Check /proc/net/tcp for our port
try {
    var tcp = new File("/proc/net/tcp", "r");
    var portLines = [];
    var line2;
    while ((line2 = tcp.readLine()) !== "") {
        if (line2.indexOf(":7A69") !== -1 || line2.indexOf(":7a69") !== -1 ||
            line2.indexOf(":69A2") !== -1 || line2.indexOf(":69a2") !== -1) {
            portLines.push(line2.trim());
        }
    }
    tcp.close();
    send("[TCP] Frida port entries: " + portLines.length);
    for (var i = 0; i < portLines.length; i++) {
        send("[TCP]   " + portLines[i]);
    }
} catch(e) {
    send("[TCP] Failed: " + e.message);
}

// 5. Check thread names
try {
    var threads = Process.enumerateThreads();
    var suspThreads = [];
    for (var i = 0; i < threads.length; i++) {
        try {
            var cf = new File("/proc/self/task/" + threads[i].id + "/comm", "r");
            var tn = cf.readLine().trim();
            cf.close();
            if (tn.indexOf("frida") !== -1 || tn.indexOf("gum-js") !== -1 ||
                tn.indexOf("gmain") !== -1 || tn.indexOf("gdbus") !== -1 ||
                tn.indexOf("linjector") !== -1) {
                suspThreads.push(threads[i].id + "=" + tn);
            }
        } catch(e2) {}
    }
    send("[THREADS] Suspicious: " + (suspThreads.length > 0 ? suspThreads.join(", ") : "NONE"));
} catch(e) {
    send("[THREADS] Failed: " + e.message);
}

send("[V5-TEST] No hooks installed. All patches applied. Ready to resume.");

rpc.exports = {
    ping: function() { return "alive"; }
};
"""

scr = sess.create_script(MINIMAL_V5_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(2)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING with v5 binary (renamed memfd) + thread patches + no hooks ===")
device.resume(pid)

log("Monitoring (45s)...")
start = time.time()
for i in range(45):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s")
        if e <= 2:
            log("=> FAST KILL: Agent still detected despite v5 patches")
            log("=> Need external /proc/pid/mem patching (friend's approach)")
        elif e <= 8:
            log("=> MEDIUM KILL: Survived longer, some detection bypassed")
        else:
            log("=> LATE KILL: Most detection bypassed, check remaining vectors")
        break
    if e % 5 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive, RPC OK")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")

if alive:
    log("SURVIVED 45s with v5 + thread patches + NO hooks!")
    log("=> memfd rename + thread rename BYPASSES Promon detection!")
    log("=> Can now test with full hooks")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
