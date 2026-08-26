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
time.sleep(1)

subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -D -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
log(f"Connected ({len(device.enumerate_processes())} procs)")

alive = True
backtraces = []
def on_msg(m, d):
    if m["type"] == "send":
        payload = str(m['payload']).encode('ascii', errors='replace').decode()
        log(f"  JS: {payload}")
        if "BACKTRACE" in payload or "CALLER" in payload:
            backtraces.append(payload)
    elif m["type"] == "error":
        log(f"  ERR: {m.get('description','?')}")
def on_det(r):
    global alive
    log(f"DETACHED: {r}"); alive = False

pid = device.spawn(PKG)
log(f"Spawned PID {pid}")
sess = device.attach(pid)
sess.on("detached", on_det)

BACKTRACE_JS = r"""
function findExport(name) {
    var libs = ["libc.so","libdl.so"];
    for (var i=0;i<libs.length;i++) {
        try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){}
    }
    return null;
}

function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }

var _myPid = Process.id;
var _pthreadExit = findExport("pthread_exit");
var pthreadExitFn = _pthreadExit ? new NativeFunction(_pthreadExit, 'void', ['pointer']) : null;
var _nanosleep = findExport("nanosleep");
var nanosleepFn = _nanosleep ? new NativeFunction(_nanosleep, 'int', ['pointer', 'pointer']) : null;
var _longSleep = Memory.alloc(16);
_longSleep.writeU64(2147483647);
_longSleep.add(8).writeU64(0);

function resolveAddr(addr) {
    try {
        var mod = Process.findModuleByAddress(addr);
        if (mod) {
            var offset = addr.sub(mod.base);
            return mod.name + "+0x" + offset.toString(16) + " (" + addr + ")";
        }
    } catch(e) {}
    return addr.toString();
}

function captureBacktrace(label, ctx) {
    var tid = Process.getCurrentThreadId();
    send("[CALLER] " + label + " tid=" + tid + " (main=" + _myPid + ")");

    try {
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        send("[BACKTRACE] " + label + " (" + bt.length + " frames):");
        for (var i = 0; i < bt.length; i++) {
            send("[BACKTRACE]   [" + i + "] " + resolveAddr(bt[i]));
        }
    } catch(e) {
        send("[BACKTRACE] ACCURATE failed: " + e.message + ", trying FUZZY...");
        try {
            var bt2 = Thread.backtrace(ctx, Backtracer.FUZZY);
            send("[BACKTRACE] FUZZY " + label + " (" + bt2.length + " frames):");
            for (var i = 0; i < bt2.length; i++) {
                send("[BACKTRACE]   [" + i + "] " + resolveAddr(bt2[i]));
            }
        } catch(e2) {
            send("[BACKTRACE] FUZZY also failed: " + e2.message);
        }
    }

    // Read 64 bytes of ARM64 code at each caller address from libg.so
    try {
        var bt3 = Thread.backtrace(ctx, Backtracer.FUZZY);
        for (var i = 0; i < Math.min(bt3.length, 5); i++) {
            try {
                var mod = Process.findModuleByAddress(bt3[i]);
                if (mod && mod.name === "libg.so") {
                    var offset = bt3[i].sub(mod.base);
                    // Read 16 bytes at caller address (potential signature)
                    var bytes = bt3[i].readByteArray(16);
                    var hex = "";
                    var arr = new Uint8Array(bytes);
                    for (var j = 0; j < arr.length; j++) {
                        hex += ("0" + arr[j].toString(16)).slice(-2);
                    }
                    send("[SIGNATURE] Frame " + i + " libg.so+0x" + offset.toString(16) + " bytes: " + hex);

                    // Also read 16 bytes at the START of the function (scan back for function prologue)
                    // ARM64 function prologues typically start with STP X29, X30, [SP, #-offset]!
                    // Encoding: 0xA9xx7BFD (STP x29, x30, ...)
                    var scanBack = 256;
                    var funcStart = null;
                    for (var k = 0; k < scanBack; k += 4) {
                        try {
                            var instr = bt3[i].sub(k).readU32();
                            // Check for STP x29, x30, [sp, #offset]! pattern
                            if ((instr & 0xFFE07FFF) === 0xA9007BFD) {
                                funcStart = bt3[i].sub(k);
                                break;
                            }
                        } catch(e4) { break; }
                    }

                    if (funcStart) {
                        var funcOffset = funcStart.sub(mod.base);
                        var funcBytes = funcStart.readByteArray(16);
                        var funcHex = "";
                        var funcArr = new Uint8Array(funcBytes);
                        for (var j = 0; j < funcArr.length; j++) {
                            funcHex += ("0" + funcArr[j].toString(16)).slice(-2);
                        }
                        send("[FUNC-SIG] libg.so+0x" + funcOffset.toString(16) + " (func start) bytes: " + funcHex);
                    }
                }
            } catch(e3) {}
        }
    } catch(e) {}
}

function suspendThread(label) {
    var tid = Process.getCurrentThreadId();
    if (tid !== _myPid && pthreadExitFn) {
        pthreadExitFn(ptr(0));
    }
    if (nanosleepFn) {
        while (true) nanosleepFn(_longSleep, ptr(0));
    }
    while (true) {}
}

// Hook kill with backtrace capture
var killAddr = findExport("kill");
if (killAddr) {
    Interceptor.replace(killAddr, new NativeCallback(function(pid, sig) {
        if (pid === _myPid || pid === 0 || sig === 9 || sig === 6) {
            captureBacktrace("kill(" + pid + ", " + sig + ")", this.context);
            suspendThread("kill");
        }
        return 0;
    }, "int", ["int", "int"]));
    send("[HOOK] kill() hooked for backtrace");
}

// Hook _exit
var exitAddr = findExport("_exit");
if (exitAddr) {
    Interceptor.replace(exitAddr, new NativeCallback(function(code) {
        captureBacktrace("_exit(" + code + ")", this.context);
        suspendThread("_exit");
    }, "void", ["int"]));
    send("[HOOK] _exit() hooked for backtrace");
}

// Hook exit
var exitAddr2 = findExport("exit");
if (exitAddr2) {
    Interceptor.replace(exitAddr2, new NativeCallback(function(code) {
        captureBacktrace("exit(" + code + ")", this.context);
        suspendThread("exit");
    }, "void", ["int"]));
    send("[HOOK] exit() hooked for backtrace");
}

// Hook abort
var abortAddr = findExport("abort");
if (abortAddr) {
    Interceptor.replace(abortAddr, new NativeCallback(function() {
        captureBacktrace("abort()", this.context);
        suspendThread("abort");
    }, "void", []));
    send("[HOOK] abort() hooked for backtrace");
}

// Hook tgkill
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) {
    Interceptor.replace(tgkillAddr, new NativeCallback(function(tgid, tid, sig) {
        if (sig === 6 || sig === 9) {
            captureBacktrace("tgkill(tgid=" + tgid + ", tid=" + tid + ", sig=" + sig + ")", this.context);
            suspendThread("tgkill");
        }
        return 0;
    }, "int", ["int", "int", "int"]));
    send("[HOOK] tgkill() hooked for backtrace");
}

// Hook raise
var raiseAddr = findExport("raise");
if (raiseAddr) {
    Interceptor.replace(raiseAddr, new NativeCallback(function(sig) {
        if (sig === 6 || sig === 9 || sig === 11) {
            captureBacktrace("raise(" + sig + ")", this.context);
            return 0;
        }
        return 0;
    }, "int", ["int"]));
    send("[HOOK] raise() hooked for backtrace");
}

// Log libg.so info for reference
var libg = Process.findModuleByName("libg.so");
if (libg) {
    send("[INFO] libg.so base=" + libg.base + " size=0x" + libg.size.toString(16) + " (" + libg.size + " bytes)");
} else {
    send("[INFO] libg.so not loaded yet");
}

send("[READY] Backtrace capture hooks installed. Resume to trigger Promon.");

rpc.exports = {
    ping: function() { return "alive"; }
};
"""

scr = sess.create_script(BACKTRACE_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(2)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING to trigger Promon detection ===")
device.resume(pid)

log("Waiting for Promon kill attempt (30s)...")
start = time.time()
for i in range(30):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"Session ended at +{e}s")
        break
    if e % 5 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")

log(f"\nCaptured {len(backtraces)} backtrace entries")
for bt in backtraces:
    log(f"  {bt}")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
