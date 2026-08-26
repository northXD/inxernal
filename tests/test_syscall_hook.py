"""
Test: Hook libc syscall() to neuter SYS_kill and SYS_exit_group.
libzyte.so (Promon) has NO direct SYSCALL/INT80 instructions -
all kills go through libc wrappers. Hooking syscall() should catch everything.
"""
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

SYSCALL_HOOK_JS = r"""
function findExport(name) {
    var libs = ["libc.so","libdl.so"];
    for (var i=0;i<libs.length;i++) {
        try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){}
    }
    return null;
}

function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }

var _myPid = Process.id;
var hookCount = 0;
var missed = [];

function hookSafe(name, callbacks) {
    var p = findExport(name);
    if (!p) { missed.push(name); return false; }
    try { Interceptor.attach(p, callbacks); hookCount++; return true; }
    catch(e) { missed.push(name+"(FAIL)"); return false; }
}

function replaceSafe(name, retType, argTypes, impl) {
    var p = findExport(name);
    if (!p) { missed.push(name); return false; }
    try {
        Interceptor.replace(p, new NativeCallback(impl, retType, argTypes));
        hookCount++;
        return true;
    } catch(e) { missed.push(name+"(FAIL)"); return false; }
}

// ── SYSCALL HOOK (KEY FIX) ──
// libzyte.so (Promon) uses libc syscall() for SYS_kill and SYS_exit_group
// We intercept and change the syscall number to SYS_getpid (harmless)
var syscallAddr = findExport("syscall");
if (syscallAddr) {
    Interceptor.attach(syscallAddr, {
        onEnter: function(args) {
            var num = args[0].toInt32();
            // x86_64 syscall numbers
            if (num === 62) { // SYS_kill
                var targetPid = args[1].toInt32();
                var sig = args[2].toInt32();
                send("[SYSCALL-HOOK] syscall(kill, pid=" + targetPid + ", sig=" + sig + ") => neutered to getpid");
                args[0] = ptr(39); // SYS_getpid (harmless)
            } else if (num === 231) { // SYS_exit_group
                var code = args[1].toInt32();
                send("[SYSCALL-HOOK] syscall(exit_group, code=" + code + ") => neutered to getpid");
                args[0] = ptr(39); // SYS_getpid
            } else if (num === 60) { // SYS_exit
                send("[SYSCALL-HOOK] syscall(exit, code=" + args[1].toInt32() + ") => neutered");
                args[0] = ptr(39);
            } else if (num === 200) { // SYS_tkill
                var tid = args[1].toInt32();
                var sig = args[2].toInt32();
                if (sig === 6 || sig === 9) {
                    send("[SYSCALL-HOOK] syscall(tkill, tid=" + tid + ", sig=" + sig + ") => neutered");
                    args[0] = ptr(39);
                }
            } else if (num === 234) { // SYS_tgkill
                var tgid = args[1].toInt32();
                var tid = args[2].toInt32();
                var sig = args[3].toInt32();
                if (sig === 6 || sig === 9) {
                    send("[SYSCALL-HOOK] syscall(tgkill, " + tgid + "," + tid + "," + sig + ") => neutered");
                    args[0] = ptr(39);
                }
            }
        }
    });
    hookCount++;
    send("[HOOK] syscall() hooked - will neuter kill/exit_group");
} else {
    send("[HOOK] WARNING: syscall() not found!");
    missed.push("syscall");
}

// ── ANTI-KILL HOOKS (libc level) ──
replaceSafe("abort", "void", [], function() {
    send("[ANTI-KILL] abort() blocked");
    // Don't actually abort - just return (UB but prevents kill)
});

replaceSafe("exit", "void", ["int"], function(code) {
    send("[ANTI-KILL] exit(" + code + ") blocked");
});

replaceSafe("_exit", "void", ["int"], function(code) {
    send("[ANTI-KILL] _exit(" + code + ") blocked");
});

replaceSafe("kill", "int", ["int", "int"], function(pid, sig) {
    if (pid === _myPid || pid === 0 || sig === 9 || sig === 6) {
        send("[ANTI-KILL] kill(" + pid + ", " + sig + ") blocked");
        return 0;
    }
    return 0;
});

replaceSafe("raise", "int", ["int"], function(sig) {
    if (sig === 6 || sig === 9 || sig === 11) {
        send("[ANTI-KILL] raise(" + sig + ") blocked");
        return 0;
    }
    return 0;
});

replaceSafe("tgkill", "int", ["int", "int", "int"], function(tgid, tid, sig) {
    if (sig === 6 || sig === 9) {
        send("[ANTI-KILL] tgkill(" + tgid + "," + tid + "," + sig + ") blocked");
        return 0;
    }
    return 0;
});

// ── STEALTH HOOKS (minimal set) ──
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent"];
var PROC_PATHS = ["/proc/self/maps","/proc/self/smaps","/proc/self/status","/proc/net/tcp","/proc/net/tcp6","/proc/net/unix"];

function isSensitive(p) { if(!p) return false; for(var i=0;i<PROC_PATHS.length;i++) if(p.indexOf(PROC_PATHS[i])!==-1) return true; if(p.indexOf("/proc/"+_myPid+"/")!==-1) return true; return false; }
function hasFrida(s) { var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

var trackedFds = {};
hookSafe("openat", {
    onEnter: function(a) { this.path = safeRead(a[1]); },
    onLeave: function(r) { try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){} }
});

hookSafe("read", {
    onEnter: function(a) { this.fd=a[0].toInt32(); this.buf=a[1]; },
    onLeave: function(r) {
        try {
            var sz = r.toInt32();
            if (trackedFds[this.fd] && sz > 0) {
                var content = this.buf.readUtf8String(sz);
                if (content) {
                    var lines = content.split("\n");
                    var clean = [];
                    for (var i = 0; i < lines.length; i++) {
                        var line = lines[i];
                        if (hasFrida(line)) {
                            // Remove frida-port lines, rename others
                            if (line.indexOf(":7A69") !== -1 || line.indexOf(":7a69") !== -1 ||
                                line.indexOf(":69A2") !== -1 || line.indexOf(":69a2") !== -1) continue;
                            clean.push(line.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop").replace(/linjector/g,"xinjector"));
                        } else {
                            clean.push(line);
                        }
                    }
                    var result = clean.join("\n");
                    this.buf.writeUtf8String(result);
                    r.replace(ptr(result.length));
                }
            }
        } catch(e) {}
    }
});

hookSafe("close", { onEnter: function(a) { try { var fd=a[0].toInt32(); if(trackedFds[fd]) delete trackedFds[fd]; } catch(e){} } });

hookSafe("strstr", {
    onEnter: function(a) { this.needle = safeRead(a[1]); },
    onLeave: function(r) { try { if(this.needle && hasFrida(this.needle)) r.replace(ptr(0)); } catch(e){} }
});

hookSafe("strcmp", {
    onEnter: function(a) { this.s1=safeRead(a[0]); this.s2=safeRead(a[1]); },
    onLeave: function(r) { try { if((this.s1&&hasFrida(this.s1))||(this.s2&&hasFrida(this.s2))) r.replace(ptr(-1)); } catch(e){} }
});

hookSafe("access", {
    onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; },
    onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} }
});

hookSafe("stat", {
    onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; },
    onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} }
});

// dl_iterate_phdr hook - filter frida modules
var _fridaRanges = [];
Process.enumerateModules().forEach(function(m) {
    if (hasFrida(m.name) || hasFrida(m.path)) {
        _fridaRanges.push({base: m.base, end: m.base.add(m.size)});
    }
});

function isFromFrida(addr) {
    for (var i = 0; i < _fridaRanges.length; i++) {
        if (addr.compare(_fridaRanges[i].base) >= 0 && addr.compare(_fridaRanges[i].end) < 0) return true;
    }
    return false;
}

var dlIterAddr = findExport("dl_iterate_phdr");
if (dlIterAddr) {
    Interceptor.attach(dlIterAddr, {
        onEnter: function(args) {
            var callerAddr = this.returnAddress;
            if (isFromFrida(callerAddr)) return; // Don't interfere with Frida's own calls

            var origCb = args[0];
            var origData = args[1];
            this._ref = new NativeCallback(function(info, size, data) {
                try {
                    var namePtr = info.add(Process.pointerSize).readPointer();
                    var name = safeRead(namePtr);
                    if (name && hasFrida(name)) return 0; // skip frida modules
                } catch(e) {}
                return new NativeFunction(origCb, 'int', ['pointer','int','pointer'])(info, size, data);
            }, 'int', ['pointer','int','pointer']);
            args[0] = this._ref;
        }
    });
    hookCount++;
}

// Patch linker data
var _dlAddr = findExport("dl_iterate_phdr");
if (_dlAddr) {
    var _rawDl = new NativeFunction(_dlAddr, 'int', ['pointer','pointer']);
    var pc = 0;
    _rawDl(new NativeCallback(function(info,sz,d) {
        try {
            var np = info.add(Process.pointerSize).readPointer();
            var n = safeRead(np);
            if (n && hasFrida(n)) {
                var nn = n.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop");
                try { Memory.protect(np,nn.length+1,'rwx'); np.writeUtf8String(nn); pc++; } catch(e){}
            }
        } catch(e) {}
        return 0;
    },'int',['pointer','int','pointer']),ptr(0));
    send("[PATCH] Renamed " + pc + " linker modules");
}

send("[HOOKS] " + hookCount + " hooks active" + (missed.length ? " | MISSED: " + missed.join(", ") : ""));
send("[READY] syscall() hook + anti-kill + stealth ready. Resume to test.");

rpc.exports = {
    ping: function() { return "alive"; },
    init: function() {
        var mod = Process.findModuleByName("libg.so");
        if (mod) { send("[INIT] libg.so at " + mod.base); return mod.base.toString(); }
        send("[INIT] libg.so not loaded yet"); return null;
    },
    getbase: function() {
        var m = Process.findModuleByName("libg.so");
        return m ? m.base.toString() : null;
    }
};
"""

scr = sess.create_script(SYSCALL_HOOK_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(2)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING with syscall() hook ===")
device.resume(pid)

log("Monitoring (60s)...")
start = time.time()
for i in range(60):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s")
        break
    if e % 5 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive, RPC OK")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")
    if e == 10:
        try:
            base = scr.exports_sync.init()
            log(f"init() => {base}")
        except Exception as ex:
            log(f"init() failed: {ex}")

if alive:
    log("SURVIVED 60s! Game running with Frida!")
    try:
        base = scr.exports_sync.getbase()
        log(f"libg.so base: {base}")
    except:
        pass

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
