"""
PLT Patch v3: MINIMAL PLT patching - only dl_iterate_phdr + abort.
All string/file detection evasion via selective global Interceptor hooks.
Goal: keep Promon's legitimate operations intact so libg.so can load.
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

adb("shell", "su -c 'killall system_service 2>/dev/null'")
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

PLT_PATCH3_JS = r"""
'use strict';

var _myPid = Process.id;
send("[INIT] PID=" + _myPid);

// ── MINIMAL PLT patches: ONLY dl_iterate_phdr + abort ──
var PLT_PATCHES = {
    'dl_iterate_phdr':  { rva: 0x2fdfa0, patch: [0x31, 0xC0, 0xC3] },  // return 0
    'abort':            { rva: 0x2ff110, patch: [0xEB, 0xFE] },          // infinite loop
};

var patchCount = 0;

function patchLibzyte(base) {
    send("[PATCH] Patching libzyte.so at " + base);
    var names = Object.keys(PLT_PATCHES);
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        var info = PLT_PATCHES[name];
        var addr = base.add(info.rva);
        try {
            Memory.protect(addr, 16, 'rwx');
            addr.writeByteArray(info.patch);
            patchCount++;
            send("[PATCH] " + name + " @ " + addr + " OK");
        } catch(e) {
            send("[PATCH] " + name + " FAILED: " + e.message);
        }
    }
    send("[PATCH] " + patchCount + "/" + names.length + " done");
}

function findExport(name) {
    var libs = ["libdl.so","libc.so","linker64"];
    for (var i=0;i<libs.length;i++) {
        try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){}
    }
    return null;
}
function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }

var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent","frida-server"];
function hasFrida(s) { if(!s) return false; var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

// ── dlopen hook ──
var zytePatched = false;
var dlopenNames = ["android_dlopen_ext","dlopen"];
for (var di = 0; di < dlopenNames.length; di++) {
    var da = findExport(dlopenNames[di]);
    if (da) {
        (function(dname) {
            Interceptor.attach(da, {
                onEnter: function(args) { try { this.path = args[0].readCString(); } catch(e) { this.path=null; } },
                onLeave: function(retval) {
                    if (!this.path) return;
                    if (!zytePatched && this.path.indexOf("zyte") !== -1) {
                        send("[DLOPEN] libzyte loaded: " + this.path);
                        try {
                            var mod = Process.findModuleByName("libzyte.so");
                            if (mod) { patchLibzyte(mod.base); zytePatched = true; }
                        } catch(e) { send("[DLOPEN] patch error: " + e.message); }
                    }
                    if (this.path.indexOf("libg.so") !== -1) {
                        send("[DLOPEN] *** libg.so LOADED: " + this.path + " ***");
                    }
                }
            });
            send("[HOOK] " + dname);
        })(dlopenNames[di]);
    }
}

// ── Anti-kill (safe functions only) ──
var killAddr = findExport("kill");
if (killAddr) {
    Interceptor.replace(killAddr, new NativeCallback(function(p, s) {
        if (p === _myPid || p === 0 || s === 9 || s === 6) {
            send("[KILL] kill(" + p + "," + s + ") BLOCKED");
            return 0;
        }
        return new NativeFunction(killAddr, 'int', ['int','int'])(p, s);
    }, 'int', ['int','int']));
}
var raiseAddr = findExport("raise");
if (raiseAddr) {
    Interceptor.replace(raiseAddr, new NativeCallback(function(s) {
        if (s === 6 || s === 9 || s === 11) { send("[KILL] raise(" + s + ") BLOCKED"); return 0; }
        return 0;
    }, 'int', ['int']));
}
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) {
    Interceptor.replace(tgkillAddr, new NativeCallback(function(a,b,s) {
        if (s === 6 || s === 9) { send("[KILL] tgkill(" + a + "," + b + "," + s + ") BLOCKED"); return 0; }
        return 0;
    }, 'int', ['int','int','int']));
}
send("[HOOK] anti-kill (kill/raise/tgkill)");

// ── Linker name patching ──
var _dlAddr = findExport("dl_iterate_phdr");
if (_dlAddr) {
    var _rawDl = new NativeFunction(_dlAddr, 'int', ['pointer','pointer']);
    var pc = 0;
    _rawDl(new NativeCallback(function(info,sz,d) {
        try {
            var np = info.add(Process.pointerSize).readPointer();
            var n = safeRead(np);
            if (n && hasFrida(n)) {
                var nn = n.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth")
                          .replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop");
                try { Memory.protect(np,nn.length+1,'rwx'); np.writeUtf8String(nn); pc++; } catch(e){}
            }
        } catch(e) {}
        return 0;
    },'int',['pointer','int','pointer']),ptr(0));
    send("[PATCH] " + pc + " linker names");
}

// ── COMPREHENSIVE stealth hooks (selective, on libc) ──

// 1. strstr - return NULL only for frida needles
var strstrAddr = findExport("strstr");
if (strstrAddr) {
    Interceptor.attach(strstrAddr, {
        onEnter: function(a) { this.needle = safeRead(a[1]); },
        onLeave: function(r) { try { if(this.needle && hasFrida(this.needle)) { r.replace(ptr(0)); } } catch(e){} }
    });
    send("[HOOK] strstr (selective)");
}

// 2. strcmp - return -1 only for frida strings
var strcmpAddr = findExport("strcmp");
if (strcmpAddr) {
    Interceptor.attach(strcmpAddr, {
        onEnter: function(a) { this.s1=safeRead(a[0]); this.s2=safeRead(a[1]); },
        onLeave: function(r) { try { if((this.s1&&hasFrida(this.s1))||(this.s2&&hasFrida(this.s2))) r.replace(ptr(-1)); } catch(e){} }
    });
    send("[HOOK] strcmp (selective)");
}

// 3. Track sensitive FDs
var PROC_PATHS = ["/proc/self/maps","/proc/self/smaps","/proc/self/status",
                  "/proc/net/tcp","/proc/net/tcp6","/proc/net/unix"];
function isSensitive(p) {
    if(!p) return false;
    for(var i=0;i<PROC_PATHS.length;i++) if(p.indexOf(PROC_PATHS[i])!==-1) return true;
    if(p.indexOf("/proc/"+_myPid+"/")!==-1) return true;
    return false;
}

var trackedFds = {};
var openatAddr = findExport("openat");
if (openatAddr) {
    Interceptor.attach(openatAddr, {
        onEnter: function(a) { this.path = safeRead(a[1]); },
        onLeave: function(r) { try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){} }
    });
    send("[HOOK] openat (FD tracking)");
}

// 4. Filter frida from /proc reads
var readAddr = findExport("read");
if (readAddr) {
    Interceptor.attach(readAddr, {
        onEnter: function(a) { this.fd=a[0].toInt32(); this.buf=a[1]; },
        onLeave: function(r) {
            try {
                var sz = r.toInt32();
                if (trackedFds[this.fd] && sz > 0) {
                    var content = this.buf.readUtf8String(sz);
                    if (content && hasFrida(content)) {
                        var lines = content.split("\n");
                        var clean = [];
                        for (var li = 0; li < lines.length; li++) {
                            if (hasFrida(lines[li])) {
                                if (lines[li].indexOf(":7A69")!==-1 || lines[li].indexOf(":7a69")!==-1 ||
                                    lines[li].indexOf(":69A2")!==-1 || lines[li].indexOf(":69a2")!==-1) continue;
                                clean.push(lines[li].replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth")
                                    .replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop")
                                    .replace(/linjector/g,"xinjector"));
                            } else {
                                clean.push(lines[li]);
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
    send("[HOOK] read (maps filter)");
}

var closeAddr = findExport("close");
if (closeAddr) {
    Interceptor.attach(closeAddr, {
        onEnter: function(a) { try { var fd=a[0].toInt32(); if(trackedFds[fd]) delete trackedFds[fd]; } catch(e){} }
    });
}

// 5. access/stat - block frida paths
var accessAddr = findExport("access");
if (accessAddr) {
    Interceptor.attach(accessAddr, {
        onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; },
        onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} }
    });
}
var statAddr = findExport("stat");
if (statAddr) {
    Interceptor.attach(statAddr, {
        onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; },
        onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} }
    });
}

// 6. dl_iterate_phdr - filter frida modules (for non-libzyte callers)
var dlIterAddr = findExport("dl_iterate_phdr");
if (dlIterAddr) {
    var _fridaRanges = [];
    Process.enumerateModules().forEach(function(m) {
        if (hasFrida(m.name) || hasFrida(m.path)) {
            _fridaRanges.push({base: m.base, end: m.base.add(m.size)});
        }
    });
    function isFromFrida(addr) {
        for (var i=0;i<_fridaRanges.length;i++) {
            if (addr.compare(_fridaRanges[i].base)>=0 && addr.compare(_fridaRanges[i].end)<0) return true;
        }
        return false;
    }
    Interceptor.attach(dlIterAddr, {
        onEnter: function(args) {
            if (isFromFrida(this.returnAddress)) return;
            var origCb = args[0];
            this._ref = new NativeCallback(function(info, size, data) {
                try {
                    var namePtr = info.add(Process.pointerSize).readPointer();
                    var name = safeRead(namePtr);
                    if (name && hasFrida(name)) return 0;
                } catch(e) {}
                return new NativeFunction(origCb, 'int', ['pointer','int','pointer'])(info, size, data);
            }, 'int', ['pointer','int','pointer']);
            args[0] = this._ref;
        }
    });
    send("[HOOK] dl_iterate_phdr (selective filter)");
}

// 7. Thread name stealth
var prctlAddr = findExport("prctl");
if (prctlAddr) {
    Interceptor.attach(prctlAddr, {
        onEnter: function(a) {
            var op = a[0].toInt32();
            if (op === 15) { // PR_SET_NAME
                this.namePtr = a[1];
            } else if (op === 16) { // PR_GET_NAME
                this.getName = a[1];
            }
        },
        onLeave: function(r) {
            if (this.getName) {
                try {
                    var name = safeRead(this.getName);
                    if (name && hasFrida(name)) {
                        var clean = name.replace(/frida/g,"nxrth").replace(/gmain/g,"gloop")
                                        .replace(/gum-js-loop/g,"app-js");
                        this.getName.writeUtf8String(clean);
                    }
                } catch(e) {}
            }
        }
    });
    send("[HOOK] prctl (thread name stealth)");
}

send("[READY] Minimal PLT + comprehensive stealth hooks. Resuming...");

// Poll fallback
var pollInt = setInterval(function() {
    if (zytePatched) { clearInterval(pollInt); return; }
    try {
        var mod = Process.findModuleByName("libzyte.so");
        if (mod) {
            send("[POLL] libzyte.so found: " + mod.base);
            patchLibzyte(mod.base);
            zytePatched = true;
            clearInterval(pollInt);
        }
    } catch(e) {}
}, 200);

rpc.exports = {
    ping: function() { return { alive: true, patched: zytePatched, patches: patchCount }; },
    mods: function() {
        var interesting = [];
        Process.enumerateModules().forEach(function(m) {
            if (m.name === "libg.so" || m.name.indexOf("supercell") !== -1 ||
                m.name.indexOf("hayday") !== -1 || m.name.indexOf("zyte") !== -1 ||
                m.name.indexOf("titan") !== -1) {
                interesting.push(m.name + "@" + m.base);
            }
        });
        return interesting;
    },
    getbase: function() {
        var m = Process.findModuleByName("libg.so");
        return m ? m.base.toString() : null;
    }
};
"""

scr = sess.create_script(PLT_PATCH3_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING ===")
device.resume(pid)

log("Monitoring (120s)...")
start = time.time()
for i in range(120):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s")
        break
    if e % 10 == 0:
        try:
            r = scr.exports_sync.ping()
            mods = scr.exports_sync.mods()
            log(f"+{e}s alive | patched={r['patched']} | mods={mods}")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")

if alive:
    log("=== SURVIVED 120s! ===")
    try:
        info = scr.exports_sync.ping()
        mods = scr.exports_sync.mods()
        base = scr.exports_sync.getbase()
        log(f"Final: {info} | mods={mods} | libg={base}")
    except:
        pass

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
