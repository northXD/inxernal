"""
PLT Patch v4: Same as v3 (minimal PLT) but wait longer (240s)
and check libg.so via BOTH Frida and ADB /proc/pid/maps.
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

# Same JS as v3 but with extra module checking
PLT_PATCH4_JS = r"""
'use strict';

var _myPid = Process.id;
send("[INIT] PID=" + _myPid);

var PLT_PATCHES = {
    'dl_iterate_phdr':  { rva: 0x2fdfa0, patch: [0x31, 0xC0, 0xC3] },
    'abort':            { rva: 0x2ff110, patch: [0xEB, 0xFE] },
};

var patchCount = 0;
function patchLibzyte(base) {
    send("[PATCH] Patching at " + base);
    var names = Object.keys(PLT_PATCHES);
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        var info = PLT_PATCHES[name];
        var addr = base.add(info.rva);
        try {
            Memory.protect(addr, 16, 'rwx');
            addr.writeByteArray(info.patch);
            patchCount++;
            send("[PATCH] " + name + " OK");
        } catch(e) { send("[PATCH] " + name + " FAIL: " + e.message); }
    }
    send("[PATCH] " + patchCount + "/" + names.length);
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

// dlopen hook
var zytePatched = false;
var libgLoaded = false;
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
                        send("[DLOPEN] libzyte: " + this.path);
                        try {
                            var mod = Process.findModuleByName("libzyte.so");
                            if (mod) { patchLibzyte(mod.base); zytePatched = true; }
                        } catch(e) {}
                    }
                    if (this.path.indexOf("libg.so") !== -1) {
                        send("[DLOPEN] *** libg.so: " + this.path + " ***");
                        libgLoaded = true;
                    }
                }
            });
        })(dlopenNames[di]);
    }
}

// Anti-kill
var killAddr = findExport("kill");
if (killAddr) {
    Interceptor.replace(killAddr, new NativeCallback(function(p, s) {
        if (p === _myPid || p === 0 || s === 9 || s === 6) { send("[KILL] kill(" + p + "," + s + ")"); return 0; }
        return new NativeFunction(killAddr, 'int', ['int','int'])(p, s);
    }, 'int', ['int','int']));
}
var raiseAddr = findExport("raise");
if (raiseAddr) { Interceptor.replace(raiseAddr, new NativeCallback(function(s) { if(s===6||s===9||s===11){send("[KILL] raise("+s+")");return 0;} return 0; }, 'int', ['int'])); }
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) { Interceptor.replace(tgkillAddr, new NativeCallback(function(a,b,s) { if(s===6||s===9){send("[KILL] tgkill("+a+","+b+","+s+")");return 0;} return 0; }, 'int', ['int','int','int'])); }

// Linker rename
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

// Stealth hooks
var strstrAddr = findExport("strstr");
if (strstrAddr) { Interceptor.attach(strstrAddr, { onEnter: function(a) { this.needle = safeRead(a[1]); }, onLeave: function(r) { try { if(this.needle && hasFrida(this.needle)) r.replace(ptr(0)); } catch(e){} } }); }
var strcmpAddr = findExport("strcmp");
if (strcmpAddr) { Interceptor.attach(strcmpAddr, { onEnter: function(a) { this.s1=safeRead(a[0]); this.s2=safeRead(a[1]); }, onLeave: function(r) { try { if((this.s1&&hasFrida(this.s1))||(this.s2&&hasFrida(this.s2))) r.replace(ptr(-1)); } catch(e){} } }); }

var PROC_PATHS = ["/proc/self/maps","/proc/self/smaps","/proc/self/status","/proc/net/tcp","/proc/net/tcp6","/proc/net/unix"];
function isSensitive(p) { if(!p) return false; for(var i=0;i<PROC_PATHS.length;i++) if(p.indexOf(PROC_PATHS[i])!==-1) return true; if(p.indexOf("/proc/"+_myPid+"/")!==-1) return true; return false; }

var trackedFds = {};
var openatAddr = findExport("openat");
if (openatAddr) { Interceptor.attach(openatAddr, { onEnter: function(a) { this.path = safeRead(a[1]); }, onLeave: function(r) { try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){} } }); }

// Also hook open() for FD tracking
var openAddr = findExport("open");
if (openAddr) { Interceptor.attach(openAddr, { onEnter: function(a) { this.path = safeRead(a[0]); }, onLeave: function(r) { try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){} } }); }

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
                                    .replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop").replace(/linjector/g,"xinjector"));
                            } else { clean.push(lines[li]); }
                        }
                        var result = clean.join("\n");
                        this.buf.writeUtf8String(result);
                        r.replace(ptr(result.length));
                    }
                }
            } catch(e) {}
        }
    });
}

var closeAddr = findExport("close");
if (closeAddr) { Interceptor.attach(closeAddr, { onEnter: function(a) { try { var fd=a[0].toInt32(); if(trackedFds[fd]) delete trackedFds[fd]; } catch(e){} } }); }
var accessAddr = findExport("access");
if (accessAddr) { Interceptor.attach(accessAddr, { onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; }, onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} } }); }

// dl_iterate_phdr filter for global callers
var dlIterAddr = findExport("dl_iterate_phdr");
if (dlIterAddr) {
    var _fridaRanges = [];
    Process.enumerateModules().forEach(function(m) {
        if (hasFrida(m.name) || hasFrida(m.path)) _fridaRanges.push({base: m.base, end: m.base.add(m.size)});
    });
    function isFromFrida(addr) { for (var i=0;i<_fridaRanges.length;i++) { if (addr.compare(_fridaRanges[i].base)>=0 && addr.compare(_fridaRanges[i].end)<0) return true; } return false; }
    Interceptor.attach(dlIterAddr, {
        onEnter: function(args) {
            if (isFromFrida(this.returnAddress)) return;
            var origCb = args[0];
            this._ref = new NativeCallback(function(info, size, data) {
                try { var np = info.add(Process.pointerSize).readPointer(); var name = safeRead(np); if (name && hasFrida(name)) return 0; } catch(e) {}
                return new NativeFunction(origCb, 'int', ['pointer','int','pointer'])(info, size, data);
            }, 'int', ['pointer','int','pointer']);
            args[0] = this._ref;
        }
    });
}

// prctl thread name stealth
var prctlAddr = findExport("prctl");
if (prctlAddr) {
    Interceptor.attach(prctlAddr, {
        onEnter: function(a) {
            var op = a[0].toInt32();
            if (op === 16) this.getName = a[1]; // PR_GET_NAME
        },
        onLeave: function(r) {
            if (this.getName) {
                try {
                    var name = safeRead(this.getName);
                    if (name && hasFrida(name)) {
                        this.getName.writeUtf8String(name.replace(/frida/g,"nxrth").replace(/gmain/g,"gloop").replace(/gum-js-loop/g,"app-js"));
                    }
                } catch(e) {}
            }
        }
    });
}

send("[READY] All hooks set.");

// Polling for libzyte.so
var pollInt = setInterval(function() {
    if (zytePatched) { clearInterval(pollInt); return; }
    try {
        var mod = Process.findModuleByName("libzyte.so");
        if (mod) { patchLibzyte(mod.base); zytePatched = true; clearInterval(pollInt); }
    } catch(e) {}
}, 200);

rpc.exports = {
    ping: function() { return { alive: true, patched: zytePatched, patches: patchCount, libg: libgLoaded }; },
    findlibg: function() {
        var m = Process.findModuleByName("libg.so");
        if (m) return { base: m.base.toString(), size: m.size, path: m.path };
        // Try enumerating all modules for anything game-related
        var all = Process.enumerateModules();
        var found = [];
        for (var i = 0; i < all.length; i++) {
            if (all[i].name.indexOf("libg") !== -1 || all[i].path.indexOf("hayday") !== -1 ||
                all[i].name.indexOf("titan") !== -1 || all[i].name.indexOf("supercell") !== -1) {
                found.push({name: all[i].name, base: all[i].base.toString(), path: all[i].path});
            }
        }
        return found.length > 0 ? found : null;
    }
};
"""

scr = sess.create_script(PLT_PATCH4_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING ===")
device.resume(pid)

log("Monitoring (240s)...")
start = time.time()
libg_found = False
for i in range(240):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s")
        break

    if e % 15 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive | patched={r['patched']} libg_dlopen={r['libg']}")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")

    # Check via ADB every 20s
    if e % 20 == 0 and not libg_found:
        try:
            maps = adb("shell", f"su -c 'cat /proc/{pid}/maps 2>/dev/null | grep libg.so | head -2'")
            if "libg.so" in maps.stdout:
                log(f"+{e}s *** libg.so found in /proc maps! ***")
                log(f"  {maps.stdout.strip()[:200]}")
                libg_found = True
                # Also check via Frida
                try:
                    fg = scr.exports_sync.findlibg()
                    log(f"  Frida findlibg: {fg}")
                except:
                    pass
        except:
            pass

    # If libg found, get more info and exit early
    if libg_found and e % 5 == 0:
        try:
            fg = scr.exports_sync.findlibg()
            if fg:
                log(f"+{e}s Frida sees libg: {fg}")
                break
        except:
            pass

if alive:
    log("=== Test complete ===")
    try:
        info = scr.exports_sync.ping()
        fg = scr.exports_sync.findlibg()
        log(f"Final: {info}")
        log(f"libg: {fg}")
    except:
        pass

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
