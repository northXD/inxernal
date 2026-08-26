"""
PLT Patch Strategy: Spawn game with Frida, hook dlopen, when libzyte.so loads
immediately patch its PLT stubs for detection functions. Detection never triggers,
so kill/exit/abort are never called (avoiding noreturn UB).

Key insight: kill/_exit are NOT in libzyte.so's PLT. Promon resolves them via dlsym.
But detection functions (strstr, open, fopen, etc.) ARE in the PLT.
If we break detection at PLT level, Promon never detects Frida.
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

PLT_PATCH_JS = r"""
'use strict';

var _myPid = Process.id;
send("[INIT] PID=" + _myPid + " Arch=" + Process.arch);

// ── PLT RVAs from offline ELF analysis of libzyte_x64.so ──
// These are virtual addresses (= offsets from module base since base_vaddr=0)
var PLT_PATCHES = {
    // Detection functions → xor eax,eax; ret (return 0/NULL)
    'strstr':           { rva: 0x2fd910, patch: [0x31, 0xC0, 0xC3] },          // return NULL
    'strcmp':            { rva: 0x2fd8c0, patch: [0xB8,0x01,0,0,0, 0xC3] },     // return 1 (not equal)
    'strncmp':          { rva: 0x2fd900, patch: [0xB8,0x01,0,0,0, 0xC3] },     // return 1
    'memcmp':           { rva: 0x2fdb90, patch: [0xB8,0x01,0,0,0, 0xC3] },     // return 1
    'open':             { rva: 0x2fe0c0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] }, // return -1
    'fopen':            { rva: 0x2fd870, patch: [0x31, 0xC0, 0xC3] },          // return NULL
    'fgets':            { rva: 0x2fd8a0, patch: [0x31, 0xC0, 0xC3] },          // return NULL
    'fread':            { rva: 0x2fdc80, patch: [0x31, 0xC0, 0xC3] },          // return 0
    'read':             { rva: 0x2fe0d0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] }, // return -1
    'dl_iterate_phdr':  { rva: 0x2fdfa0, patch: [0x31, 0xC0, 0xC3] },          // return 0
    'access':           { rva: 0x2fdfb0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] }, // return -1
    'stat':             { rva: 0x2fdd20, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] }, // return -1
    'popen':            { rva: 0x2fdd50, patch: [0x31, 0xC0, 0xC3] },          // return NULL
    'socket':           { rva: 0x2fdeb0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] }, // return -1
    'syscall':          { rva: 0x2fe180, patch: [0x31, 0xC0, 0xC3] },          // return 0

    // Safety net - abort IS in PLT
    'abort':            { rva: 0x2ff110, patch: [0xEB, 0xFE] },                // jmp $-2 (infinite loop)
};

var patchCount = 0;
var patchFails = [];

function patchLibzyte(base) {
    send("[PATCH] Patching libzyte.so PLT stubs at base " + base);

    var names = Object.keys(PLT_PATCHES);
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        var info = PLT_PATCHES[name];
        var addr = base.add(info.rva);
        var patchBytes = info.patch;

        try {
            // Read original bytes first
            var orig = addr.readByteArray(16);
            var origHex = Array.from(new Uint8Array(orig)).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('');

            // Make writable and write patch
            Memory.protect(addr, 16, 'rwx');
            addr.writeByteArray(patchBytes);

            // Verify
            var verify = addr.readByteArray(patchBytes.length);
            var verifyHex = Array.from(new Uint8Array(verify)).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('');
            var patchHex = patchBytes.map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('');

            if (verifyHex === patchHex) {
                patchCount++;
                send("[PATCH] " + name + " @ " + addr + " OK (was: " + origHex.substring(0,12) + "...)");
            } else {
                patchFails.push(name + "(verify)");
                send("[PATCH] " + name + " @ " + addr + " VERIFY FAIL: wrote " + patchHex + " read " + verifyHex);
            }
        } catch(e) {
            patchFails.push(name);
            send("[PATCH] " + name + " @ " + addr + " FAILED: " + e.message);
        }
    }

    send("[PATCH] Done: " + patchCount + "/" + names.length + " patched" +
         (patchFails.length ? " | FAILED: " + patchFails.join(", ") : ""));
}

// ── Hook dlopen to catch libzyte.so loading ──
var dlopen_names = ["android_dlopen_ext", "dlopen"];
var hooked_dlopen = false;

function findExport(name) {
    var libs = ["libdl.so", "libc.so", "linker64"];
    for (var i = 0; i < libs.length; i++) {
        try {
            var m = Process.getModuleByName(libs[i]);
            var a = m.getExportByName(name);
            if (a && !a.isNull()) return a;
        } catch(e) {}
    }
    return null;
}

var zytePatched = false;

for (var di = 0; di < dlopen_names.length; di++) {
    var dlopenAddr = findExport(dlopen_names[di]);
    if (dlopenAddr) {
        (function(dname) {
            Interceptor.attach(dlopenAddr, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        this.path = path;
                        if (path && (path.indexOf("libzyte") !== -1 || path.indexOf("zyte") !== -1)) {
                            send("[DLOPEN] Loading: " + path);
                        }
                    } catch(e) { this.path = null; }
                },
                onLeave: function(retval) {
                    if (zytePatched) return;
                    if (!this.path) return;

                    // Check if libzyte.so just loaded
                    if (this.path.indexOf("zyte") !== -1) {
                        send("[DLOPEN] libzyte.so loaded via " + dname + ": " + this.path);

                        // Find the x86_64 version
                        try {
                            var mods = Process.enumerateModules();
                            for (var m = 0; m < mods.length; m++) {
                                if (mods[m].name === "libzyte.so" &&
                                    mods[m].path.indexOf("x86_64") !== -1) {
                                    send("[DLOPEN] Found x86_64 libzyte.so: " + mods[m].base + " (" + mods[m].size + ")");
                                    patchLibzyte(mods[m].base);
                                    zytePatched = true;
                                    return;
                                }
                            }
                            // Maybe it's just "libzyte.so" without x86_64 in path
                            for (var m = 0; m < mods.length; m++) {
                                if (mods[m].name === "libzyte.so") {
                                    send("[DLOPEN] Found libzyte.so: " + mods[m].base + " path=" + mods[m].path);
                                    patchLibzyte(mods[m].base);
                                    zytePatched = true;
                                    return;
                                }
                            }
                            send("[DLOPEN] WARNING: libzyte.so not in module list after dlopen!");
                        } catch(e) {
                            send("[DLOPEN] ERROR scanning modules: " + e.message);
                        }
                    }

                    // Also watch for libg.so
                    if (this.path.indexOf("libg.so") !== -1) {
                        send("[DLOPEN] libg.so loaded: " + this.path);
                    }
                }
            });
            hooked_dlopen = true;
            send("[HOOK] " + dname + " hooked");
        })(dlopen_names[di]);
    }
}

if (!hooked_dlopen) {
    send("[HOOK] WARNING: No dlopen hooked! Falling back to polling...");
}

// ── Backup: Also hook kill (NOT noreturn, safe to replace) ──
var killAddr = findExport("kill");
if (killAddr) {
    Interceptor.replace(killAddr, new NativeCallback(function(pid, sig) {
        if (pid === _myPid || pid === 0 || sig === 9 || sig === 6) {
            send("[ANTI-KILL] kill(" + pid + ", " + sig + ") BLOCKED");
            return 0;
        }
        // Let non-self kills through
        var real_kill = new NativeFunction(killAddr, 'int', ['int', 'int']);
        return real_kill(pid, sig);
    }, 'int', ['int', 'int']));
    send("[HOOK] kill() replaced (safe - returns int)");
}

// Hook raise (NOT noreturn, returns int)
var raiseAddr = findExport("raise");
if (raiseAddr) {
    Interceptor.replace(raiseAddr, new NativeCallback(function(sig) {
        if (sig === 6 || sig === 9 || sig === 11) {
            send("[ANTI-KILL] raise(" + sig + ") BLOCKED");
            return 0;
        }
        return 0;
    }, 'int', ['int']));
    send("[HOOK] raise() replaced (safe - returns int)");
}

// Hook tgkill (NOT noreturn, returns int)
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) {
    Interceptor.replace(tgkillAddr, new NativeCallback(function(tgid, tid, sig) {
        if (sig === 6 || sig === 9) {
            send("[ANTI-KILL] tgkill(" + tgid + "," + tid + "," + sig + ") BLOCKED");
            return 0;
        }
        return 0;
    }, 'int', ['int', 'int', 'int']));
    send("[HOOK] tgkill() replaced (safe - returns int)");
}

// ── Minimal stealth hooks ──
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent"];
function hasFrida(s) { if(!s) return false; var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }
function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }

// Patch linker data (rename frida modules in linker's internal list)
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
    send("[PATCH] Renamed " + pc + " linker module names");
}

// Hook libc strstr for global stealth (not just libzyte)
var strstrAddr = findExport("strstr");
if (strstrAddr) {
    Interceptor.attach(strstrAddr, {
        onEnter: function(a) { this.needle = safeRead(a[1]); },
        onLeave: function(r) {
            try { if(this.needle && hasFrida(this.needle)) r.replace(ptr(0)); } catch(e){}
        }
    });
    send("[HOOK] strstr() stealth hook");
}

// Track sensitive file descriptors
var PROC_PATHS = ["/proc/self/maps","/proc/self/smaps","/proc/self/status","/proc/net/tcp","/proc/net/tcp6","/proc/net/unix"];
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
        onLeave: function(r) {
            try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){}
        }
    });
}

var readAddr = findExport("read");
if (readAddr) {
    Interceptor.attach(readAddr, {
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
                                if (line.indexOf(":7A69") !== -1 || line.indexOf(":7a69") !== -1 ||
                                    line.indexOf(":69A2") !== -1 || line.indexOf(":69a2") !== -1) continue;
                                clean.push(line.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth")
                                              .replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop")
                                              .replace(/linjector/g,"xinjector"));
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
}

var closeAddr = findExport("close");
if (closeAddr) {
    Interceptor.attach(closeAddr, {
        onEnter: function(a) { try { var fd=a[0].toInt32(); if(trackedFds[fd]) delete trackedFds[fd]; } catch(e){} }
    });
}

// Hook access/stat for stealth
var accessAddr = findExport("access");
if (accessAddr) {
    Interceptor.attach(accessAddr, {
        onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; },
        onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} }
    });
}

send("[READY] PLT patcher + anti-kill + stealth ready. Resuming...");

// Polling fallback: check every 500ms if libzyte.so appeared
var pollInterval = setInterval(function() {
    if (zytePatched) {
        clearInterval(pollInterval);
        return;
    }
    try {
        var mod = Process.findModuleByName("libzyte.so");
        if (mod) {
            send("[POLL] Found libzyte.so via polling: " + mod.base + " path=" + mod.path);
            // Check if it's x86_64 (the one actually executing)
            if (mod.path.indexOf("x86_64") !== -1 || mod.path.indexOf("x86") !== -1) {
                patchLibzyte(mod.base);
                zytePatched = true;
                clearInterval(pollInterval);
            } else {
                // Find x86_64 version
                var mods = Process.enumerateModules();
                for (var m = 0; m < mods.length; m++) {
                    if (mods[m].name === "libzyte.so" && mods[m].path.indexOf("x86_64") !== -1) {
                        patchLibzyte(mods[m].base);
                        zytePatched = true;
                        clearInterval(pollInterval);
                        return;
                    }
                }
                // Just patch whatever we found
                patchLibzyte(mod.base);
                zytePatched = true;
                clearInterval(pollInterval);
            }
        }
    } catch(e) {}
}, 500);

rpc.exports = {
    ping: function() { return { alive: true, patched: zytePatched, patchCount: patchCount }; },
    getbase: function() {
        var m = Process.findModuleByName("libg.so");
        return m ? m.base.toString() : null;
    }
};
"""

scr = sess.create_script(PLT_PATCH_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

if not alive:
    log("DEAD before resume!")
    sys.exit(1)

log("=== RESUMING ===")
device.resume(pid)

log("Monitoring (60s)...")
start = time.time()
for i in range(60):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s after resume")
        break
    if e % 5 == 0:
        try:
            r = scr.exports_sync.ping()
            log(f"+{e}s alive | patched={r['patched']} patchCount={r['patchCount']}")
        except Exception as ex:
            log(f"+{e}s RPC failed: {ex}")
    if e == 15:
        try:
            base = scr.exports_sync.getbase()
            log(f"libg.so base: {base}")
        except:
            pass

if alive:
    log("=== SURVIVED 60s! ===")
    try:
        info = scr.exports_sync.ping()
        log(f"Final: {info}")
        base = scr.exports_sync.getbase()
        log(f"libg.so base: {base}")
    except:
        pass

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
