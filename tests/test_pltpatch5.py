"""
PLT Patch v5: Full PLT patching (like v1) + 300s wait + ADB maps check.
The aggressive approach keeps the process alive indefinitely.
Question: does libg.so ever load with more time?
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

PLT_FULL_JS = r"""
'use strict';

var _myPid = Process.id;
send("[INIT] PID=" + _myPid);

// FULL PLT patches - disable ALL detection functions in libzyte.so
var PLT_PATCHES = {
    'strstr':           { rva: 0x2fd910, patch: [0x31, 0xC0, 0xC3] },
    'strcmp':            { rva: 0x2fd8c0, patch: [0xB8,0x01,0,0,0, 0xC3] },
    'strncmp':          { rva: 0x2fd900, patch: [0xB8,0x01,0,0,0, 0xC3] },
    'memcmp':           { rva: 0x2fdb90, patch: [0xB8,0x01,0,0,0, 0xC3] },
    'open':             { rva: 0x2fe0c0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] },
    'fopen':            { rva: 0x2fd870, patch: [0x31, 0xC0, 0xC3] },
    'fgets':            { rva: 0x2fd8a0, patch: [0x31, 0xC0, 0xC3] },
    'fread':            { rva: 0x2fdc80, patch: [0x31, 0xC0, 0xC3] },
    'read':             { rva: 0x2fe0d0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] },
    'dl_iterate_phdr':  { rva: 0x2fdfa0, patch: [0x31, 0xC0, 0xC3] },
    'access':           { rva: 0x2fdfb0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] },
    'stat':             { rva: 0x2fdd20, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] },
    'popen':            { rva: 0x2fdd50, patch: [0x31, 0xC0, 0xC3] },
    'socket':           { rva: 0x2fdeb0, patch: [0xB8,0xFF,0xFF,0xFF,0xFF, 0xC3] },
    'syscall':          { rva: 0x2fe180, patch: [0x31, 0xC0, 0xC3] },
    'abort':            { rva: 0x2ff110, patch: [0xEB, 0xFE] },
};

var patchCount = 0;
function patchLibzyte(base) {
    send("[PATCH] Full PLT patch at " + base);
    var names = Object.keys(PLT_PATCHES);
    for (var i = 0; i < names.length; i++) {
        var info = PLT_PATCHES[names[i]];
        var addr = base.add(info.rva);
        try {
            Memory.protect(addr, 16, 'rwx');
            addr.writeByteArray(info.patch);
            patchCount++;
        } catch(e) { send("[PATCH] " + names[i] + " FAIL"); }
    }
    send("[PATCH] " + patchCount + "/" + names.length + " done");
}

function findExport(name) {
    var libs = ["libdl.so","libc.so","linker64"];
    for (var i=0;i<libs.length;i++) { try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){} }
    return null;
}
function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent","frida-server"];
function hasFrida(s) { if(!s) return false; var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

// dlopen hook
var zytePatched = false;
var libgLoaded = false;
var da = findExport("android_dlopen_ext");
if (da) {
    Interceptor.attach(da, {
        onEnter: function(args) { try { this.path = args[0].readCString(); } catch(e) { this.path=null; } },
        onLeave: function(retval) {
            if (!this.path) return;
            if (!zytePatched && this.path.indexOf("zyte") !== -1) {
                send("[DLOPEN] " + this.path);
                try { var mod = Process.findModuleByName("libzyte.so"); if (mod) { patchLibzyte(mod.base); zytePatched = true; } } catch(e) {}
            }
            if (this.path.indexOf("libg.so") !== -1) {
                send("[DLOPEN] *** libg.so LOADED! ***");
                libgLoaded = true;
            }
        }
    });
}

// Anti-kill (safe, non-noreturn)
var killAddr = findExport("kill");
if (killAddr) { Interceptor.replace(killAddr, new NativeCallback(function(p,s) { if(p===_myPid||p===0||s===9||s===6){send("[K] kill("+p+","+s+")");return 0;} return 0; }, 'int', ['int','int'])); }
var raiseAddr = findExport("raise");
if (raiseAddr) { Interceptor.replace(raiseAddr, new NativeCallback(function(s) { if(s===6||s===9||s===11){send("[K] raise("+s+")");return 0;} return 0; }, 'int', ['int'])); }
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) { Interceptor.replace(tgkillAddr, new NativeCallback(function(a,b,s) { if(s===6||s===9){send("[K] tgkill("+a+","+b+","+s+")");return 0;} return 0; }, 'int', ['int','int','int'])); }

// Linker rename
var _dlAddr = findExport("dl_iterate_phdr");
if (_dlAddr) {
    var _rawDl = new NativeFunction(_dlAddr, 'int', ['pointer','pointer']);
    _rawDl(new NativeCallback(function(info,sz,d) {
        try { var np = info.add(Process.pointerSize).readPointer(); var n = safeRead(np);
            if (n && hasFrida(n)) { var nn = n.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop");
                try { Memory.protect(np,nn.length+1,'rwx'); np.writeUtf8String(nn); } catch(e){} }
        } catch(e) {} return 0;
    },'int',['pointer','int','pointer']),ptr(0));
}

send("[READY]");

// Poll
var pollInt = setInterval(function() {
    if (zytePatched) { clearInterval(pollInt); return; }
    try { var mod = Process.findModuleByName("libzyte.so"); if (mod) { patchLibzyte(mod.base); zytePatched = true; clearInterval(pollInt); } } catch(e) {}
}, 200);

rpc.exports = {
    ping: function() { return { alive: true, patched: zytePatched, patches: patchCount, libg: libgLoaded }; },
    findlibg: function() {
        var m = Process.findModuleByName("libg.so");
        if (m) return { base: m.base.toString(), size: m.size, path: m.path };
        return null;
    },
    modcount: function() { return Process.enumerateModules().length; }
};
"""

scr = sess.create_script(PLT_FULL_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

log("=== RESUMING ===")
device.resume(pid)

log("Monitoring (300s)...")
start = time.time()
libg_found = False
for i in range(300):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"DEAD at +{e}s")
        break

    if e % 30 == 0:
        try:
            r = scr.exports_sync.ping()
            mc = scr.exports_sync.modcount()
            log(f"+{e}s alive | patches={r['patches']} mods={mc} libg_dlopen={r['libg']}")
        except Exception as ex:
            log(f"+{e}s RPC: {ex}")

    if e % 30 == 0 and not libg_found:
        try:
            maps = adb("shell", f"su -c 'cat /proc/{pid}/maps 2>/dev/null | grep libg.so | head -1'")
            if "libg.so" in maps.stdout:
                log(f"+{e}s *** libg.so in maps! ***")
                log(f"  {maps.stdout.strip()[:200]}")
                libg_found = True
        except:
            pass

if alive and not libg_found:
    log("300s: libg.so still not loaded")
elif libg_found:
    log("libg.so loaded!")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
