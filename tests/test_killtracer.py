"""
Kill-tracer approach:
1. Game already running (manually started)
2. Kill Promon's anti-debug tracer (PID that holds ptrace)
3. Immediately attach Frida
4. From inside, patch libzyte.so PLT stubs
5. Load stealth hooks

Race: must attach before Promon detects tracer death.
"""
import frida, subprocess, time, sys, threading

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

# Find game PID and tracer PID
game_pid_str = adb("shell", f"pidof {PKG}").stdout.strip()
if not game_pid_str:
    log("Game not running! Start it manually first.")
    sys.exit(1)

game_pid = int(game_pid_str)
log(f"Game PID: {game_pid}")

# Find tracer PID
status = adb("shell", f"su -c 'cat /proc/{game_pid}/status'").stdout
tracer_pid = None
for line in status.split('\n'):
    if line.startswith('TracerPid:'):
        tp = int(line.split(':')[1].strip())
        if tp > 0:
            tracer_pid = tp
        break

if tracer_pid:
    log(f"Tracer PID: {tracer_pid}")
    # Check what it is
    tracer_info = adb("shell", f"su -c 'cat /proc/{tracer_pid}/cmdline'").stdout
    log(f"Tracer cmdline: {tracer_info}")
else:
    log("No tracer attached")

# Make sure Frida server is running
adb("shell", "su -c 'killall system_service 2>/dev/null'")
time.sleep(0.5)
subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
log(f"Frida server ready ({len(device.enumerate_processes())} procs)")

# JS payload with PLT patches + stealth
INJECT_JS = r"""
'use strict';

var _myPid = Process.id;
send("[INIT] PID=" + _myPid + " Arch=" + Process.arch);

// Find libzyte.so
var zyte = Process.findModuleByName("libzyte.so");
if (!zyte) {
    // Try to find it in all modules
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name === "libzyte.so" && mods[i].path.indexOf("x86_64") !== -1) {
            zyte = mods[i];
            break;
        }
    }
    if (!zyte) {
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name === "libzyte.so") {
                zyte = mods[i];
                break;
            }
        }
    }
}

if (zyte) {
    send("[ZYTE] Found: " + zyte.base + " size=" + zyte.size + " path=" + zyte.path);

    // PLT patches
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

    var ok = 0, fail = 0;
    var names = Object.keys(PLT_PATCHES);
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        var info = PLT_PATCHES[name];
        var addr = zyte.base.add(info.rva);
        try {
            Memory.protect(addr, 16, 'rwx');
            addr.writeByteArray(info.patch);
            ok++;
        } catch(e) {
            fail++;
            send("[PATCH] " + name + " FAIL: " + e.message);
        }
    }
    send("[PATCH] " + ok + "/" + names.length + " patched (" + fail + " failed)");
} else {
    send("[ZYTE] NOT FOUND!");
}

// Find libg.so
var libg = Process.findModuleByName("libg.so");
if (libg) {
    send("[LIBG] Found: " + libg.base + " size=" + libg.size);
} else {
    send("[LIBG] Not found (will scan later)");
}

function findExport(name) {
    var libs = ["libdl.so","libc.so","linker64"];
    for (var i=0;i<libs.length;i++) { try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){} }
    return null;
}
function safeRead(p) { try { return p && !p.isNull() ? p.readCString() : null; } catch(e) { return null; } }
var FRIDA_SIGS = ["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent","frida-server"];
function hasFrida(s) { if(!s) return false; var l=s.toLowerCase(); for(var i=0;i<FRIDA_SIGS.length;i++) if(l.indexOf(FRIDA_SIGS[i])!==-1) return true; return false; }

// Anti-kill
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
var openAddr = findExport("open");
if (openAddr) { Interceptor.attach(openAddr, { onEnter: function(a) { this.path = safeRead(a[0]); }, onLeave: function(r) { try { if(isSensitive(this.path)) trackedFds[r.toInt32()]=this.path; } catch(e){} } }); }
var readAddr = findExport("read");
if (readAddr) {
    Interceptor.attach(readAddr, {
        onEnter: function(a) { this.fd=a[0].toInt32(); this.buf=a[1]; },
        onLeave: function(r) {
            try { var sz = r.toInt32(); if (trackedFds[this.fd] && sz > 0) {
                var content = this.buf.readUtf8String(sz);
                if (content && hasFrida(content)) {
                    var lines = content.split("\n"); var clean = [];
                    for (var li = 0; li < lines.length; li++) {
                        if (hasFrida(lines[li])) {
                            if (lines[li].indexOf(":7A69")!==-1||lines[li].indexOf(":7a69")!==-1||lines[li].indexOf(":69A2")!==-1||lines[li].indexOf(":69a2")!==-1) continue;
                            clean.push(lines[li].replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop").replace(/linjector/g,"xinjector"));
                        } else { clean.push(lines[li]); }
                    }
                    var result = clean.join("\n"); this.buf.writeUtf8String(result); r.replace(ptr(result.length));
                }
            }} catch(e) {}
        }
    });
}
var closeAddr = findExport("close");
if (closeAddr) { Interceptor.attach(closeAddr, { onEnter: function(a) { try { var fd=a[0].toInt32(); if(trackedFds[fd]) delete trackedFds[fd]; } catch(e){} } }); }
var accessAddr = findExport("access");
if (accessAddr) { Interceptor.attach(accessAddr, { onEnter: function(a) { var p=safeRead(a[0]); if(p&&hasFrida(p)) this.block=true; }, onLeave: function(r) { try { if(this.block) r.replace(ptr(-1)); } catch(e){} } }); }

// dl_iterate_phdr filter
var dlIterAddr = findExport("dl_iterate_phdr");
if (dlIterAddr) {
    var _fridaRanges = [];
    Process.enumerateModules().forEach(function(m) { if (hasFrida(m.name)||hasFrida(m.path)) _fridaRanges.push({base:m.base,end:m.base.add(m.size)}); });
    function isFromFrida(addr) { for(var i=0;i<_fridaRanges.length;i++){if(addr.compare(_fridaRanges[i].base)>=0&&addr.compare(_fridaRanges[i].end)<0)return true;}return false; }
    Interceptor.attach(dlIterAddr, {
        onEnter: function(args) {
            if (isFromFrida(this.returnAddress)) return;
            var origCb = args[0];
            this._ref = new NativeCallback(function(info,size,data) {
                try { var np=info.add(Process.pointerSize).readPointer(); var name=safeRead(np); if(name&&hasFrida(name))return 0; } catch(e){}
                return new NativeFunction(origCb,'int',['pointer','int','pointer'])(info,size,data);
            },'int',['pointer','int','pointer']);
            args[0] = this._ref;
        }
    });
}

// prctl thread name
var prctlAddr = findExport("prctl");
if (prctlAddr) {
    Interceptor.attach(prctlAddr, {
        onEnter: function(a) { if(a[0].toInt32()===16) this.getName=a[1]; },
        onLeave: function(r) {
            if(this.getName){try{var n=safeRead(this.getName);if(n&&hasFrida(n))this.getName.writeUtf8String(n.replace(/frida/g,"nxrth").replace(/gmain/g,"gloop").replace(/gum-js-loop/g,"app-js"));}catch(e){}}
        }
    });
}

send("[READY] PLT patched + stealth hooks active");

rpc.exports = {
    ping: function() { return "alive"; },
    getbase: function() {
        var m = Process.findModuleByName("libg.so");
        return m ? { base: m.base.toString(), size: m.size } : null;
    },
    modcount: function() { return Process.enumerateModules().length; }
};
"""

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

# === THE CRITICAL SEQUENCE ===
# 1. Kill the tracer
if tracer_pid:
    log(f"Killing tracer PID {tracer_pid}...")
    adb("shell", f"su -c 'kill -9 {tracer_pid}'")
    time.sleep(0.3)

    # Verify tracer is gone
    status2 = adb("shell", f"su -c 'cat /proc/{game_pid}/status 2>/dev/null | grep TracerPid'").stdout.strip()
    log(f"After kill: {status2}")

    # Check game still alive
    gp2 = adb("shell", f"pidof {PKG}").stdout.strip()
    if not gp2:
        log("Game died when tracer was killed!")
        sys.exit(1)
    log(f"Game still alive: PID {gp2}")

# 2. Attach Frida immediately
log("Attaching Frida...")
try:
    sess = device.attach(game_pid)
    sess.on("detached", on_det)
    log("ATTACH SUCCESSFUL!")

    # 3. Load payload with PLT patches + stealth
    scr = sess.create_script(INJECT_JS)
    scr.on("message", on_msg)
    scr.load()
    time.sleep(2)

    # 4. Monitor
    log("Monitoring (120s)...")
    start = time.time()
    for i in range(120):
        time.sleep(1)
        e = int(time.time() - start)
        if not alive:
            log(f"DEAD at +{e}s")
            break
        if e % 15 == 0:
            try:
                r = scr.exports_sync.ping()
                base = scr.exports_sync.getbase()
                mc = scr.exports_sync.modcount()
                log(f"+{e}s alive | mods={mc} | libg={base}")
            except Exception as ex:
                log(f"+{e}s RPC: {ex}")

    if alive:
        log("=== SURVIVED 120s! ===")
        try:
            base = scr.exports_sync.getbase()
            log(f"libg.so: {base}")
        except:
            pass

except frida.ProcessNotFoundError:
    log("ERROR: Process not found")
except Exception as e:
    log(f"ERROR: {e}")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
