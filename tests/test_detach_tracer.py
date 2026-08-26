"""
Detach-tracer approach:
1. Frida attach to the TRACER process
2. From inside tracer, call ptrace(PTRACE_DETACH, game_pid)
3. Detach from tracer
4. Immediately attach Frida to the game
5. Patch libzyte.so + install stealth hooks
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

# Get PIDs
game_pid = int(adb("shell", f"pidof {PKG}").stdout.strip())
status = adb("shell", f"su -c 'cat /proc/{game_pid}/status'").stdout
tracer_pid = 0
for line in status.split('\n'):
    if line.startswith('TracerPid:'):
        tracer_pid = int(line.split(':')[1].strip())

log(f"Game PID: {game_pid}, Tracer PID: {tracer_pid}")
if tracer_pid == 0:
    log("No tracer! Can attach directly.")

# Start Frida server
adb("shell", "su -c 'killall system_service 2>/dev/null'")
time.sleep(0.5)
subprocess.Popen([ADB, "-s", DEV, "shell", f"su -c 'nohup {BIN} -l 0.0.0.0:{PORT} &'"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
log(f"Frida ready ({len(device.enumerate_processes())} procs)")

# Step 1: Attach to tracer and make it PTRACE_DETACH the game
if tracer_pid > 0:
    log(f"Attaching to tracer PID {tracer_pid}...")
    try:
        tracer_sess = device.attach(tracer_pid)
        log("Attached to tracer!")

        detach_done = threading.Event()
        detach_result = {"value": None}

        DETACH_JS = f"""
        var PTRACE_DETACH = 17;
        var SIGSTOP = 19;
        var gamePid = {game_pid};
        var detached = false;

        // Find ptrace in libc
        var ptraceAddr = null;
        try {{
            var libc = Process.getModuleByName("libc.so");
            ptraceAddr = libc.getExportByName("ptrace");
        }} catch(e) {{
            send("[TRACER] libc.so not found: " + e.message);
        }}

        if (ptraceAddr) {{
            send("[TRACER] ptrace at " + ptraceAddr);
            var ptrace = new NativeFunction(ptraceAddr, 'long', ['int', 'int', 'pointer', 'pointer']);
            var hookCount = 0;
            var hookedWaitAddresses = {{}};

            // PTRACE_DETACH has to be issued by the tracer thread while the
            // tracee is stopped.  Calling it eagerly from Frida's JS thread
            // always fails with ESRCH.  A waitpid/wait4 return gives us both
            // the correct calling thread and a stopped tracee.
            ["waitpid", "wait4"].forEach(function (name) {{
                try {{
                    var waitAddr = Process.getModuleByName("libc.so").getExportByName(name);
                    var waitKey = waitAddr.toString();
                    if (hookedWaitAddresses[waitKey]) return;
                    hookedWaitAddresses[waitKey] = true;
                    Interceptor.attach(waitAddr, {{
                        onLeave: function (retval) {{
                            if (detached || retval.toInt32() !== gamePid) return;
                            var tid = Process.getCurrentThreadId();
                            // Deliver SIGSTOP as part of DETACH.  This prevents
                            // the game from executing its no-tracer watchdog in
                            // the tiny window before Frida attaches.
                            var result = ptrace(PTRACE_DETACH, gamePid, ptr(0), ptr(SIGSTOP));
                            if (result === 0) detached = true;
                            send("[TRACER] ptrace(DETACH, " + gamePid + ") = " +
                                 result + " from tid=" + tid);
                        }}
                    }});
                    hookCount++;
                }} catch (e) {{}}
            }});
            send("[TRACER] armed " + hookCount + " wait hooks");
        }} else {{
            send("[TRACER] ERROR: ptrace not found");
        }}
        """

        def on_tracer_msg(m, d):
            if m["type"] == "send":
                payload = str(m["payload"])
                log(f"  {payload}")
                if "ptrace(DETACH" in payload:
                    succeeded = " = 0 " in payload
                    # waitpid may wrap wait4, so both hooks can observe the
                    # same return.  Never let a later ESRCH overwrite the
                    # successful inner detach.
                    if succeeded or detach_result["value"] is None:
                        detach_result["value"] = succeeded
                    if succeeded:
                        detach_done.set()
            elif m["type"] == "error":
                log(f"  TRACER ERR: {m.get('description','?')}")

        tracer_scr = tracer_sess.create_script(DETACH_JS)
        tracer_scr.on("message", on_tracer_msg)
        tracer_scr.load()

        # Wake the tracer's wait loop with a real ptrace-stop.  The hook above
        # performs DETACH synchronously before the tracer can resume the game.
        adb("shell", f"su -c 'kill -STOP {game_pid}'")
        if not detach_done.wait(3) or not detach_result["value"]:
            log("Tracer detach failed or timed out")
            try:
                tracer_scr.unload()
            except Exception:
                pass
            try:
                tracer_sess.detach()
            except Exception:
                pass
            adb("shell", "su -c 'killall system_service 2>/dev/null'")
            sys.exit(1)

        # Keep the tracer session alive until the game agent is installed.
        # Unloading it here costs enough time for Promon's watchdog to kill
        # the game before Frida can win the attach race.
        log("Tracer detached; racing game attach now")

    except Exception as e:
        log(f"Tracer attach failed: {e}")
        # Try killing as fallback
        log("Fallback: killing tracer...")
        adb("shell", f"su -c 'kill -STOP {tracer_pid}'")
        time.sleep(0.1)

# Step 2: Attach Frida to the game
log(f"Attaching Frida to game PID {game_pid}...")

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

try:
    game_sess = device.attach(game_pid)
    game_sess.on("detached", on_det)
    log("=== GAME ATTACH SUCCESSFUL! ===")

    # Load full payload
    GAME_JS = r"""
    'use strict';
    var _myPid = Process.id;
    send("[GAME] PID=" + _myPid + " Arch=" + Process.arch);

    // Find libzyte.so
    var zyte = null;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name === "libzyte.so" && mods[i].path.indexOf("x86_64") !== -1) {
            zyte = mods[i]; break;
        }
    }
    if (!zyte) {
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name === "libzyte.so") { zyte = mods[i]; break; }
        }
    }

    if (zyte) {
        send("[ZYTE] " + zyte.base + " (" + zyte.size + ") " + zyte.path);

        var PLT = {
            'strstr':     { rva: 0x2fd910, p: [0x31,0xC0,0xC3] },
            'strcmp':      { rva: 0x2fd8c0, p: [0xB8,1,0,0,0,0xC3] },
            'strncmp':     { rva: 0x2fd900, p: [0xB8,1,0,0,0,0xC3] },
            'memcmp':      { rva: 0x2fdb90, p: [0xB8,1,0,0,0,0xC3] },
            'open':        { rva: 0x2fe0c0, p: [0xB8,0xFF,0xFF,0xFF,0xFF,0xC3] },
            'fopen':       { rva: 0x2fd870, p: [0x31,0xC0,0xC3] },
            'fgets':       { rva: 0x2fd8a0, p: [0x31,0xC0,0xC3] },
            'fread':       { rva: 0x2fdc80, p: [0x31,0xC0,0xC3] },
            'read':        { rva: 0x2fe0d0, p: [0xB8,0xFF,0xFF,0xFF,0xFF,0xC3] },
            'dl_iterate':  { rva: 0x2fdfa0, p: [0x31,0xC0,0xC3] },
            'access':      { rva: 0x2fdfb0, p: [0xB8,0xFF,0xFF,0xFF,0xFF,0xC3] },
            'stat':        { rva: 0x2fdd20, p: [0xB8,0xFF,0xFF,0xFF,0xFF,0xC3] },
            'popen':       { rva: 0x2fdd50, p: [0x31,0xC0,0xC3] },
            'socket':      { rva: 0x2fdeb0, p: [0xB8,0xFF,0xFF,0xFF,0xFF,0xC3] },
            'syscall':     { rva: 0x2fe180, p: [0x31,0xC0,0xC3] },
            'abort':       { rva: 0x2ff110, p: [0xEB,0xFE] },
        };

        var ok = 0;
        var names = Object.keys(PLT);
        for (var i = 0; i < names.length; i++) {
            var addr = zyte.base.add(PLT[names[i]].rva);
            try {
                Memory.protect(addr, 16, 'rwx');
                addr.writeByteArray(PLT[names[i]].p);
                ok++;
            } catch(e) { send("[PATCH] " + names[i] + " FAIL"); }
        }
        send("[PATCH] " + ok + "/" + names.length);
    } else {
        send("[ZYTE] NOT FOUND");
    }

    // libg.so
    var libg = Process.findModuleByName("libg.so");
    send("[LIBG] " + (libg ? libg.base + " (" + libg.size + ")" : "NOT FOUND"));

    // Anti-kill + stealth
    function findExport(n) { var L=["libdl.so","libc.so","linker64"]; for(var i=0;i<L.length;i++){try{var m=Process.getModuleByName(L[i]);var a=m.getExportByName(n);if(a&&!a.isNull())return a;}catch(e){}} return null; }
    function safeRead(p){try{return p&&!p.isNull()?p.readCString():null}catch(e){return null}}
    var FS=["frida","gadget","linjector","gum-js-loop","gmain","gdbus","re.frida","frida-agent","frida-server"];
    function hasFrida(s){if(!s)return false;var l=s.toLowerCase();for(var i=0;i<FS.length;i++)if(l.indexOf(FS[i])!==-1)return true;return false;}

    var kA=findExport("kill");
    if(kA)Interceptor.replace(kA,new NativeCallback(function(p,s){if(p===_myPid||p===0||s===9||s===6){send("[K]kill("+p+","+s+")");return 0;}return 0;},'int',['int','int']));
    var rA=findExport("raise");
    if(rA)Interceptor.replace(rA,new NativeCallback(function(s){if(s===6||s===9||s===11)return 0;return 0;},'int',['int']));
    var tA=findExport("tgkill");
    if(tA)Interceptor.replace(tA,new NativeCallback(function(a,b,s){if(s===6||s===9)return 0;return 0;},'int',['int','int','int']));

    // Linker rename
    var dlA=findExport("dl_iterate_phdr");
    if(dlA){var rDl=new NativeFunction(dlA,'int',['pointer','pointer']);
        rDl(new NativeCallback(function(i,s,d){try{var np=i.add(Process.pointerSize).readPointer();var n=safeRead(np);
            if(n&&hasFrida(n)){var nn=n.replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop");
                try{Memory.protect(np,nn.length+1,'rwx');np.writeUtf8String(nn);}catch(e){}}}catch(e){}return 0;},'int',['pointer','int','pointer']),ptr(0));}

    // Stealth hooks
    var ssA=findExport("strstr");
    if(ssA)Interceptor.attach(ssA,{onEnter:function(a){this.n=safeRead(a[1])},onLeave:function(r){try{if(this.n&&hasFrida(this.n))r.replace(ptr(0))}catch(e){}}});
    var scA=findExport("strcmp");
    if(scA)Interceptor.attach(scA,{onEnter:function(a){this.a=safeRead(a[0]);this.b=safeRead(a[1])},onLeave:function(r){try{if((this.a&&hasFrida(this.a))||(this.b&&hasFrida(this.b)))r.replace(ptr(-1))}catch(e){}}});

    var PP=["/proc/self/maps","/proc/self/smaps","/proc/self/status","/proc/net/tcp","/proc/net/tcp6","/proc/net/unix"];
    function isS(p){if(!p)return false;for(var i=0;i<PP.length;i++)if(p.indexOf(PP[i])!==-1)return true;if(p.indexOf("/proc/"+_myPid+"/")!==-1)return true;return false;}
    var tF={};
    var oaA=findExport("openat");if(oaA)Interceptor.attach(oaA,{onEnter:function(a){this.p=safeRead(a[1])},onLeave:function(r){try{if(isS(this.p))tF[r.toInt32()]=this.p}catch(e){}}});
    var oA=findExport("open");if(oA)Interceptor.attach(oA,{onEnter:function(a){this.p=safeRead(a[0])},onLeave:function(r){try{if(isS(this.p))tF[r.toInt32()]=this.p}catch(e){}}});
    var rdA=findExport("read");
    if(rdA)Interceptor.attach(rdA,{onEnter:function(a){this.fd=a[0].toInt32();this.buf=a[1]},onLeave:function(r){try{var sz=r.toInt32();if(tF[this.fd]&&sz>0){var c=this.buf.readUtf8String(sz);if(c&&hasFrida(c)){var ls=c.split("\n"),cl=[];for(var i=0;i<ls.length;i++){if(hasFrida(ls[i])){if(ls[i].indexOf(":7A69")!==-1||ls[i].indexOf(":7a69")!==-1||ls[i].indexOf(":69A2")!==-1||ls[i].indexOf(":69a2")!==-1)continue;cl.push(ls[i].replace(/frida-agent/g,"system-agent").replace(/frida/g,"nxrth").replace(/gum-js-loop/g,"app-js-loop").replace(/gmain/g,"gloop").replace(/linjector/g,"xinjector"))}else cl.push(ls[i])}var res=cl.join("\n");this.buf.writeUtf8String(res);r.replace(ptr(res.length))}}}catch(e){}}});
    var clA=findExport("close");if(clA)Interceptor.attach(clA,{onEnter:function(a){try{var fd=a[0].toInt32();if(tF[fd])delete tF[fd]}catch(e){}}});
    var acA=findExport("access");if(acA)Interceptor.attach(acA,{onEnter:function(a){var p=safeRead(a[0]);if(p&&hasFrida(p))this.bl=true},onLeave:function(r){try{if(this.bl)r.replace(ptr(-1))}catch(e){}}});

    var dIA=findExport("dl_iterate_phdr");
    if(dIA){var fR=[];Process.enumerateModules().forEach(function(m){if(hasFrida(m.name)||hasFrida(m.path))fR.push({b:m.base,e:m.base.add(m.size)})});
        function iFF(a){for(var i=0;i<fR.length;i++)if(a.compare(fR[i].b)>=0&&a.compare(fR[i].e)<0)return true;return false;}
        Interceptor.attach(dIA,{onEnter:function(a){if(iFF(this.returnAddress))return;var oc=a[0];this._r=new NativeCallback(function(i,s,d){try{var np=i.add(Process.pointerSize).readPointer();var n=safeRead(np);if(n&&hasFrida(n))return 0;}catch(e){}return new NativeFunction(oc,'int',['pointer','int','pointer'])(i,s,d);},'int',['pointer','int','pointer']);a[0]=this._r}});}

    var prA=findExport("prctl");
    if(prA)Interceptor.attach(prA,{onEnter:function(a){if(a[0].toInt32()===16)this.gn=a[1]},onLeave:function(r){if(this.gn){try{var n=safeRead(this.gn);if(n&&hasFrida(n))this.gn.writeUtf8String(n.replace(/frida/g,"nxrth").replace(/gmain/g,"gloop").replace(/gum-js-loop/g,"app-js"))}catch(e){}}}});

    send("[READY] All hooks active!");

    rpc.exports = {
        ping: function() { return "alive"; },
        getbase: function() {
            var m = Process.findModuleByName("libg.so");
            return m ? { base: m.base.toString(), size: m.size } : null;
        },
        modcount: function() { return Process.enumerateModules().length; }
    };
    """

    game_scr = game_sess.create_script(GAME_JS)
    game_scr.on("message", on_msg)
    game_scr.load()

    # The tracee was deliberately left in a group-stop by PTRACE_DETACH.
    # Resume only after all game-side patches and hooks are active.
    adb("shell", f"su -c 'kill -CONT {game_pid}'")
    time.sleep(2)

    # Monitor
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
                r = game_scr.exports_sync.ping()
                base = game_scr.exports_sync.getbase()
                log(f"+{e}s alive | libg={base}")
            except Exception as ex:
                log(f"+{e}s RPC: {ex}")

    if alive:
        log("=== SURVIVED 120s WITH ATTACH MODE! ===")
        try:
            base = game_scr.exports_sync.getbase()
            log(f"libg.so: {base}")
        except:
            pass

except frida.ProcessNotFoundError:
    log("ERROR: Game process not found")
except Exception as e:
    log(f"ERROR: {e}")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
