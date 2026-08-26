"""
Runtime memory scanner: spawn game with Frida, wait for libg.so to load,
scan its memory for Promon SHIELD detection patterns (ARM64 inline syscalls,
exit_group, kill, /proc/self/maps references, frida strings, 0xdead1007).
Anti-kill hooks keep the process alive while scanning.
"""
import frida, subprocess, time, sys, json

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
scan_results = []
def on_msg(m, d):
    if m["type"] == "send":
        payload = m['payload']
        if isinstance(payload, dict):
            scan_results.append(payload)
            log(f"  RESULT: {json.dumps(payload, indent=2)[:200]}")
        else:
            payload = str(payload).encode('ascii', errors='replace').decode()
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

SCANNER_JS = r"""
function findExport(name) {
    var libs = ["libc.so","libdl.so"];
    for (var i=0;i<libs.length;i++) {
        try { var m=Process.getModuleByName(libs[i]); var a=m.getExportByName(name); if(a&&!a.isNull()) return a; } catch(e){}
    }
    return null;
}

var _myPid = Process.id;
var _pthreadExit = findExport("pthread_exit");
var pthreadExitFn = _pthreadExit ? new NativeFunction(_pthreadExit, 'void', ['pointer']) : null;
var _nanosleep = findExport("nanosleep");
var nanosleepFn = _nanosleep ? new NativeFunction(_nanosleep, 'int', ['pointer', 'pointer']) : null;
var _longSleep = Memory.alloc(16);
_longSleep.writeU64(2147483647);
_longSleep.add(8).writeU64(0);

function suspendThread(label) {
    var tid = Process.getCurrentThreadId();
    send("[ANTI-KILL] " + label + " tid=" + tid);
    if (tid !== _myPid && pthreadExitFn) { pthreadExitFn(ptr(0)); }
    if (nanosleepFn) { while(true) nanosleepFn(_longSleep, ptr(0)); }
    while(true) {}
}

// Anti-kill hooks
var killAddr = findExport("kill");
if (killAddr) {
    Interceptor.replace(killAddr, new NativeCallback(function(p, s) {
        if (p === _myPid || p === 0 || s === 9 || s === 6) {
            suspendThread("kill(" + p + "," + s + ")");
        }
        return 0;
    }, "int", ["int","int"]));
}
var exitAddr = findExport("_exit");
if (exitAddr) {
    Interceptor.replace(exitAddr, new NativeCallback(function(c) {
        suspendThread("_exit(" + c + ")");
    }, "void", ["int"]));
}
var abortAddr = findExport("abort");
if (abortAddr) {
    Interceptor.replace(abortAddr, new NativeCallback(function() {
        suspendThread("abort()");
    }, "void", []));
}
var exitAddr2 = findExport("exit");
if (exitAddr2) {
    Interceptor.replace(exitAddr2, new NativeCallback(function(c) {
        suspendThread("exit(" + c + ")");
    }, "void", ["int"]));
}
var tgkillAddr = findExport("tgkill");
if (tgkillAddr) {
    Interceptor.replace(tgkillAddr, new NativeCallback(function(tg,t,s) {
        if (s === 6 || s === 9) { suspendThread("tgkill"); }
        return 0;
    }, "int", ["int","int","int"]));
}
var raiseAddr = findExport("raise");
if (raiseAddr) {
    Interceptor.replace(raiseAddr, new NativeCallback(function(s) { return 0; }, "int", ["int"]));
}

send("[ANTI-KILL] All kill vectors hooked");

// ── SCANNER ──
var scanDone = false;

function scanLibg() {
    if (scanDone) return;
    scanDone = true;

    var mod = Process.findModuleByName("libg.so");
    if (!mod) { send("[SCAN] libg.so not found!"); return; }

    send("[SCAN] libg.so loaded at " + mod.base + " size=0x" + mod.size.toString(16) + " (" + mod.size + " bytes)");

    var results = {
        type: "scan_results",
        base: mod.base.toString(),
        size: mod.size,
        exit_group: [],
        kill_syscall: [],
        svc_instructions: [],
        frida_strings: [],
        proc_maps_refs: [],
        dead1007: [],
        openat_syscall: []
    };

    // Enumerate memory ranges of libg.so
    var ranges = mod.enumerateRanges('r-x');
    send("[SCAN] " + ranges.length + " executable ranges in libg.so");

    var totalScanned = 0;
    for (var ri = 0; ri < ranges.length; ri++) {
        var range = ranges[ri];
        var rangeSize = range.size;
        totalScanned += rangeSize;

        // Scan in 64KB chunks to avoid memory issues
        var CHUNK = 65536;
        for (var chunkOff = 0; chunkOff < rangeSize; chunkOff += CHUNK) {
            var readSize = Math.min(CHUNK, rangeSize - chunkOff);
            var addr = range.base.add(chunkOff);

            try {
                var bytes = addr.readByteArray(readSize);
                var view = new DataView(bytes);

                for (var i = 0; i < readSize - 4; i += 4) {
                    var instr = view.getUint32(i, true); // little-endian

                    // SVC #0 = 0xD4000001
                    if (instr === 0xD4000001) {
                        var svcAddr = addr.add(i);
                        var offset = svcAddr.sub(mod.base).toInt32();

                        // Check previous instructions for syscall number
                        if (i >= 4) {
                            var prev1 = view.getUint32(i - 4, true);
                            // MOV X8, #imm = MOVZ X8, #imm16
                            // MOVZ X8 = 0xD28xxxE8 where xxx encodes imm16
                            if ((prev1 & 0xFFE0001F) === 0xD2800008) {
                                var sysno = (prev1 >> 5) & 0xFFFF;

                                if (sysno === 94) { // exit_group
                                    var sig = svcAddr.sub(4).readByteArray(16);
                                    var sigHex = "";
                                    var arr = new Uint8Array(sig);
                                    for (var j = 0; j < arr.length; j++) sigHex += ("0" + arr[j].toString(16)).slice(-2);

                                    // Scan back for function prologue (STP X29, X30)
                                    var funcStart = null;
                                    var funcSig = "";
                                    for (var k = 4; k < 512; k += 4) {
                                        try {
                                            var pi = svcAddr.sub(k).readU32();
                                            if ((pi & 0xFFE07FFF) === 0xA9007BFD) { // STP X29, X30, [SP, #off]!
                                                funcStart = svcAddr.sub(k);
                                                var fsBytes = funcStart.readByteArray(16);
                                                var fsArr = new Uint8Array(fsBytes);
                                                for (var j2 = 0; j2 < fsArr.length; j2++) funcSig += ("0" + fsArr[j2].toString(16)).slice(-2);
                                                break;
                                            }
                                        } catch(e) { break; }
                                    }

                                    results.exit_group.push({
                                        offset: "0x" + offset.toString(16),
                                        addr: svcAddr.sub(4).toString(),
                                        sig: sigHex,
                                        funcStart: funcStart ? funcStart.sub(mod.base).toInt32().toString(16) : null,
                                        funcSig: funcSig || null
                                    });
                                    send("[SCAN] exit_group at libg.so+0x" + offset.toString(16) + " sig=" + sigHex);
                                }
                                else if (sysno === 129) { // kill
                                    var sig2 = svcAddr.sub(4).readByteArray(16);
                                    var sigHex2 = "";
                                    var arr2 = new Uint8Array(sig2);
                                    for (var j3 = 0; j3 < arr2.length; j3++) sigHex2 += ("0" + arr2[j3].toString(16)).slice(-2);

                                    var funcStart2 = null;
                                    var funcSig2 = "";
                                    for (var k2 = 4; k2 < 512; k2 += 4) {
                                        try {
                                            var pi2 = svcAddr.sub(k2).readU32();
                                            if ((pi2 & 0xFFE07FFF) === 0xA9007BFD) {
                                                funcStart2 = svcAddr.sub(k2);
                                                var fs2Bytes = funcStart2.readByteArray(16);
                                                var fs2Arr = new Uint8Array(fs2Bytes);
                                                for (var j4 = 0; j4 < fs2Arr.length; j4++) funcSig2 += ("0" + fs2Arr[j4].toString(16)).slice(-2);
                                                break;
                                            }
                                        } catch(e) { break; }
                                    }

                                    results.kill_syscall.push({
                                        offset: "0x" + offset.toString(16),
                                        addr: svcAddr.sub(4).toString(),
                                        sig: sigHex2,
                                        funcStart: funcStart2 ? funcStart2.sub(mod.base).toInt32().toString(16) : null,
                                        funcSig: funcSig2 || null
                                    });
                                    send("[SCAN] kill syscall at libg.so+0x" + offset.toString(16) + " sig=" + sigHex2);
                                }
                                else if (sysno === 56) { // openat
                                    results.openat_syscall.push({
                                        offset: "0x" + offset.toString(16),
                                        sysno: sysno
                                    });
                                }
                            }
                        }
                    }
                }
            } catch(e) {
                // Skip unreadable ranges
            }
        }
    }

    send("[SCAN] Scanned " + totalScanned + " bytes of executable code");

    // Scan all readable ranges for strings
    var allRanges = mod.enumerateRanges('r--');
    send("[SCAN] Scanning " + allRanges.length + " readable ranges for strings...");

    var stringTargets = ["frida", "/proc/self/maps", "/proc/self/status", "/proc/net/tcp",
                         "TracerPid", "memfd:", "ptrace", "xposed", "substrate"];

    for (var si = 0; si < allRanges.length; si++) {
        var sr = allRanges[si];
        try {
            var SCHUNK = 65536;
            for (var soff = 0; soff < sr.size; soff += SCHUNK) {
                var sread = Math.min(SCHUNK, sr.size - soff);
                var saddr = sr.base.add(soff);
                try {
                    var sbytes = saddr.readByteArray(sread);
                    var sview = new Uint8Array(sbytes);

                    for (var t = 0; t < stringTargets.length; t++) {
                        var target = stringTargets[t];
                        var targetBytes = [];
                        for (var tc = 0; tc < target.length; tc++) targetBytes.push(target.charCodeAt(tc));

                        // Simple byte-by-byte search
                        for (var si2 = 0; si2 <= sread - targetBytes.length; si2++) {
                            var match = true;
                            for (var tc2 = 0; tc2 < targetBytes.length; tc2++) {
                                if (sview[si2 + tc2] !== targetBytes[tc2]) { match = false; break; }
                            }
                            if (match) {
                                var strAddr = saddr.add(si2);
                                var strOffset = strAddr.sub(mod.base).toInt32();
                                // Read full string at this location
                                var fullStr = "";
                                try { fullStr = strAddr.readCString(); } catch(e) { fullStr = target; }

                                if (target === "frida") {
                                    results.frida_strings.push({
                                        offset: "0x" + strOffset.toString(16),
                                        str: fullStr ? fullStr.substring(0, 100) : target
                                    });
                                    send("[SCAN] 'frida' string at libg.so+0x" + strOffset.toString(16) + ": " + (fullStr || "").substring(0, 60));
                                } else if (target === "/proc/self/maps") {
                                    results.proc_maps_refs.push({
                                        offset: "0x" + strOffset.toString(16),
                                        str: fullStr ? fullStr.substring(0, 100) : target
                                    });
                                    send("[SCAN] '/proc/self/maps' at libg.so+0x" + strOffset.toString(16));
                                }
                            }
                        }
                    }
                } catch(e2) {}
            }
        } catch(e) {}
    }

    // Search for 0xdead1007 in all readable memory
    try {
        Memory.scan(mod.base, mod.size, "07 10 AD DE", {
            onMatch: function(addr, size) {
                var off = addr.sub(mod.base).toInt32();
                results.dead1007.push({ offset: "0x" + off.toString(16) });
                send("[SCAN] 0xdead1007 at libg.so+0x" + off.toString(16));
            },
            onComplete: function() {
                send("[SCAN] 0xdead1007 scan complete");
            }
        });
    } catch(e) {
        send("[SCAN] dead1007 scan error: " + e.message);
    }

    // Send final results
    setTimeout(function() {
        send(results);
        send("[SCAN] === SCAN COMPLETE ===");
        send("[SCAN] exit_group: " + results.exit_group.length);
        send("[SCAN] kill_syscall: " + results.kill_syscall.length);
        send("[SCAN] openat_syscall: " + results.openat_syscall.length);
        send("[SCAN] frida_strings: " + results.frida_strings.length);
        send("[SCAN] proc_maps_refs: " + results.proc_maps_refs.length);
        send("[SCAN] dead1007: " + results.dead1007.length);
    }, 2000);
}

// Hook dlopen to detect libg.so loading
var dlopenAddr = findExport("dlopen");
var androidDlopenAddr = findExport("android_dlopen_ext");

function hookDlopen(addr, name) {
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var path = args[0];
                try { this.libName = path.readCString(); } catch(e) { this.libName = null; }
            },
            onLeave: function(retval) {
                if (this.libName && this.libName.indexOf("libg.so") !== -1) {
                    send("[LOADER] libg.so loaded via " + name + ": " + this.libName);
                    setTimeout(scanLibg, 100);
                }
            }
        });
        send("[HOOK] " + name + " hooked");
    } catch(e) {
        send("[HOOK] " + name + " failed: " + e.message);
    }
}

if (dlopenAddr) hookDlopen(dlopenAddr, "dlopen");
if (androidDlopenAddr) hookDlopen(androidDlopenAddr, "android_dlopen_ext");

// Also poll for libg.so in case dlopen hook misses it
var pollInterval = setInterval(function() {
    var mod = Process.findModuleByName("libg.so");
    if (mod) {
        clearInterval(pollInterval);
        send("[POLL] libg.so found at " + mod.base);
        scanLibg();
    }
}, 500);

send("[READY] Scanner ready. Resume to start game.");

rpc.exports = {
    ping: function() { return "alive"; },
    forcescan: function() { scanLibg(); return "scanning"; },
    getresults: function() { return scan_results; }
};
"""

scr = sess.create_script(SCANNER_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(1)

log("=== RESUMING to trigger libg.so load + scan ===")
device.resume(pid)

log("Waiting for scan results (60s max)...")
start = time.time()
for i in range(60):
    time.sleep(1)
    e = int(time.time() - start)
    if not alive:
        log(f"Process ended at +{e}s")
        break
    if e % 10 == 0:
        log(f"+{e}s alive, waiting for scan...")

log(f"\nCollected {len(scan_results)} result objects")
for r in scan_results:
    if isinstance(r, dict) and r.get('type') == 'scan_results':
        log("\n=== FINAL SCAN RESULTS ===")
        log(f"  exit_group locations: {len(r.get('exit_group', []))}")
        for eg in r.get('exit_group', []):
            log(f"    offset={eg['offset']} sig={eg['sig']}")
            if eg.get('funcStart'):
                log(f"    funcStart=0x{eg['funcStart']} funcSig={eg['funcSig']}")
        log(f"  kill_syscall locations: {len(r.get('kill_syscall', []))}")
        for ks in r.get('kill_syscall', []):
            log(f"    offset={ks['offset']} sig={ks['sig']}")
            if ks.get('funcStart'):
                log(f"    funcStart=0x{ks['funcStart']} funcSig={ks['funcSig']}")
        log(f"  openat_syscall: {len(r.get('openat_syscall', []))}")
        log(f"  frida_strings: {len(r.get('frida_strings', []))}")
        for fs in r.get('frida_strings', []):
            log(f"    offset={fs['offset']} str={fs['str'][:60]}")
        log(f"  proc_maps_refs: {len(r.get('proc_maps_refs', []))}")
        for pm in r.get('proc_maps_refs', []):
            log(f"    offset={pm['offset']}")
        log(f"  dead1007: {len(r.get('dead1007', []))}")

# Save results to file for further analysis
if scan_results:
    with open("scan_results.json", "w") as f:
        json.dump(scan_results, f, indent=2, default=str)
    log("Results saved to scan_results.json")

adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
