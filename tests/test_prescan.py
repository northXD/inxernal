"""
Pre-resume scan: spawn game, check what's loaded BEFORE resume.
If libzyte.so is loaded, we can patch it before Promon starts!
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

def on_msg(m, d):
    if m["type"] == "send":
        payload = str(m['payload']).encode('ascii', errors='replace').decode()
        log(f"  JS: {payload}")

pid = device.spawn(PKG)
log(f"Spawned PID {pid}")
sess = device.attach(pid)

PRESCAN_JS = r"""
send("[SCAN] PID=" + Process.id + " Arch=" + Process.arch);

// Check ALL loaded modules
var mods = Process.enumerateModules();
send("[SCAN] " + mods.length + " modules loaded BEFORE resume");

var found = { libg: null, zyte: null, zyte_arm64: null, supercell: null };

for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    var name = m.name.toLowerCase();
    var path = m.path.toLowerCase();

    if (name === "libg.so") found.libg = m;
    if (name === "libzyte.so" && path.indexOf("x86_64") !== -1) found.zyte = m;
    if (name === "libzyte.so" && path.indexOf("arm64") !== -1) found.zyte_arm64 = m;
    if (name.indexOf("supercell") !== -1) found.supercell = m;

    // Log interesting modules
    if (name.indexOf("zyte") !== -1 || name.indexOf("promon") !== -1 ||
        name.indexOf("shield") !== -1 || name === "libg.so" ||
        name.indexOf("supercell") !== -1 || name.indexOf("hayday") !== -1) {
        send("[MOD] " + m.name + " @ " + m.base + " (" + m.size + ") " + m.path);
    }
}

if (found.zyte) {
    send("[CRITICAL] libzyte.so (x86_64) IS loaded before resume!");
    send("[CRITICAL] Base: " + found.zyte.base + " Size: " + found.zyte.size);
    send("[CRITICAL] Path: " + found.zyte.path);

    // Check its memory ranges
    var ranges = found.zyte.enumerateRanges('---');
    send("[CRITICAL] " + ranges.length + " memory ranges:");
    for (var r = 0; r < ranges.length; r++) {
        send("[RANGE] " + ranges[r].base + " - " + ranges[r].base.add(ranges[r].size) +
             " (" + ranges[r].size + ") " + ranges[r].protection);
    }

    // Check if we can read its .text section
    try {
        var testRead = found.zyte.base.readByteArray(16);
        send("[READ] First 16 bytes: " + Array.from(new Uint8Array(testRead)).map(b => ('0'+b.toString(16)).slice(-2)).join(''));
    } catch(e) {
        send("[READ] Failed: " + e.message);
    }

    // Try to find exports
    try {
        var exports = found.zyte.enumerateExports();
        send("[EXPORTS] " + exports.length + " exports");
        var jniOnLoad = null;
        for (var e = 0; e < exports.length; e++) {
            if (exports[e].name === "JNI_OnLoad") {
                jniOnLoad = exports[e];
                send("[EXPORT] JNI_OnLoad at " + exports[e].address);
            }
        }
    } catch(e) {
        send("[EXPORTS] Failed: " + e.message);
    }

    // Try to find imports (for PLT patching)
    try {
        var imports = found.zyte.enumerateImports();
        var interesting = ["strstr","open","fopen","read","fread","kill","_exit","abort","syscall","dl_iterate_phdr","access","stat","opendir","readdir"];
        send("[IMPORTS] " + imports.length + " imports");
        for (var im = 0; im < imports.length; im++) {
            for (var ii = 0; ii < interesting.length; ii++) {
                if (imports[im].name === interesting[ii]) {
                    send("[IMPORT] " + imports[im].name + " @ slot=" + imports[im].address + " type=" + imports[im].type);
                }
            }
        }
    } catch(e) {
        send("[IMPORTS] Failed: " + e.message);
    }
} else {
    send("[SCAN] libzyte.so x86_64 NOT loaded before resume");
}

if (found.zyte_arm64) {
    send("[MOD] libzyte.so (arm64) also loaded: " + found.zyte_arm64.base);
}

if (found.libg) {
    send("[MOD] libg.so loaded: " + found.libg.base);
} else {
    send("[SCAN] libg.so NOT loaded before resume");
}

send("[SCAN] Done. DO NOT RESUME - just collecting info.");

rpc.exports = {
    getinfo: function() {
        return {
            zyte_loaded: found.zyte !== null,
            zyte_base: found.zyte ? found.zyte.base.toString() : null,
            zyte_size: found.zyte ? found.zyte.size : 0,
            libg_loaded: found.libg !== null
        };
    }
};
"""

scr = sess.create_script(PRESCAN_JS)
scr.on("message", on_msg)
scr.load()
time.sleep(2)

try:
    info = scr.exports_sync.getinfo()
    log(f"\nSummary: {info}")
except:
    pass

# Clean up without resume
device.kill(pid)
adb("shell", "su -c 'killall system_service 2>/dev/null'")
log("Done")
