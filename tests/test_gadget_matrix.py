"""Bisect startup-sensitive hook groups while using file-backed Gadget."""

import json
import subprocess
import time

import frida


ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
DEVICE_ID = "emulator-5554"
PACKAGE = "com.supercell.hayday"
SERVER_BIN = "/data/local/tmp/system_service"
GADGET_PATH = "/data/local/tmp/libandroid_runtime.so"
SERVER_PORT = 31337
GADGET_PORT = 31338

CASES = {
    "no_noreturn": ["abort", "exit", "_exit"],
    "no_signals": ["kill", "raise", "tgkill"],
    "no_strings": ["strstr", "strcmp", "__system_property_get"],
    "no_files": [
        "openat", "open", "read", "close", "fopen", "fgets", "fclose",
        "readlink", "readlinkat", "access", "faccessat", "stat", "lstat",
    ],
    "no_dirs": ["opendir", "readdir", "closedir"],
    "no_misc": ["pthread_create", "connect"],
}


def adb(*args):
    return subprocess.run(
        [ADB, "-s", DEVICE_ID, *args],
        capture_output=True,
        text=True,
        timeout=10,
    )


def make_code(disabled):
    with open("hook.js", "r", encoding="utf-8") as source:
        code = source.read()
    marker = "var DISABLED_HOOKS = {};"
    disabled_map = {name: True for name in disabled}
    replacement = "var DISABLED_HOOKS = " + json.dumps(disabled_map) + ";"
    if marker not in code:
        raise RuntimeError("hook.js test marker is missing")
    return code.replace(marker, replacement, 1)


def run_case(name, disabled):
    adb("shell", "su -c 'killall system_service 2>/dev/null'")
    adb("shell", f"am force-stop {PACKAGE}")
    subprocess.Popen(
        [
            ADB, "-s", DEVICE_ID, "shell",
            f"su -c 'nohup {SERVER_BIN} -D -l 0.0.0.0:{SERVER_PORT} &'",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    adb("forward", f"tcp:{SERVER_PORT}", f"tcp:{SERVER_PORT}")

    manager = frida.get_device_manager()
    server = manager.add_remote_device(f"127.0.0.1:{SERVER_PORT}")
    pid = server.spawn(PACKAGE)
    server.inject_library_file(pid, GADGET_PATH, "pthread_exit", "")
    adb("forward", f"tcp:{GADGET_PORT}", f"tcp:{GADGET_PORT}")
    time.sleep(0.4)

    gadget = manager.add_remote_device(f"127.0.0.1:{GADGET_PORT}")
    session = gadget.attach("Gadget")
    state = {"alive": True, "messages": []}
    session.on("detached", lambda reason: state.update(alive=False))

    script = session.create_script(make_code(disabled))
    script.on(
        "message",
        lambda message, data: state["messages"].append(str(message.get("payload", "")))
        if message.get("type") == "send"
        else None,
    )
    script.load()
    script.exports_sync.init()
    server.resume(pid)

    result = {"case": name, "alive": True, "libg": None, "messages": []}
    for _ in range(8):
        time.sleep(1)
        if not state["alive"]:
            result["alive"] = False
            break
        try:
            info = script.exports_sync.info()
            if info["base"]:
                result["libg"] = info["base"]
                break
        except Exception:
            result["alive"] = False
            break

    result["messages"] = [m for m in state["messages"] if "ANTI-KILL" in m]
    adb("shell", "su -c 'killall system_service 2>/dev/null'")
    print(json.dumps(result), flush=True)


for case_name, disabled_hooks in CASES.items():
    try:
        run_case(case_name, disabled_hooks)
    except Exception as error:
        print(json.dumps({"case": case_name, "error": repr(error)}), flush=True)
        adb("shell", "su -c 'killall system_service 2>/dev/null'")

