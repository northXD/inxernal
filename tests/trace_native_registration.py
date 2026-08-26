"""One-shot diagnostic: map Promon Java native methods to libzyte offsets.

This intentionally uses file-backed Gadget and exits after a few seconds.  It
does not patch the target; the captured offsets are used to locate the narrow
detection decision in the native library.
"""

from __future__ import annotations

import subprocess
import time

import frida


ADB = r"C:\LDPlayer\LDPlayer9\adb.exe"
SERIAL = "emulator-5554"
PACKAGE = "com.supercell.hayday"
SERVER = "/data/local/tmp/system_service"
GADGET = "/data/local/tmp/libandroid_runtime.so"
SERVER_PORT = 31337
GADGET_PORT = 31338


TRACE_JS = r"""
'use strict';

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return { module: null, offset: null, address: address.toString() };
    return {
        module: module.name,
        path: module.path,
        offset: address.sub(module.base).toString(),
        address: address.toString()
    };
}

const watched = new Set();
function hookRegisterNatives() {
    const art = Process.getModuleByName('libart.so');
    const candidates = art.enumerateSymbols().filter(function (symbol) {
        return symbol.name.indexOf('RegisterNatives') !== -1;
    });
    candidates.forEach(function (symbol) {
        const key = symbol.address.toString();
        if (watched.has(key))
            return;
        watched.add(key);
        if (symbol.address.isNull())
            return;
        try {
        Interceptor.attach(symbol.address, {
            onEnter(args) {
                let count;
                try { count = args[3].toInt32(); } catch (_) { return; }
                if (count <= 0 || count > 512 || args[2].isNull())
                    return;
                const methods = [];
                try {
                    for (let i = 0; i !== count; i++) {
                        const item = args[2].add(i * Process.pointerSize * 3);
                        const name = item.readPointer().readCString();
                        const signature = item.add(Process.pointerSize).readPointer().readCString();
                        const implementation = item.add(Process.pointerSize * 2).readPointer();
                        methods.push({
                            name: name,
                            signature: signature,
                            implementation: describe(implementation)
                        });
                    }
                } catch (_) {
                    return;
                }
                if (methods.some(m => m.implementation.module === 'libzyte.so'))
                    send({ event: 'register-natives', symbol: symbol.name, methods: methods });
            }
        });
        } catch (error) {
            send({ event: 'lookup-hook-error', symbol: symbol.name,
                   address: symbol.address.toString(), error: String(error) });
        }
    });
    send({ event: 'register-hooks', count: watched.size });
}

let jniCallCount = 0;
const classes = new Map();
const methods = new Map();
function hookJniLookups() {
    const art = Process.getModuleByName('libart.so');
    const hooked = new Set();
    art.enumerateSymbols().filter(function (symbol) {
        return symbol.name.indexOf('FindClass') !== -1 ||
               symbol.name.indexOf('GetStaticMethodID') !== -1;
    }).forEach(function (symbol) {
        const key = symbol.address.toString();
        if (hooked.has(key))
            return;
        hooked.add(key);
        if (symbol.address.isNull())
            return;
        try {
        Interceptor.attach(symbol.address, {
            onEnter(args) {
                this.kind = symbol.name.indexOf('GetStaticMethodID') !== -1
                    ? 'method' : 'class';
                try {
                    if (this.kind === 'class') {
                        this.className = args[1].readCString();
                    } else {
                        this.classRef = args[1].toString();
                        this.methodName = args[2].readCString();
                        this.signature = args[3].readCString();
                    }
                } catch (_) {
                    this.kind = null;
                }
            },
            onLeave(retval) {
                if (this.kind === null || retval.isNull())
                    return;
                const key = retval.toString();
                if (this.kind === 'class') {
                    classes.set(key, this.className);
                    send({ event: 'find-class', result: key, name: this.className });
                } else {
                    const entry = {
                        className: classes.get(this.classRef) || null,
                        classRef: this.classRef,
                        name: this.methodName,
                        signature: this.signature
                    };
                    methods.set(key, entry);
                    send({ event: 'get-static-method', result: key, method: entry });
                }
            }
        });
        } catch (error) {
            send({ event: 'lookup-hook-error', symbol: symbol.name,
                   address: symbol.address.toString(), error: String(error) });
        }
    });
    send({ event: 'lookup-hooks', count: hooked.size });
}

function hookJniCalls() {
    const art = Process.getModuleByName('libart.so');
    const hooked = new Set();
    art.enumerateSymbols().filter(function (symbol) {
        return symbol.name.indexOf('CallStaticVoidMethod') !== -1 ||
               symbol.name.indexOf('CallVoidMethod') !== -1;
    }).forEach(function (symbol) {
        const key = symbol.address.toString();
        if (hooked.has(key))
            return;
        hooked.add(key);
        Interceptor.attach(symbol.address, {
            onEnter(args) {
                if (jniCallCount >= 80)
                    return;
                const caller = describe(this.returnAddress);
                if (caller.module === 'libart.so')
                    return;
                jniCallCount++;
                const methodId = args[2].toString();
                send({
                    event: 'jni-call',
                    symbol: symbol.name,
                    methodId: methodId,
                    method: methods.get(methodId) || null,
                    caller: caller,
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0, 12).map(describe)
                });
            }
        });
    });
    send({ event: 'jni-hooks', count: hooked.size });
}

function hookWrites() {
    const libc = Process.getModuleByName('libc.so');
    const write = libc.getExportByName('write');
    Interceptor.attach(write, {
        onEnter(args) {
            const caller = describe(this.returnAddress);
            const count = args[2].toUInt32();
            if (caller.module !== 'libzyte.so' || count === 0 || count > 16384)
                return;
            let preview = null;
            try {
                const bytes = args[1].readByteArray(Math.min(count, 256));
                preview = Array.from(new Uint8Array(bytes)).map(function (value) {
                    return value >= 32 && value < 127
                        ? String.fromCharCode(value)
                        : '\\x' + value.toString(16).padStart(2, '0');
                }).join('');
            } catch (_) {}
            send({
                event: 'write',
                fd: args[0].toInt32(),
                count: count,
                preview: preview,
                caller: caller,
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 16).map(describe)
            });
        }
    });
    send({ event: 'write-hook', address: write.toString() });
}

Process.attachModuleObserver({
    onAdded(module) {
        if (module.name === 'libzyte.so')
            send({ event: 'module', module: module.name, path: module.path,
                   base: module.base.toString(), size: module.size });
    }
});

hookRegisterNatives();
hookJniLookups();
hookJniCalls();
hookWrites();
send({ event: 'ready' });
"""


def adb(*args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [ADB, "-s", SERIAL, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    existing = adb("shell", "pidof", "system_service").stdout.strip()
    if existing:
        raise RuntimeError(f"refusing to reuse unknown system_service PID(s): {existing}")

    server_pid: str | None = None
    session = None
    spawned_pid: int | None = None
    try:
        adb("shell", "am", "force-stop", PACKAGE)
        started = adb(
            "shell",
            f"su -c 'nohup {SERVER} -D -l 0.0.0.0:{SERVER_PORT} "
            ">/data/local/tmp/system_service.log 2>&1 &'",
        )
        if started.returncode != 0:
            raise RuntimeError(started.stderr.strip() or "server start failed")
        time.sleep(1.5)
        server_pid = adb("shell", "pidof", "system_service").stdout.strip()
        if not server_pid.isdigit():
            server_log = adb(
                "shell", "su", "-c", "cat /data/local/tmp/system_service.log"
            ).stdout.strip()
            raise RuntimeError(f"could not capture server PID; log={server_log!r}")

        for port in (SERVER_PORT, GADGET_PORT):
            result = adb("forward", f"tcp:{port}", f"tcp:{port}")
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"forward {port} failed")

        manager = frida.get_device_manager()
        injector = manager.add_remote_device(f"127.0.0.1:{SERVER_PORT}")
        spawned_pid = injector.spawn(PACKAGE)
        print(f"spawned={spawned_pid}", flush=True)
        injector.inject_library_file(spawned_pid, GADGET, "pthread_exit", "")
        time.sleep(0.6)

        gadget = manager.add_remote_device(f"127.0.0.1:{GADGET_PORT}")
        session = gadget.attach("Gadget")
        session.on(
            "detached",
            lambda reason, crash=None: print(
                f"detached reason={reason!r} crash={crash!r}", flush=True
            ),
        )
        script = session.create_script(TRACE_JS)
        script.on(
            "message",
            lambda message, data: print(
                str(message).encode("ascii", errors="backslashreplace").decode("ascii"),
                flush=True,
            ),
        )
        script.load()
        injector.resume(spawned_pid)
        time.sleep(5)
        return 0
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        adb("shell", "am", "force-stop", PACKAGE)
        for port in (SERVER_PORT, GADGET_PORT):
            adb("forward", "--remove", f"tcp:{port}")
        if server_pid is not None and server_pid.isdigit():
            adb(
                "shell",
                f"su -c 'kill {server_pid} 2>/dev/null || true'",
            )


if __name__ == "__main__":
    raise SystemExit(main())
