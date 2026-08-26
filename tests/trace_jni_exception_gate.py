"""Reproduce startup once with hook.js plus read-only JNI telemetry.

This is intentionally separate from the production loader.  It uses the same
file-backed Gadget path, loads ``jni_exception_diagnostic.js`` before the main
hook, resumes once, prints structured messages, and always force-stops the
diagnostic target during cleanup.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from loader import (
    GADGET_BIN,
    GADGET_PORT,
    PACKAGE_NAME,
    PROJECT_DIR,
    LoaderError,
    NXRTHConsole,
    adb_checked,
)


DIAGNOSTIC_PATH = PROJECT_DIR / "jni_exception_diagnostic.js"
HOOK_PATH = PROJECT_DIR / "hook.js"
CAPTURE_SECONDS = 8.0


def print_message(source: str, message: dict, data: bytes | None) -> None:
    record = {
        "source": source,
        "message": message,
    }
    if data is not None:
        record["dataLength"] = len(data)
    print(json.dumps(record, ensure_ascii=True, default=str), flush=True)


def load_script(console: NXRTHConsole, path: Path, source: str):
    if console.session is None:
        raise LoaderError("Gadget session is not attached")
    code = path.read_text(encoding="utf-8")
    script = console.session.create_script(code)
    script.on(
        "message",
        lambda message, data: print_message(source, message, data),
    )
    script.load()
    return script


def main() -> int:
    console = NXRTHConsole()
    diagnostic_script = None
    try:
        if not DIAGNOSTIC_PATH.is_file():
            raise LoaderError(f"diagnostic payload not found: {DIAGNOSTIC_PATH}")
        if not HOOK_PATH.is_file():
            raise LoaderError(f"main hook not found: {HOOK_PATH}")

        console.setup_adb()
        console.prepare_assets()
        console.ensure_server_dead()
        console.start_and_connect()

        adb_checked(
            console.adb,
            console.device_id,
            "shell",
            f"am force-stop {PACKAGE_NAME}",
        )
        console.pid = console.injector_device.spawn(PACKAGE_NAME)
        print(f"spawned={console.pid}", flush=True)
        console.injector_device.inject_library_file(
            console.pid,
            GADGET_BIN,
            "pthread_exit",
            "",
        )

        console._add_forward(GADGET_PORT)
        console.gadget_device = console._connect_remote(GADGET_PORT, "Gadget")
        console.session = console.gadget_device.attach("Gadget")
        console.session.on("detached", console._on_detached)

        # Load telemetry first so ExceptionCheck entry is captured independently
        # of the main hook's onLeave return-value edit.
        diagnostic_script = load_script(
            console,
            DIAGNOSTIC_PATH,
            "jni-diagnostic",
        )
        console.script = load_script(console, HOOK_PATH, "hook")

        console.injector_device.resume(console.pid)
        console.resumed = True
        console._release_injector()

        deadline = time.monotonic() + CAPTURE_SECONDS
        while time.monotonic() < deadline and not console.detached.wait(0.1):
            pass
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"diagnostic failed: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        if diagnostic_script is not None:
            try:
                if not diagnostic_script.is_destroyed:
                    diagnostic_script.unload()
            except Exception:
                pass
        console.cleanup(stop_game=True)


if __name__ == "__main__":
    raise SystemExit(main())
