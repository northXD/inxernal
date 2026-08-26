import frida
import json
import os
import queue
import random
import re
import time
import shlex
import socket
import struct
import subprocess
import threading
from pathlib import Path

PACKAGE_NAME = "com.supercell.hayday"
PROJECT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = PROJECT_DIR / "hook.js"
JAVA_GUARD_PATH = PROJECT_DIR / "java_guard.bundle.js"
QUAGO_PROBE_PATH = PROJECT_DIR / "quago_probe.bundle.js"   # frida-compiled (Java bridge); bare .js can't hook Java
GADGET_CONFIG_PATH = PROJECT_DIR / "gadget.config.json"
ASSET_VAULT = "/data/adb/nxrth-assets"
FRIDA_BIN = f"{ASSET_VAULT}/.service"
GADGET_VAULT = f"{ASSET_VAULT}/libmetrics.so"
APP_DATA_DIR = f"/data/user/0/{PACKAGE_NAME}"
RUNTIME_GADGET_DIR = f"{APP_DATA_DIR}/files/metrics"
GADGET_BIN = f"{RUNTIME_GADGET_DIR}/libmetrics.so"
CONFIG_STAGE_PATH = "/data/local/tmp/.nxrth-libmetrics.config.so"
# Native engine module (aarch64) built by native/build.ps1. Loaded into the app
# via its own ART loader (System.load routes ARM libs through the native bridge).
MODULE_LOCAL = PROJECT_DIR / "native" / "build" / "libnxrth.so"
MODULE_REMOTE = f"{APP_DATA_DIR}/files/libnxrth.so"
MODULE_STAGE = "/data/local/tmp/.nxrth-libnxrth.so"
INJECTOR_OAT_DIR = "/data/local/tmp/oat"
SERVER_LOG = "/data/local/tmp/.nxrth-server.log"
FRIDA_SHA256 = "b13013c5fb19b01dc81fed1cd9b517b10681240c63d8111167e9df50fb0a0d18"
GADGET_SHA256 = "cfd21e76394bcf86481707754720c3d279016066e71aadeeef26d6ecdff4f981"
FRIDA_PORT = 31337
GADGET_PORT = 31338
CONNECT_TIMEOUT = 12.0
RESUME_TIMEOUT = 5.0
ENGINE_TIMEOUT = 90.0
RPC_TIMEOUT = 5.0
STABILITY_WINDOW = 5.0

HELPER_RESIDUE_PATTERN = re.compile(
    r"/data/local/tmp/(?:frida-[0-9a-fA-F]{32}|"
    r"frida-helper-[A-Za-z0-9][A-Za-z0-9._-]*|"
    r"\.frida-[A-Za-z0-9][A-Za-z0-9._-]*)\Z"
)

ADB_SEARCH_PATHS = [
    r"C:\LDPlayer\LDPlayer9\adb.exe",
    r"C:\LDPlayer\LDPlayer14\adb.exe",
    r"C:\Program Files\Genymobile\Genymotion\tools\adb.exe",
    "adb",
]


def find_adb():
    for p in ADB_SEARCH_PATHS:
        try:
            result = subprocess.run([p, "version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return p
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return None


def find_emulator(adb):
    try:
        result = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=5)
        devices = []
        for line in result.stdout.strip().split("\n")[1:]:
            line = line.strip()
            if not line or "offline" in line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        for d in devices:
            if "127.0.0.1" in d:
                return d
        for d in devices:
            if "emulator" in d:
                return d
        if devices:
            return devices[0]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


class LoaderError(RuntimeError):
    pass


def adb_cmd(adb, device_id, *args, timeout=10):
    return subprocess.run(
        [adb, "-s", device_id] + list(args),
        capture_output=True, text=True, timeout=timeout
    )


def adb_checked(adb, device_id, *args, timeout=10):
    try:
        result = adb_cmd(adb, device_id, *args, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as error:
        raise LoaderError(f"adb command failed: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LoaderError(f"adb {' '.join(args)} failed: {detail or 'unknown error'}")
    return result


def su_command(adb, device_id, command, *, check=True, timeout=10):
    args = ("shell", f"su -c {shlex.quote(command)}")
    if check:
        return adb_checked(adb, device_id, *args, timeout=timeout)
    try:
        return adb_cmd(adb, device_id, *args, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def find_game_pids(adb, device_id):
    try:
        result = adb_cmd(adb, device_id, "shell", f"pidof {PACKAGE_NAME}")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as error:
        raise LoaderError(f"could not query game PID: {error}") from error
    # Android pidof returns 1 when the process is simply absent.
    if result.returncode not in (0, 1):
        detail = (result.stderr or result.stdout).strip()
        raise LoaderError(f"could not query game PID: {detail or 'adb shell failed'}")
    pids = set()
    for pid_str in result.stdout.split():
        try:
            pids.add(int(pid_str))
        except ValueError:
            pass
    return pids


def gadget_config_remote_path(gadget_path):
    if gadget_path.endswith(".so"):
        return gadget_path[:-3] + ".config.so"
    return gadget_path + ".config"


class NXRTHConsole:
    def __init__(self):
        self.manager = None
        self.injector_device = None
        self.gadget_device = None
        self.session = None
        self.script = None
        self.guard_script = None
        self.probe_script = None
        self.pid = None
        self.pid_starttime = None
        self.adb = None
        self.device_id = None
        self.app_uid = None
        self.app_context = None
        self.server_exe = FRIDA_BIN
        self.server_pids = set()
        self.helper_residues_before = None
        self.server_start_attempted = False
        self.forwarded_ports = {}
        self.gadget_config_remote = gadget_config_remote_path(GADGET_BIN)
        self.detached = threading.Event()
        self.script_failed = threading.Event()
        self.detached_reason = None
        self.crash = None
        self.script_error = None
        self.closing = False
        self.resumed = False
        self.resume_barrier_complete = False
        self.spawn_owned = False
        self.startup_complete = False
        self.scan_results = []
        self.scan_type = None
        self.cmdlog_mbox = None
        self.engine_base = None
        self.plant_mbox = None
        self.plant_cave = None
        self.plant_F = None
        self.plant_base = None
        self.sell_mbox = None
        self.sell_cave = None
        self.sell_F = None
        self.nat_base = None
        self.nat_mbox = None
        self.nat_cave = None
        self.nat_F = None
        self._cached_field_path = None
        self.field_vtable_off = None
        self.current_fields = []
        # --- external control channel (TCP GUI driver) ---
        self._cmd_lock = threading.Lock()   # serializes native cmds across CLI + socket + farm
        self._farm_thread = None
        self._farm_stop = threading.Event()
        self._control_srv = None

    def on_message(self, message, data):
        message_type = message.get("type")
        if message_type == "send":
            print(f"  {message.get('payload')}")
        elif message_type == "error":
            self.script_error = message.get("stack") or message.get("description") or str(message)
            self.script_failed.set()
            print(f"  [ERROR] {self.script_error}")

    def _on_guard_message(self, message, data):
        # The SHIELD guard runs as an independent script. Its errors must be
        # logged but MUST NOT trip self.script_failed (that Event gates all
        # hook.js RPC via _attached()); a guard hiccup should never break
        # automation.
        message_type = message.get("type")
        if message_type == "send":
            print(f"  {message.get('payload')}")
        elif message_type == "error":
            detail = message.get("stack") or message.get("description") or str(message)
            print(f"  [JAVA-GUARD ERROR] {detail}")

    def _on_detached(self, reason, crash=None):
        self.detached_reason = reason
        self.crash = crash
        self.detached.set()
        if self.closing:
            return
        print(f"\n[!] Detached: {reason}")
        if crash is not None:
            print(f"[!] Crash: {crash}")
        if reason == "process-terminated":
            print("[!] Game crashed or was killed by anti-cheat")

    def setup_adb(self):
        self.adb = find_adb()
        if not self.adb:
            raise LoaderError("adb not found")
        print(f"[+] ADB: {self.adb}")

        self.device_id = find_emulator(self.adb)
        if not self.device_id:
            raise LoaderError("No device found. Start LDPlayer first.")
        print(f"[+] Device: {self.device_id}")

    def _remote_realpath(self, path):
        result = su_command(
            self.adb, self.device_id, f"readlink -f {shlex.quote(path)}", check=False
        )
        if result is None or result.returncode != 0:
            return path
        return result.stdout.strip() or path

    def _remote_sha256(self, path):
        result = su_command(
            self.adb,
            self.device_id,
            f"sha256sum {shlex.quote(path)}",
            check=False,
            timeout=30,
        )
        if result is None or result.returncode != 0:
            raise LoaderError(f"could not hash remote asset: {path}")
        digest = result.stdout.split(maxsplit=1)[0].lower() if result.stdout else ""
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LoaderError(f"invalid SHA-256 output for remote asset: {path}")
        return digest

    def _process_exe(self, pid):
        result = su_command(
            self.adb, self.device_id, f"readlink /proc/{int(pid)}/exe 2>/dev/null", check=False
        )
        if result is None or result.returncode != 0:
            return None
        return result.stdout.strip().removesuffix(" (deleted)") or None

    def _pid_exists(self, pid):
        result = su_command(
            self.adb,
            self.device_id,
            f"test -d /proc/{int(pid)}",
            check=False,
        )
        if result is None:
            raise LoaderError(f"could not check PID {int(pid)}")
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        detail = (result.stderr or result.stdout).strip()
        raise LoaderError(
            f"could not check PID {int(pid)}: {detail or 'remote test failed'}"
        )

    def _pid_starttime(self, pid):
        if not self._pid_exists(pid):
            return None
        result = su_command(
            self.adb,
            self.device_id,
            f"cat /proc/{int(pid)}/stat",
            check=False,
        )
        if result is None:
            raise LoaderError(f"could not fingerprint PID {int(pid)}")
        if result.returncode != 0:
            if not self._pid_exists(pid):
                return None
            detail = (result.stderr or result.stdout).strip()
            raise LoaderError(
                f"could not fingerprint PID {int(pid)}: "
                f"{detail or 'remote stat read failed'}"
            )
        stat = result.stdout.strip()
        comm_end = stat.rfind(")")
        fields = stat[comm_end + 2:].split() if comm_end >= 0 else []
        if len(fields) < 20 or re.fullmatch(r"[0-9]+", fields[19]) is None:
            raise LoaderError(f"invalid /proc stat for PID {int(pid)}")
        return fields[19]

    def _owned_game_alive(self):
        if self.pid is None or self.pid_starttime is None:
            return False
        return self._pid_starttime(self.pid) == self.pid_starttime

    def _matching_server_pids(self):
        process_name = FRIDA_BIN.rsplit("/", 1)[-1]
        result = adb_cmd(self.adb, self.device_id, "shell", f"pidof {process_name}")
        if result.returncode not in (0, 1):
            detail = (result.stderr or result.stdout).strip()
            raise LoaderError(
                f"could not query injector server PID: {detail or 'adb shell failed'}"
            )
        matches = set()
        for value in result.stdout.split():
            try:
                pid = int(value)
            except ValueError:
                continue
            if self._process_exe(pid) == self.server_exe:
                matches.add(pid)
        return matches

    def _stop_server_pids(self, pids, force=False):
        owned = {pid for pid in pids if self._process_exe(pid) == self.server_exe}
        initially_owned = set(owned)
        for pid in sorted(owned):
            signal = "kill -9" if force else "kill"
            su_command(self.adb, self.device_id, f"{signal} {pid}", check=False)

        deadline = time.monotonic() + (1.0 if force else 2.0)
        while owned and time.monotonic() < deadline:
            owned = {pid for pid in owned if self._process_exe(pid) == self.server_exe}
            if owned:
                time.sleep(0.05 if force else 0.1)

        if not force:
            for pid in sorted(owned):
                if self._process_exe(pid) == self.server_exe:
                    su_command(self.adb, self.device_id, f"kill -9 {pid}", check=False)

        deadline = time.monotonic() + 1.0
        while owned and time.monotonic() < deadline:
            owned = {pid for pid in owned if self._process_exe(pid) == self.server_exe}
            if owned:
                time.sleep(0.05)
        self.server_pids.difference_update(initially_owned - owned)
        return owned

    def ensure_server_dead(self):
        existing = self._matching_server_pids()
        if existing:
            print(f"[*] Stopping existing project server PID(s): {', '.join(map(str, sorted(existing)))}")
            self._stop_server_pids(existing)
        if self._matching_server_pids():
            raise LoaderError("existing injector server could not be stopped")
        print("[+] Clean state (no server)")

    def _resolve_package_uid(self):
        result = su_command(
            self.adb,
            self.device_id,
            f"stat -c %u {shlex.quote(APP_DATA_DIR)}",
            check=False,
        )
        if result is not None and result.returncode == 0:
            value = result.stdout.strip()
            if re.fullmatch(r"[0-9]+", value) and int(value) > 0:
                return int(value)

        queries = (
            f"pm list packages -U {shlex.quote(PACKAGE_NAME)}",
            f"dumpsys package {shlex.quote(PACKAGE_NAME)}",
        )
        for command in queries:
            try:
                result = adb_cmd(self.adb, self.device_id, "shell", command)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
            if result.returncode != 0:
                continue
            match = re.search(r"(?:\buid:|\buserId=)([0-9]+)\b", result.stdout)
            if match is not None and int(match.group(1)) > 0:
                return int(match.group(1))
        raise LoaderError(f"could not resolve package UID for {PACKAGE_NAME}")

    def _remote_context(self, path):
        commands = (
            f"stat -c %C {shlex.quote(path)}",
            f"ls -Zd {shlex.quote(path)}",
        )
        context_pattern = re.compile(
            r"u:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_:,.-]+"
        )
        for command in commands:
            result = su_command(
                self.adb, self.device_id, command, check=False
            )
            if result is None or result.returncode != 0:
                continue
            match = context_pattern.search(result.stdout)
            if match is not None:
                return match.group(0)
        return None

    def _resolve_app_context(self):
        context = self._remote_context(APP_DATA_DIR)
        if context is not None:
            return context
        raise LoaderError(f"could not resolve SELinux context for {APP_DATA_DIR}")

    def _verify_runtime_path(self, path, expected_mode, *, directory=False):
        kind_test = "-d" if directory else "-s"
        exists = su_command(
            self.adb,
            self.device_id,
            f"test {kind_test} {shlex.quote(path)}",
            check=False,
        )
        if exists is None or exists.returncode != 0:
            raise LoaderError(f"staged runtime asset is missing: {path}")

        result = su_command(
            self.adb,
            self.device_id,
            f"stat -c '%u %a' {shlex.quote(path)}",
            check=False,
        )
        if result is None or result.returncode != 0:
            raise LoaderError(f"could not verify staged runtime asset: {path}")
        fields = result.stdout.strip().split()
        if len(fields) != 2:
            raise LoaderError(f"unexpected stat output for staged runtime asset: {path}")
        uid, mode = fields
        context = self._remote_context(path)
        if uid != str(self.app_uid) or mode != expected_mode or context != self.app_context:
            raise LoaderError(
                f"invalid owner/mode/context for {path}: "
                f"uid={uid}, mode={mode}, context={context}"
            )

    def _stage_runtime_gadget(self):
        self.app_uid = self._resolve_package_uid()
        self.app_context = self._resolve_app_context()
        gadget_tmp = GADGET_BIN + ".nxrth-tmp"
        config_tmp = self.gadget_config_remote + ".nxrth-tmp"

        adb_checked(
            self.adb,
            self.device_id,
            "push",
            str(GADGET_CONFIG_PATH),
            CONFIG_STAGE_PATH,
            timeout=15,
        )
        try:
            uid = self.app_uid
            context = shlex.quote(self.app_context)
            paths = " ".join(
                shlex.quote(path)
                for path in (RUNTIME_GADGET_DIR, gadget_tmp, config_tmp)
            )
            final_paths = " ".join(
                shlex.quote(path)
                for path in (GADGET_BIN, self.gadget_config_remote)
            )
            command = " && ".join((
                f"rm -f {shlex.quote(gadget_tmp)} {shlex.quote(config_tmp)}",
                f"mkdir -p {shlex.quote(RUNTIME_GADGET_DIR)}",
                f"cp -f {shlex.quote(GADGET_VAULT)} {shlex.quote(gadget_tmp)}",
                f"cp -f {shlex.quote(CONFIG_STAGE_PATH)} {shlex.quote(config_tmp)}",
                f"chown {uid}:{uid} {paths}",
                f"chmod 0700 {shlex.quote(RUNTIME_GADGET_DIR)}",
                f"chmod 0500 {shlex.quote(gadget_tmp)}",
                f"chmod 0400 {shlex.quote(config_tmp)}",
                f"chcon {context} {paths}",
                f"mv -f {shlex.quote(gadget_tmp)} {shlex.quote(GADGET_BIN)}",
                f"mv -f {shlex.quote(config_tmp)} {shlex.quote(self.gadget_config_remote)}",
                f"chown {uid}:{uid} {final_paths}",
                f"chmod 0500 {shlex.quote(GADGET_BIN)}",
                f"chmod 0400 {shlex.quote(self.gadget_config_remote)}",
                f"chcon {context} {final_paths}",
            ))
            su_command(self.adb, self.device_id, command, timeout=20)
        finally:
            su_command(
                self.adb,
                self.device_id,
                f"rm -f {shlex.quote(CONFIG_STAGE_PATH)} "
                f"{shlex.quote(gadget_tmp)} {shlex.quote(config_tmp)}",
                check=False,
            )

        self._verify_runtime_path(RUNTIME_GADGET_DIR, "700", directory=True)
        self._verify_runtime_path(GADGET_BIN, "500")
        self._verify_runtime_path(self.gadget_config_remote, "400")
        staged_digest = self._remote_sha256(GADGET_BIN)
        if staged_digest != GADGET_SHA256:
            raise LoaderError(
                f"staged Gadget SHA-256 mismatch: expected {GADGET_SHA256}, "
                f"got {staged_digest}"
            )
        print(
            f"[+] Runtime Gadget staged for UID {self.app_uid}: {GADGET_BIN}"
        )

    def _stage_native_module(self):
        """Push the aarch64 engine module into the app's files dir with app
        ownership + SELinux context so the app's own ART loader can load it
        (mirrors the gadget staging in _stage_runtime_gadget)."""
        if not MODULE_LOCAL.is_file():
            raise LoaderError(f"native module not built: {MODULE_LOCAL} "
                              f"(run native/build.ps1)")
        if not getattr(self, "app_uid", None):
            self.app_uid = self._resolve_package_uid()
        if not getattr(self, "app_context", None):
            self.app_context = self._resolve_app_context()
        uid = self.app_uid
        context = shlex.quote(self.app_context)
        files_dir = f"{APP_DATA_DIR}/files"
        tmp = MODULE_REMOTE + ".nxrth-tmp"
        adb_checked(self.adb, self.device_id, "push", str(MODULE_LOCAL),
                    MODULE_STAGE, timeout=30)
        # Write a temp file and rename it into place. Copying ONTO the live path
        # would rewrite a .so that is currently mmap'd into the game, corrupting
        # its code pages (instant freeze/crash); rename swaps the directory entry
        # and leaves existing mappings on the old inode untouched.
        command = " && ".join((
            f"mkdir -p {shlex.quote(files_dir)}",
            f"rm -f {shlex.quote(tmp)}",
            f"cp -f {shlex.quote(MODULE_STAGE)} {shlex.quote(tmp)}",
            f"chown {uid}:{uid} {shlex.quote(tmp)}",
            f"chmod 0500 {shlex.quote(tmp)}",
            f"chcon {context} {shlex.quote(tmp)}",
            f"mv -f {shlex.quote(tmp)} {shlex.quote(MODULE_REMOTE)}",
        ))
        su_command(self.adb, self.device_id, command, timeout=20)
        su_command(self.adb, self.device_id,
                   f"rm -f {shlex.quote(MODULE_STAGE)}", check=False)
        self._verify_runtime_path(MODULE_REMOTE, "500")
        print(f"[+] native module staged: {MODULE_REMOTE}")

    def cmd_loadnative(self, args):
        """Phase 1 bootstrap: stage libnxrth.so into the app, then load it via the
        app's ART loader (System.load -> native bridge -> Houdini, the same route
        libg.so takes). Confirms via logcat that the module's constructor ran
        nx_init in-process."""
        # Already resident? Re-staging would rewrite the mapped .so and reloading
        # is a no-op for the linker, so just re-resolve the mailbox and stop.
        # A new build needs a fresh game process (loadnative after a restart).
        if self._native_module_base() and "force" not in [a.lower() for a in args]:
            self._ensure_native_mbox()
            print(f"  native module already loaded at 0x{self._native_module_base():x} "
                  f"(mailbox 0x{self.nat_mbox:x}).")
            print("  Restart the game + loader to pick up a NEW build "
                  "('loadnative force' to stage anyway).")
            return
        enforce = su_command(self.adb, self.device_id, "getenforce", check=False)
        if enforce and enforce.stdout:
            print(f"  SELinux: {enforce.stdout.strip()}")
        try:
            binfo = self._rpc("bridgeinfo", timeout=10.0)
            print(f"  bridge: mods={binfo.get('modules')} ext={binfo.get('hasExt')} "
                  f"vendorNs={binfo.get('hasVendorNs')} capturedNs={binfo.get('capturedNs')}")
            if binfo.get("capturedFrom"):
                print(f"  captured ns from: {binfo['capturedFrom']}")
            if not binfo.get("capturedNs") and binfo.get("loads"):
                print(f"  bridge loads seen: {binfo['loads'][:12]}")
        except LoaderError as err:
            print(f"  (bridgeinfo unavailable: {err})")
        self._stage_native_module()
        su_command(self.adb, self.device_id, "logcat -c", check=False)
        res = self._rpc("loadmodule", MODULE_REMOTE, timeout=25.0)
        print(f"  loadmodule -> {res}")
        time.sleep(0.7)
        log = adb_cmd(self.adb, self.device_id, "shell",
                      "logcat -d -s NXRTH:V", timeout=10)
        lines = [ln for ln in (log.stdout or "").splitlines() if "NXRTH" in ln]
        if lines:
            print("  --- module logcat (NXRTH) ---")
            for ln in lines[-12:]:
                print("   " + ln)
            if any("nx_init: OK" in ln for ln in lines):
                print("  >>> MODULE LIVE: native engine resident in-process.")
        else:
            print("  (no NXRTH logcat - load may have failed; see error above)")

    def _elf_dynsyms(self, path):
        """Minimal ELF64 .dynsym parser -> {name: value(RVA)}. Reads the freshly
        built module's nx_mailbox / nx_on_tick RVAs without an external tool
        (they change every build)."""
        data = path.read_bytes()
        if data[:4] != b"\x7fELF":
            return {}
        u = lambda fmt, off: struct.unpack_from(fmt, data, off)[0]
        e_shoff = u("<Q", 0x28)
        e_shentsize = u("<H", 0x3a)
        e_shnum = u("<H", 0x3c)
        secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            secs.append((u("<I", o + 4), u("<Q", o + 0x18), u("<Q", o + 0x20),
                         u("<I", o + 0x28), u("<Q", o + 0x38)))
        dynsym = dynstr = None
        for st, so, ss, sl, se in secs:
            if st == 11 and sl < len(secs):          # SHT_DYNSYM
                dynsym = (so, ss, se)
                dynstr = (secs[sl][1], secs[sl][2])
                break
        if not dynsym or not dynstr:
            return {}
        so, ss, se = dynsym
        stroff = dynstr[0]
        syms = {}
        for i in range(ss // se if se else 0):
            e = so + i * se
            st_name = u("<I", e)
            st_value = u("<Q", e + 8)
            end = data.index(b"\x00", stroff + st_name)
            name = data[stroff + st_name:end].decode("ascii", "replace")
            if name:
                syms[name] = st_value
        return syms

    def _native_module_base(self):
        res = su_command(self.adb, self.device_id,
                         f"cat /proc/{int(self.pid)}/maps", check=False, timeout=15)
        if not res or res.returncode != 0:
            return 0
        for line in res.stdout.splitlines():
            if "libnxrth.so" in line:
                try:
                    return int(line.split("-", 1)[0], 16)
                except ValueError:
                    return 0
        return 0

    def _build_bridge_cave(self, on_tick_abs, stolen, fabs):
        """Cave on the tick that just calls the native module's on_tick(x0=
        GameMode) and continues. Saves x0 (GameMode) + x30 (return) around the
        call; the rest are caller-saved and the tick prologue re-establishes
        them. All real work happens natively inside on_tick."""
        prog = []
        def emit(x):
            prog.append(x & 0xFFFFFFFF)
        def li(rd, v):
            for w in self._le_words(self._load_imm64(rd, v)):
                emit(w)
        emit(0xD1000000 | (0x20 << 10) | (31 << 5) | 31)   # sub sp,sp,#0x20
        emit(0xA9000000 | (30 << 10) | (31 << 5) | 0)      # stp x0,x30,[sp]
        li(16, on_tick_abs)                                # x16 = on_tick
        emit(0xD63F0000 | (16 << 5))                       # blr x16 (x0=GameMode)
        emit(0xA9400000 | (30 << 10) | (31 << 5) | 0)      # ldp x0,x30,[sp]
        emit(0x91000000 | (0x20 << 10) | (31 << 5) | 31)   # add sp,sp,#0x20
        for i in range(0, 16, 4):
            emit(int.from_bytes(stolen[i:i + 4], "little"))  # stolen tick prologue
        emit(0x58000051)                                   # ldr x17,#8
        emit(0xD61F0220)                                   # br x17
        code = b"".join(struct.pack("<I", w) for w in prog)
        code += struct.pack("<Q", fabs + 16)
        return code

    def _install_native_gate(self):
        base = self._native_module_base()
        if not base:
            raise LoaderError("native module not loaded (run 'loadnative' first)")
        syms = self._elf_dynsyms(MODULE_LOCAL)
        if "nx_mailbox" not in syms or "nx_on_tick" not in syms:
            raise LoaderError("module missing nx_mailbox/nx_on_tick exports")
        libg = int(str(self._rpc("info")["base"]), 0)
        self.plant_base = libg
        F = 0x00ae2430
        fabs = libg + F
        on_tick_abs = base + syms["nx_on_tick"]
        self.nat_base = base
        self.nat_mbox = base + syms["nx_mailbox"]
        self.nat_F = F
        # Prefer the clean prologue the module captured at load - immune to a
        # leftover gate from an old plant/harvest command. Fall back to reading
        # the tick directly (waits out Promon's revert) only if that's unusable.
        raw = self._rpc("readabs", f"0x{self.nat_mbox + 0x538:x}", 16)
        stolen = bytes(raw)[:16] if raw and len(raw) >= 16 else b""
        if len(stolen) != 16 or not self._stolen_is_pi(stolen):
            stolen = self._read_stolen(F)
        if not stolen or len(stolen) != 16 or not self._stolen_is_pi(stolen):
            raise LoaderError("tick prologue not relocatable")
        cave = self._rpc("alloccave", 256)
        self._rpc("writeabs", cave,
                  list(self._build_bridge_cave(on_tick_abs, stolen, fabs)))
        self.nat_cave = cave
        self.nat_stolen = stolen           # clean 16-byte tick prologue, for disarm
        print(f"  native gate: module@0x{base:x} mailbox@0x{self.nat_mbox:x} "
              f"on_tick@0x{on_tick_abs:x}")

    def _disarm_native_gate(self):
        """Restore the clean tick prologue + flush the guest translation, so the
        farjump does NOT sit on the tick between commands. Promon SHIELD does
        byte-level integrity sweeps and freezes the game when it finds the tick
        patched; leaving it armed only during the sub-second command window (and
        clean while idle) is what keeps the game alive. Mirrors _arm_hook's
        GOT-trampoline flush, but writes back the ORIGINAL bytes."""
        stolen = getattr(self, "nat_stolen", None)
        if not stolen or self.nat_F is None or not getattr(self, "plant_base", None):
            return
        base = self.plant_base
        fabs = base + self.nat_F
        try:
            self._rpc("writeabs", f"0x{fabs:x}", list(stolen))     # un-patch the tick
            got_abs = base + 0x015057f0
            got_s = f"0x{got_abs:x}"
            orig_i = int.from_bytes(bytes(self._rpc("readabs", got_s, 8)), "little")
            fc = self._load_imm64(16, fabs)
            fc += struct.pack("<I", 0xD50B7B20 | 16)   # dc cvau, x16
            fc += struct.pack("<I", 0xD5033B9F)         # dsb ish
            fc += struct.pack("<I", 0xD50B7520 | 16)   # ic ivau, x16
            fc += struct.pack("<I", 0xD5033B9F)
            fc += struct.pack("<I", 0xD5033FDF)         # isb
            fc += struct.pack("<I", 0x58000051)         # ldr x17,#8
            fc += struct.pack("<I", 0xD61F0220)         # br x17
            fc += struct.pack("<Q", orig_i)
            fcave = self._rpc("alloccave", 64)
            self._rpc("writeabs", fcave, list(fc))
            self._rpc("writeabs", got_s, list(struct.pack("<Q", int(fcave, 0))))
            time.sleep(0.2)                             # let the hooked fn flush fabs once
            self._rpc("writeabs", got_s, list(struct.pack("<Q", orig_i)))
        except Exception:
            pass

    def _native_cmd(self, cmd_id, arg0=0, ids=None, timeout=4.0):
        """Arm the bridge cave, optionally hand the module a list of field ids
        (mailbox.ids + arg1), write the command, wait for on_tick to clear it,
        return the result count (mailbox+0x14)."""
        if not getattr(self, "nat_cave", None):
            self._install_native_gate()
        m = self.nat_mbox
        if ids is not None:
            ids = ids[:128]
            self._rpc("writeabs", f"0x{m + 0x28:x}",
                      list(b"".join(struct.pack("<I", i) for i in ids)))
            self._rpc("writeabs", f"0x{m + 0x0c:x}", list(struct.pack("<I", len(ids))))  # arg1
        self._rpc("writeabs", f"0x{m + 0x08:x}", list(struct.pack("<I", arg0 & 0xFFFFFFFF)))
        self._rpc("writeabs", f"0x{m + 0x04:x}", list(struct.pack("<I", cmd_id)))
        # Promon reverts the inline patch after ~1.5s, so a single arm can lose
        # the race; re-arm and keep polling until the module clears the command.
        # ALWAYS disarm afterwards (restore the clean tick) so the patch never
        # sits idle on the tick where Promon's sweep freezes the game.
        result = None
        deadline = time.monotonic() + timeout
        while result is None and time.monotonic() < deadline:
            self._arm_hook(self.nat_F, self.nat_cave, f"0x{m:x}")
            for _ in range(8):
                time.sleep(0.1)
                c = int.from_bytes(bytes(self._rpc("readabs", f"0x{m + 0x04:x}", 4)), "little")
                if c == 0:
                    result = int.from_bytes(
                        bytes(self._rpc("readabs", f"0x{m + 0x14:x}", 4)), "little")
                    break
        if result is None:
            self._rpc("writeabs", f"0x{m + 0x04:x}", list(struct.pack("<I", 0)))  # clear stale cmd
            print("  native cmd timed out (gate not running - in the farm?).")
        self._disarm_native_gate()
        return result

    def _native_ids(self, count):
        count = min(count, 128)
        raw = self._rpc("readabs", f"0x{self.nat_mbox + 0x28:x}", count * 4)
        if not raw:
            return []
        b = bytes(raw)
        return [int.from_bytes(b[i * 4:i * 4 + 4], "little") for i in range(count)]

    def cmd_nping(self, args):
        c = self._native_cmd(1)
        if c is not None:
            print(f"  nping -> count=0x{c:x} (expect 0xabcd) "
                  f"{'OK' if c == 0xABCD else 'MISMATCH'}")

    def cmd_ndiag(self, args):
        n = self._native_cmd(2)
        if n is None:
            return
        ids = self._native_ids(min(n * 4, 128))
        print(f"  ndiag: {n} field-holder / manager object(s) within 2 hops of gm/level")
        for k in range(min(n, 30)):
            if 4 * k + 3 >= len(ids):
                break
            key, o2, vt, fc = ids[4 * k], ids[4 * k + 1], ids[4 * k + 2], ids[4 * k + 3]
            src = "gm" if (key >> 28) == 0 else "level"
            o1 = key & 0x0FFFFFFF
            path = f"{src}+0x{o1:x}" if o2 == 0xFFFFFFFF else f"{src}+0x{o1:x}+0x{o2:x}"
            tag = " [MGR]" if vt == 0x14ba5b0 else (" [FIELD]" if vt == self.FIELD_VTABLE_OFF else "")
            if fc:
                tag += f"  <<< HOLDS {fc} FIELDS"
            print(f"   {path:22s} -> vt+0x{vt:07x} fc={fc}{tag}")

    def _ensure_native_mbox(self):
        """Resolve the module base + nx_mailbox address (no cave needed) so read
        -only commands can poll the background-maintained field list."""
        if getattr(self, "nat_mbox", None):
            return True
        base = self._native_module_base()
        if not base:
            print("  [!] native module not loaded (run 'loadnative' first).")
            return False
        syms = self._elf_dynsyms(MODULE_LOCAL)
        if "nx_mailbox" not in syms:
            print("  [!] module missing nx_mailbox export.")
            return False
        self.nat_base = base
        self.nat_mbox = base + syms["nx_mailbox"]
        return True

    def _native_scan_ids(self, timeout=8.0):
        """Ask the module for a fresh field scan and read the result. The scan
        runs on the module's own thread (never the game thread) and only when
        requested - scanning continuously is heavy enough to freeze the game."""
        if not self._ensure_native_mbox():
            return None, 0, 0, 0
        m = self.nat_mbox
        rd = lambda o: int.from_bytes(bytes(self._rpc("readabs", f"0x{m + o:x}", 4)), "little")
        gen0 = rd(0x22c)
        self._rpc("writeabs", f"0x{m + 0x548:x}",
                  list(struct.pack("<I", (rd(0x548) + 1) & 0xFFFFFFFF)))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.1)
            if rd(0x22c) != gen0:
                break
        cnt, gen, ms, seen = rd(0x228), rd(0x22c), rd(0x230), rd(0x234)
        cnt = min(cnt, 192)
        raw = self._rpc("readabs", f"0x{m + 0x238:x}", cnt * 4) if cnt else None
        ids = sorted(int.from_bytes(bytes(raw)[i * 4:i * 4 + 4], "little")
                     for i in range(cnt)) if raw else []
        return ids, gen, ms, seen

    def _native_refresh_ranges(self, timeout=2.5):
        """Ask the module to refresh its /proc/self/maps snapshot OFF the game
        thread, so is_readable() is current for the in-process container read
        (otherwise every crash-safe read short-circuits to 0). Bumps scan_req and
        waits for scan_gen to advance. No memory scan happens. Returns True if the
        refresh completed (module + range thread present)."""
        if not self._ensure_native_mbox():
            return False
        m = self.nat_mbox
        rd = lambda o: int.from_bytes(bytes(self._rpc("readabs", f"0x{m + o:x}", 4)), "little")
        gen0 = rd(0x22c)
        self._rpc("writeabs", f"0x{m + 0x548:x}",
                  list(struct.pack("<I", (rd(0x548) + 1) & 0xFFFFFFFF)))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.05)
            if rd(0x22c) != gen0:
                return True
        return False

    def _field_ids(self, verbose=True):
        """Field ids for the native commands, enumerated by the native module
        reading the game's OWN object list in-process (CMD_FIELDS) - not by
        scraping raw heap. A vector<Field*> holds pointers, so fields scattered
        across separate heap blocks are all found; the module writes the live ids
        into mailbox.ids and we read them back. If the native path yields nothing
        plausible we fall back to the legacy RPC field walk so a transient state
        never leaves commands blind."""
        self._native_refresh_ranges()   # make is_readable current for the in-process read
        n = self._native_cmd(3)   # CMD_FIELDS: module enumerates, writes ids[] + count
        if n is None:
            if verbose:
                print("  [!] native gate not live (open the farm and retry).")
            return []
        ids = sorted(set(self._native_ids(n))) if n else []
        if not ids:
            # Gate is live but the container wasn't resolvable in this state: fall
            # back to the old RPC heap walk from the gate's captured gameMode.
            gm = self._read_u64(self.nat_mbox + 0x20)
            ids = self._enumerate_fields(gm) if gm else []
            if ids and verbose:
                print("  (native container empty; used RPC-walk fallback)")
        # Sanity gate: the farm's field count is fixed, so a sudden jump means a
        # bad read (mixed generations / stale objects). Firing commands at fields
        # that don't exist is what hung the game, so refuse instead of guessing.
        prev = getattr(self, "_last_field_count", 0)
        if prev and ids and not (0.5 * prev <= len(ids) <= 1.5 * prev):
            print(f"  [!] enumeration returned {len(ids)} field(s) but the farm had "
                  f"{prev}; ignoring this read (retry in a moment).")
            return []
        if ids:
            self._last_field_count = len(ids)
        if verbose:
            rng = f" [{ids[0]}..{ids[-1]}]" if ids else "  (none found - in the farm?)"
            print(f"  {len(ids)} field(s){rng}")
        return ids

    def cmd_nediag(self, args):
        """Read-only enumeration diagnostic: show what each step contributes and
        the real address/slot spread of the Fields we can see, so we can pick a
        traversal that reaches ALL of them instead of guessing at the layout."""
        if not getattr(self, "nat_cave", None):
            self._install_native_gate()
        if not self._arm_hook(self.nat_F, self.nat_cave, f"0x{self.nat_mbox:x}"):
            print("  [!] native gate not live (open the farm and retry).")
            return
        gm = self._read_u64(self.nat_mbox + 0x20)
        base = int(str(self._rpc("info")["base"]), 0)
        vt = base + self.FIELD_VTABLE_OFF
        first = self._find_a_field(gm, vt)
        if not first:
            print("  no field found at all")
            return
        print(f"  gm=0x{gm:x}  first=0x{first:x} id={self._read_field_id(first, vt)}")

        step = {}
        start = first
        for _ in range(64):
            if self._read_u64(start - self.FIELD_STRIDE) == vt:
                start -= self.FIELD_STRIDE
            else:
                break
        a = start
        for _ in range(64):
            fid = self._read_field_id(a, vt)
            if fid is None:
                break
            step.setdefault(a, ("contig", fid))
            a += self.FIELD_STRIDE
        print(f"  [1] contiguous walk: {len(step)}")

        n0 = len(step)
        vt_pat = " ".join(f"{b:02X}" for b in struct.pack("<Q", vt))
        for mm in (self._rpc("scanone", f"0x{first:x}", vt_pat, timeout=30.0) or []):
            addr = int(mm, 0)
            fid = self._read_field_id(addr, vt)
            if fid is not None:
                step.setdefault(addr, ("arena", fid))
        print(f"  [2] arena scan     : +{len(step) - n0}  (total {len(step)})")

        n1 = len(step)
        seen_pages = set()
        for _ in range(4):
            pages = {self._read_u64(a + 0x48) & ~0xFFF for a in list(step)
                     if 0x700000000000 <= self._read_u64(a + 0x48) < 0x800000000000}
            pages -= seen_pages
            if not pages:
                break
            seen_pages |= pages
            for pg in pages:
                for off in range(0, 0x1000, 0x200):
                    slot = pg + off
                    fp = self._read_u64(slot + 0x8)
                    if not (0x700000000000 <= fp < 0x800000000000) or fp in step:
                        continue
                    if self._read_u64(fp) != vt or self._read_u64(fp + 0x48) != slot:
                        continue
                    fid = self._read_field_id(fp, vt)
                    if fid is not None:
                        step[fp] = ("slotpage", fid)
        print(f"  [3] slot-page walk : +{len(step) - n1}  (total {len(step)}, "
              f"{len(seen_pages)} slot page(s))")

        # Per-field: address, id, slot pointer + back-ref. The address/slot deltas
        # reveal whether either forms a walkable array and at what stride.
        rows = sorted(((fid, addr, src) for addr, (src, fid) in step.items()))
        print(f"  --- {len(rows)} field(s): id, addr, slot, back-ref ok? ---")
        prev_a = prev_s = None
        for fid, addr, src in rows[:40]:
            slot = self._read_u64(addr + 0x48)
            back = self._read_u64(slot + 0x8) if 0x700000000000 <= slot < 0x800000000000 else 0
            da = f"+0x{addr - prev_a:x}" if prev_a else "-"
            ds = f"+0x{slot - prev_s:x}" if prev_s and slot else "-"
            print(f"   {fid} @0x{addr:x} (d{da:>8})  slot=0x{slot:x} (d{ds:>8})  "
                  f"live={back == addr}  [{src}]")
            prev_a, prev_s = addr, slot

    def cmd_nfields(self, args):
        ids = self._field_ids()
        print(f"  nfields -> {len(ids)} field(s): {ids}")

    def cmd_nfdiag(self, args):
        """Validate the native container read (run with the farm FULLY open):
        fire CMD_FIELDS_DIAG and print each candidate container's field count. The
        canonical container is the one whose count == the real field count and
        stays stable across states - re-run after harvest, replant and reopening
        the farm to confirm it isn't a transient view. Per-id detail -> NXRTH logcat."""
        su_command(self.adb, self.device_id, "logcat -c", check=False)  # only this run's fdiag
        self._native_refresh_ranges()   # make is_readable current for the in-process read
        n = self._native_cmd(7)   # CMD_FIELDS_DIAG
        if n is None:
            print("  [!] native gate not live (open the farm and retry).")
            return
        m = self.nat_mbox
        rd = lambda o: int.from_bytes(bytes(self._rpc("readabs", f"0x{m + o:x}", 4)), "little")
        best = rd(0x228)
        ids = sorted(set(self._native_ids(n)))
        print(f"  nfdiag: type-4 field sub-manager -> {best} field(s) "
              f"(gm/level+0x220 -> mgr+0x15c8[4])")
        print(f"    ids: {ids}")
        time.sleep(0.4)
        try:
            log = adb_cmd(self.adb, self.device_id, "shell",
                          "logcat -d -s NXRTH:V", timeout=10)
            lines = [ln for ln in (log.stdout or "").splitlines() if "fdiag" in ln]
            if lines:
                print("  --- module logcat (fdiag) ---")
                for ln in lines[-80:]:
                    print("   " + ln)
        except Exception:
            pass
        print("  re-run after harvest/replant/reopen; the canonical count stays == real field count")

    def _nspoof_dump(self):
        """Print accumulated 'spoof' NXRTH logcat WITHOUT clearing it, so open()
        intercept hits ('spoof: /proc/cpuinfo -> S24 Ultra', 'spoof: hidden ...')
        survive between commands."""
        try:
            log = adb_cmd(self.adb, self.device_id, "shell",
                          "logcat -d -s NXRTH:V", timeout=10)
            lines = [ln for ln in (log.stdout or "").splitlines() if "spoof" in ln]
            if lines:
                print(f"  --- nspoof logcat ({len(lines)} lines) ---")
                for ln in lines[-60:]:
                    print("   " + ln)
            else:
                print("  no 'spoof' logcat yet (run 'nspoof scan'/'nspoof on' first).")
        except Exception as e:
            print(f"  nspoof dump error: {e}")

    def cmd_nspoof(self, args):
        """Anti-ban device spoof (Galaxy S24 Ultra / Android 14 profile).
          nspoof scan  - report libg's hookable libc import slots (NO patch, verify)
          nspoof on    - install the open() hook (/proc/cpuinfo -> Snapdragon, hide su/root)
          nspoof off   - restore the original open()
          nspoof       - dump accumulated 'spoof' logcat (intercept hits)"""
        sub = args[0].lower() if args else "log"
        cmd_map = {"scan": 8, "on": 9, "off": 10}
        if sub == "log":
            self._nspoof_dump()
            return
        if sub not in cmd_map:
            print("  usage: nspoof scan | on | off  (or bare 'nspoof' to dump hits)")
            return
        su_command(self.adb, self.device_id, "logcat -c", check=False)
        n = self._native_cmd(cmd_map[sub])
        if n is None:
            print("  [!] native gate not live (open the farm and retry).")
            return
        if sub == "on":
            print(f"  nspoof on -> {n} (1=installed, 2=already, 0=open import not found)")
        elif sub == "off":
            print(f"  nspoof off -> {n}")
        time.sleep(0.4)
        self._nspoof_dump()

    def cmd_nquago(self, args):
        """Quago module control (loaded when $env:NX_QUAGO='1'):
          nquago               - dump the module logcat (QUAGOPROBE)
          nquago status        - block/spoof + hook status
          nquago block on|off  - block/allow the api.quago.io upload (default ON)
          nquago spoof on|off  - toggle accelerometer emulation (optional, off)"""
        sub = args[0].lower() if args else "log"
        ps = getattr(self, "probe_script", None)
        if sub in ("status", "block", "spoof"):
            if ps is None:
                print("  quago module not loaded (launch with  $env:NX_QUAGO='1').")
                return
            try:
                on = len(args) > 1 and args[1].lower() in ("on", "1", "true", "yes")
                if sub == "status":
                    print(f"  quago status: {ps.exports_sync.status()}")
                elif sub == "block":
                    print(f"  Quago upload block -> {ps.exports_sync.set_block(on)}")
                else:
                    print(f"  accel emulation -> {ps.exports_sync.set_spoof(on)}")
            except Exception as e:
                print(f"  nquago rpc error: {e}")
            return
        try:
            log = adb_cmd(self.adb, self.device_id, "shell",
                          "logcat -d -s QUAGOPROBE:V", timeout=10)
            lines = [ln for ln in (log.stdout or "").splitlines() if "QUAGOPROBE" in ln]
            if lines:
                print(f"  --- quago module ({len(lines)} lines) ---")
                for ln in lines[-150:]:
                    print("   " + ln)
            else:
                print("  no QUAGOPROBE logcat. Launch with  $env:NX_QUAGO='1'  before "
                      "python loader.py (look for '[+] quago_probe loaded' at startup).")
        except Exception as e:
            print(f"  nquago error: {e}")

    def cmd_nstate(self, args):
        """Live game-state captured from Quago's QuagoManager telemetry: current
        screen segment (FARM/ROADSIDE/...), player id/name, farm level, sell
        details. Free structured feed - needs the quago module ($env:NX_QUAGO='1')."""
        ps = getattr(self, "probe_script", None)
        if ps is None:
            print("  quago module not loaded (launch with  $env:NX_QUAGO='1').")
            return
        try:
            st = ps.exports_sync.state() or {}
            print(f"  screen/segment: {st.get('segment') or '(none)'}")
            for k in sorted(st):
                if k in ("segment", "_updated"):
                    continue
                print(f"    {k} = {st[k]}")
        except Exception as e:
            print(f"  nstate error: {e}")

    def _wait_fresh_scan(self, timeout=1.5):
        """Wait for the background scan to publish a fresh field list, so plant/
        harvest act on the CURRENT fields (ids change after each harvest cycle)."""
        if not self._ensure_native_mbox():
            return
        m = self.nat_mbox
        g0 = int.from_bytes(bytes(self._rpc("readabs", f"0x{m + 0x22c:x}", 4)), "little")
        for _ in range(int(timeout / 0.1)):
            time.sleep(0.1)
            g = int.from_bytes(bytes(self._rpc("readabs", f"0x{m + 0x22c:x}", 4)), "little")
            if g > g0:
                return

    def cmd_nplant(self, args):
        crop = int(args[0], 0) if args else 400001
        ids = self._field_ids()
        if not ids:
            print("  nplant -> no fields (are you in the farm?)")
            return
        c = self._native_cmd(4, arg0=crop, ids=ids)
        if c is not None:
            print(f"  nplant -> {c} field(s) (crop {crop})")

    def cmd_nharvest(self, args):
        ids = self._field_ids()
        if not ids:
            print("  nharvest -> no fields (are you in the farm?)")
            return
        c = self._native_cmd(5, ids=ids)
        if c is not None:
            print(f"  nharvest -> {c} field(s)")

    def cmd_nsell(self, args):
        """Put an item up for sale in a roadside-shop crate (executed natively).
        Usage: nsell <slot> [count=10] [price=1] [ad=0] [item=400001]"""
        if not args:
            print("  Usage: nsell <slot> [count=10] [price=1] [ad=0] [item=400001]")
            print("         open the roadside shop first; slot is the crate index")
            return
        slot = int(args[0], 0)
        count = int(args[1], 0) if len(args) > 1 else 10
        price = int(args[2], 0) if len(args) > 2 else 1
        ad = 1 if len(args) > 3 and args[3].lower() not in ("0", "no", "false", "n") else 0
        item = int(args[4], 0) if len(args) > 4 else self.WHEAT_ITEM
        c = self._native_cmd(6, ids=[slot, item, count, price, ad])
        if c is not None:
            print(f"  nsell -> item {item} x{count} @ {price} coin, slot {slot}, ad={ad}")

    def cmd_nfarm(self, args):
        """Auto-farm loop, executed natively: harvest all -> plant all -> wait ->
        repeat until Ctrl+C. Harvest on unripe fields and plant on occupied ones
        are no-ops, so the loop self-syncs from any starting state.
        Waits are randomized (and occasionally longer) so the cadence doesn't look
        machine-perfect. Usage: nfarm [wait_seconds=130] [cropId=400001]"""
        wait = int(args[0], 0) if args and args[0].isdigit() else 130
        crop = int(args[1], 0) if len(args) > 1 else 400001
        print(f"  Auto-farm (native): harvest -> plant every ~{wait}s. Ctrl+C to stop.")
        cycle = 0
        try:
            while True:
                cycle += 1
                ids = self._field_ids(verbose=False)
                if not ids:
                    print(f"  [{cycle}] no fields; retrying shortly")
                else:
                    h = self._native_cmd(5, ids=ids)
                    time.sleep(random.uniform(0.8, 2.2))     # act, then look again
                    ids = self._field_ids(verbose=False) or ids
                    p = self._native_cmd(4, arg0=crop, ids=ids)
                    print(f"  [{cycle}] harvested {h}, planted {p} ({len(ids)} fields)")
                # jittered growth wait; every few cycles take a longer break
                delay = wait * random.uniform(1.02, 1.18)
                if cycle % random.randint(4, 7) == 0:
                    delay += random.uniform(20, 90)
                left = int(delay)
                while left > 0:
                    print(f"\r  growing... {left:4d}s ", end="", flush=True)
                    step = min(2, left)
                    time.sleep(step)
                    left -= step
                print("\r" + " " * 26 + "\r", end="")
        except KeyboardInterrupt:
            print(f"\n  Auto-farm stopped after {cycle} cycle(s).")

    def _list_helper_residues(self):
        result = su_command(
            self.adb,
            self.device_id,
            "find /data/local/tmp -mindepth 1 -maxdepth 1 -print 2>/dev/null",
            check=False,
        )
        if result is None or result.returncode != 0:
            return None
        return {
            path
            for path in (line.strip().rstrip("/") for line in result.stdout.splitlines())
            if HELPER_RESIDUE_PATTERN.fullmatch(path)
        }

    def _cleanup_injector_residues(self):
        current = self._list_helper_residues()
        if self.helper_residues_before is not None and current is not None:
            for path in sorted(current - self.helper_residues_before):
                if HELPER_RESIDUE_PATTERN.fullmatch(path):
                    su_command(
                        self.adb,
                        self.device_id,
                        f"rm -rf {shlex.quote(path)}",
                        check=False,
                    )
        su_command(
            self.adb,
            self.device_id,
            f"rm -rf {shlex.quote(INJECTOR_OAT_DIR)}",
            check=False,
        )

    def prepare_assets(self):
        if not SCRIPT_PATH.is_file():
            raise LoaderError(f"hook script not found: {SCRIPT_PATH}")
        if not GADGET_CONFIG_PATH.is_file():
            raise LoaderError(f"Gadget config not found: {GADGET_CONFIG_PATH}")

        try:
            config = json.loads(GADGET_CONFIG_PATH.read_text(encoding="utf-8"))
            interaction = config["interaction"]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise LoaderError(f"invalid Gadget config: {error}") from error
        if interaction.get("type") != "listen":
            raise LoaderError("Gadget config must use listen interaction for the RPC console")
        if interaction.get("address") != "127.0.0.1" or interaction.get("port") != GADGET_PORT:
            raise LoaderError(
                f"Gadget config must listen on 127.0.0.1:{GADGET_PORT}"
            )
        if interaction.get("on_load") != "resume":
            raise LoaderError("Gadget config on_load must be 'resume' for injector loading")

        server_check = su_command(
            self.adb, self.device_id, f"test -x {shlex.quote(FRIDA_BIN)}", check=False
        )
        if server_check is None or server_check.returncode != 0:
            raise LoaderError(
                f"vault injector server is missing or not executable: {FRIDA_BIN}"
            )
        gadget_check = su_command(
            self.adb,
            self.device_id,
            f"test -r {shlex.quote(GADGET_VAULT)}",
            check=False,
        )
        if gadget_check is None or gadget_check.returncode != 0:
            raise LoaderError(
                f"vault Gadget is missing or unreadable: {GADGET_VAULT}"
            )

        server_digest = self._remote_sha256(FRIDA_BIN)
        if server_digest != FRIDA_SHA256:
            raise LoaderError(
                f"vault injector SHA-256 mismatch: expected {FRIDA_SHA256}, "
                f"got {server_digest}"
            )
        gadget_digest = self._remote_sha256(GADGET_VAULT)
        if gadget_digest != GADGET_SHA256:
            raise LoaderError(
                f"vault Gadget SHA-256 mismatch: expected {GADGET_SHA256}, "
                f"got {gadget_digest}"
            )

        self.server_exe = self._remote_realpath(FRIDA_BIN)
        self._stage_runtime_gadget()
        print(f"[+] Gadget config: {self.gadget_config_remote}")

    def _add_forward(self, port):
        local = f"tcp:{port}"
        adb_cmd(self.adb, self.device_id, "forward", "--remove", local)
        adb_checked(self.adb, self.device_id, "forward", local, local)
        self.forwarded_ports[port] = port

    def _remove_forward(self, port):
        if port not in self.forwarded_ports or not self.adb or not self.device_id:
            return
        try:
            adb_cmd(self.adb, self.device_id, "forward", "--remove", f"tcp:{port}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        self.forwarded_ports.pop(port, None)

    def _connect_remote(self, port, label):
        address = f"127.0.0.1:{port}"
        deadline = time.monotonic() + CONNECT_TIMEOUT
        last_error = None
        while time.monotonic() < deadline:
            try:
                device = self.manager.add_remote_device(address)
                processes = device.enumerate_processes()
                print(f"[+] {label} connected ({len(processes)} processes)")
                return device
            except Exception as error:
                last_error = error
                try:
                    self.manager.remove_remote_device(address)
                except Exception:
                    pass
                time.sleep(0.25)
        raise LoaderError(f"{label} connection timed out: {last_error}")

    def start_and_connect(self):
        print("\n[*] === SETUP ===")
        print(f"[1/3] Starting injector server (port {FRIDA_PORT})...")
        self.helper_residues_before = self._list_helper_residues()
        command = (
            f"nohup {shlex.quote(FRIDA_BIN)} -D -l 127.0.0.1:{FRIDA_PORT} "
            f">{shlex.quote(SERVER_LOG)} 2>&1 &"
        )
        self.server_start_attempted = True
        su_command(self.adb, self.device_id, command)

        deadline = time.monotonic() + CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            self.server_pids = self._matching_server_pids()
            if self.server_pids:
                break
            time.sleep(0.2)
        if not self.server_pids:
            raise LoaderError("injector server failed to start")
        print(f"[+] Injector PID(s): {', '.join(map(str, sorted(self.server_pids)))}")

        print("[2/3] Forwarding injector port...")
        self._add_forward(FRIDA_PORT)
        self.manager = frida.get_device_manager()
        print("[3/3] Connecting to injector...")
        self.injector_device = self._connect_remote(FRIDA_PORT, "Injector")

    def spawn_inject(self):
        print("\n[*] === FILE-BACKED GADGET INJECTION ===")
        adb_checked(self.adb, self.device_id, "shell", f"am force-stop {PACKAGE_NAME}")
        deadline = time.monotonic() + 5.0
        while find_game_pids(self.adb, self.device_id) and time.monotonic() < deadline:
            time.sleep(0.1)
        remaining_pids = find_game_pids(self.adb, self.device_id)
        if remaining_pids:
            raise LoaderError(
                f"could not stop existing game PID(s): "
                f"{', '.join(map(str, sorted(remaining_pids)))}"
            )

        print("[1/8] Spawning game (suspended)...")
        try:
            self.pid = self.injector_device.spawn(PACKAGE_NAME)
        except Exception as error:
            raise LoaderError(f"spawn failed: {error}") from error
        self.spawn_owned = True
        self.pid_starttime = self._pid_starttime(self.pid)
        if self.pid_starttime is None:
            raise LoaderError(f"spawned PID {self.pid} disappeared before injection")
        print(f"[+] Spawned PID {self.pid}")

        print(f"[2/8] Injecting file-backed Gadget: {GADGET_BIN}")
        try:
            self.injector_device.inject_library_file(
                self.pid, GADGET_BIN, "pthread_exit", ""
            )
        except Exception as error:
            raise LoaderError(f"Gadget injection failed: {error}") from error

        print(f"[3/8] Connecting to Gadget (port {GADGET_PORT})...")
        self._add_forward(GADGET_PORT)
        self.gadget_device = self._connect_remote(GADGET_PORT, "Gadget")
        try:
            self.session = self.gadget_device.attach("Gadget")
        except Exception as error:
            raise LoaderError(f"Gadget attach failed: {error}") from error
        self.session.on("detached", self._on_detached)

        print("[4/8] Loading RPC agent and verifying resume barrier...")
        try:
            code = SCRIPT_PATH.read_text(encoding="utf-8")
            self.script = self.session.create_script(code)
            self.script.on("message", self.on_message)
            self.script.load()
            if self._rpc("ping") != "pong":
                raise LoaderError("agent ping returned an unexpected response")
            status = self._rpc("status")
            self._validate_agent_status(status)
            if status.get("resumeComplete") is not False:
                raise LoaderError(
                    "resume barrier was already complete before external resume"
                )
        except LoaderError:
            raise
        except Exception as error:
            raise LoaderError(f"hook load failed: {error}") from error

        # Load the Promon SHIELD suppression guard as a SECOND, independent script
        # in the SAME Gadget session, BEFORE resume. SHIELD arms during the app's
        # JNI_OnLoad (runs on resume), so the guard's ClassLoader hooks must be in
        # place first; it touches only boot-class methods, so Java.performNow works
        # while suspended. The bundle auto-initializes on load (top-level IIFE),
        # no RPC trigger needed. Failure here must never abort automation.
        if JAVA_GUARD_PATH.is_file():
            try:
                guard_code = JAVA_GUARD_PATH.read_text(encoding="utf-8")
                self.guard_script = self.session.create_script(guard_code)
                self.guard_script.on("message", self._on_guard_message)
                self.guard_script.load()
                print("[+] java_guard loaded (SHIELD kill/report suppression active)")
            except Exception as error:
                self.guard_script = None
                print(f"[!] java_guard load failed (continuing without guard): {error}")
        else:
            print("[!] java_guard.bundle.js missing; SHIELD guard disabled")

        # Optional READ-ONLY Quago probe (set NX_QUAGO=1). Loads before resume so
        # it catches Quago's init / sensor registration / first report. Logs only,
        # neuters nothing. [QUAGO] lines print via _on_guard_message.
        if os.environ.get("NX_QUAGO") == "1" and QUAGO_PROBE_PATH.is_file():
            try:
                probe_code = QUAGO_PROBE_PATH.read_text(encoding="utf-8")
                self.probe_script = self.session.create_script(probe_code)
                self.probe_script.on("message", self._on_guard_message)
                self.probe_script.load()
                print("[+] quago_probe loaded (READ-ONLY; [QUAGO] lines follow)")
            except Exception as error:
                self.probe_script = None
                print(f"[!] quago_probe load failed: {error}")

        print("[5/8] Starting engine watcher while process is suspended...")
        if self._rpc("init") is not True:
            raise LoaderError("agent init returned an unexpected response")

        print("[6/8] Resuming process and waiting for rollback barrier...")
        try:
            self.injector_device.resume(self.pid)
            self.resumed = True
        except Exception as error:
            raise LoaderError(f"resume failed: {error}") from error
        self._wait_for_resume_barrier()

        print("[7/8] Releasing injector server...")
        self._release_injector()

        print("[8/8] Waiting for libg.so and a stable heartbeat...")
        base = self._wait_for_engine()
        print(f"[+] libg.so base: {base}")
        print("[+] === INJECTION COMPLETE ===")

    def _validate_agent_status(self, status):
        if not isinstance(status, dict):
            raise LoaderError(f"agent status is not an object: {status!r}")
        if status.get("pid") != self.pid:
            raise LoaderError(
                f"Gadget PID mismatch: expected {self.pid}, got {status.get('pid')!r}"
            )
        if status.get("resumeBarrierInstalled") is not True:
            detail = status.get("resumeDetail") or "no detail"
            raise LoaderError(f"spawn resume barrier is not installed: {detail}")

    def _wait_for_resume_barrier(self):
        deadline = time.monotonic() + RESUME_TIMEOUT
        last_status = None
        while time.monotonic() < deadline:
            if not self._attached():
                reason = self.detached_reason or self.script_error or "connection lost"
                raise LoaderError(f"Gadget detached during resume: {reason}")
            remaining = max(0.1, deadline - time.monotonic())
            last_status = self._rpc(
                "status", timeout=min(RPC_TIMEOUT, remaining)
            )
            self._validate_agent_status(last_status)
            if last_status.get("resumeComplete") is True:
                self.resume_barrier_complete = True
                print(f"[+] Spawn rollback completed for PID {self.pid}")
                return
            time.sleep(0.02)

        detail = f"; last status={last_status}" if last_status is not None else ""
        raise LoaderError(
            f"spawn resume barrier did not complete within {RESUME_TIMEOUT:.0f}s{detail}"
        )

    def _attached(self):
        if self.detached.is_set() or self.script_failed.is_set():
            return False
        if self.session is None or self.script is None:
            return False
        try:
            return not self.session.is_detached and not self.script.is_destroyed
        except Exception:
            return False

    def _rpc(self, method, *args, timeout=RPC_TIMEOUT):
        if not self._attached():
            reason = self.detached_reason or self.script_error or "session is not attached"
            raise LoaderError(str(reason))

        outcome = queue.Queue(maxsize=1)

        def invoke():
            try:
                value = getattr(self.script.exports_sync, method)(*args)
                outcome.put((True, value))
            except BaseException as error:
                outcome.put((False, error))

        threading.Thread(target=invoke, daemon=True, name=f"nxrth-rpc-{method}").start()
        try:
            success, value = outcome.get(timeout=max(0.1, timeout))
        except queue.Empty as error:
            raise LoaderError(f"RPC {method} timed out after {timeout:.1f}s") from error
        if not success:
            raise LoaderError(f"RPC {method} failed: {value}") from value
        return value

    def _wait_for_engine(self):
        deadline = time.monotonic() + ENGINE_TIMEOUT
        stable_since = None
        stable_identity = None
        last_info = None

        while time.monotonic() < deadline:
            if not self._attached():
                reason = self.detached_reason or self.script_error or "connection lost"
                raise LoaderError(f"Gadget detached during startup: {reason}")
            # The spawned child can briefly retain a zygote-era process name
            # while RoboLauncher finishes specialization, making pidof(package)
            # return an empty set even though our exact PID and Gadget session
            # are alive.  Check the owned /proc entry; RPC below independently
            # verifies that the attached agent reports the same PID.
            if not self._owned_game_alive():
                raise LoaderError(f"game PID {self.pid} terminated during startup")

            remaining = max(0.1, deadline - time.monotonic())
            last_info = self._rpc("info", timeout=min(RPC_TIMEOUT, remaining))
            if not isinstance(last_info, dict):
                raise LoaderError(f"agent info is not an object: {last_info!r}")
            if last_info.get("pid") != self.pid:
                raise LoaderError(
                    f"Gadget PID mismatch during engine wait: expected {self.pid}, "
                    f"got {last_info.get('pid')!r}"
                )

            base = last_info.get("base")
            size = last_info.get("size")
            valid_base = False
            if base:
                try:
                    valid_base = int(str(base), 0) > 0
                except (TypeError, ValueError):
                    raise LoaderError(f"agent returned an invalid libg.so base: {base!r}")
            valid_size = isinstance(size, int) and not isinstance(size, bool) and size > 0
            now = time.monotonic()
            if valid_base and valid_size:
                identity = (str(base), size)
                if identity != stable_identity:
                    stable_identity = identity
                    stable_since = now
                    print(
                        f"[*] Engine heartbeat at {base} ({size} bytes); "
                        f"verifying {STABILITY_WINDOW:.0f}s stability..."
                    )
                elif stable_since is not None and now - stable_since >= STABILITY_WINDOW:
                    return base
            else:
                stable_identity = None
                stable_since = None
            time.sleep(0.5)

        detail = f"; last info={last_info}" if last_info is not None else ""
        raise LoaderError(f"libg.so did not become ready within {ENGINE_TIMEOUT:.0f}s{detail}")

    def _release_injector(self):
        had_injector = bool(
            self.injector_device
            or self.server_pids
            or self.server_start_attempted
            or FRIDA_PORT in self.forwarded_ports
        )
        owned_pids = set(self.server_pids)
        if self.server_start_attempted and self.adb and self.device_id:
            try:
                owned_pids.update(self._matching_server_pids())
            except (LoaderError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        survivors = set()
        if owned_pids:
            # Once RoboLauncher has completed its rollback handshake, the
            # injected pthread_exit call is still keeping the injector RPC
            # alive.  A graceful server shutdown tears down that live call and
            # can take the independent Gadget session with it.  Terminate only
            # the exact owned executable, immediately, before removing the
            # host-side remote device.
            survivors = self._stop_server_pids(
                owned_pids, force=self.resume_barrier_complete
            )
        if survivors and self.resume_barrier_complete:
            raise LoaderError(
                f"injector server did not terminate: "
                f"{', '.join(map(str, sorted(survivors)))}"
            )
        if self.manager is not None:
            try:
                self.manager.remove_remote_device(f"127.0.0.1:{FRIDA_PORT}")
            except Exception:
                pass
        self.injector_device = None
        self.server_start_attempted = False
        self._remove_forward(FRIDA_PORT)
        if self.adb and self.device_id and had_injector:
            su_command(
                self.adb, self.device_id, f"rm -f {shlex.quote(SERVER_LOG)}", check=False
            )
            if not survivors:
                self._cleanup_injector_residues()
        if survivors:
            raise LoaderError(
                f"injector server did not terminate: "
                f"{', '.join(map(str, sorted(survivors)))}"
            )
        if had_injector:
            print("[+] Injector server released")

    def cmd_read(self, args):
        if len(args) < 2:
            print("  Usage: read <type> <offset> [length]")
            return
        dtype, offset = args[0], args[1]
        dispatch = {
            "int": lambda: self._rpc("readint", offset),
            "float": lambda: self._rpc("readfloat", offset),
            "double": lambda: self._rpc("readdouble", offset),
            "long": lambda: self._rpc("readlong", offset),
            "ptr": lambda: self._rpc("readpointer", offset),
            "str": lambda: self._rpc(
                "readstring", offset, args[2] if len(args) > 2 else "256"
            ),
            "bytes": lambda: self._rpc(
                "readbytes", offset, args[2] if len(args) > 2 else "64"
            ),
        }
        if dtype not in dispatch:
            print(f"  Unknown type: {dtype}")
            return
        result = dispatch[dtype]()
        if dtype == "bytes" and result:
            print(f"  [{offset}] = {' '.join(f'{b:02x}' for b in result)}")
        else:
            print(f"  [{offset}] = {result}")

    def cmd_write(self, args):
        if len(args) < 3:
            print("  Usage: write <type> <offset> <value>")
            return
        dtype, offset, value = args[0], args[1], args[2]
        dispatch = {
            "int": lambda: self._rpc("writeint", offset, value),
            "float": lambda: self._rpc("writefloat", offset, value),
            "double": lambda: self._rpc("writedouble", offset, value),
            "long": lambda: self._rpc("writelong", offset, value),
            "bytes": lambda: self._rpc("writebytes", offset, value),
        }
        if dtype not in dispatch:
            print(f"  Unknown type: {dtype}")
            return
        print(f"  {'OK' if dispatch[dtype]() else 'FAIL'}")

    def cmd_nop(self, args):
        if len(args) < 2:
            print("  Usage: nop <offset> <byte_count>")
            return
        print(f"  {'Patched' if self._rpc('nop', args[0], args[1]) else 'FAIL'}")

    def cmd_call(self, args):
        if len(args) < 4:
            print("  Usage: call <offset> <ret_type> <arg_types_json> <args_json>")
            return
        result = self._rpc("call", args[0], args[1], args[2], args[3])
        print(f"  Result: {result}")

    def cmd_hook(self, args):
        if len(args) < 1:
            print("  Usage: hook <offset>")
            return
        print(f"  {'Hooked' if self._rpc('hookfn', args[0]) else 'FAIL'}")

    def cmd_scan(self, args):
        if len(args) < 1:
            print("  Usage: scan <pattern>")
            return
        results = self._rpc("scan", " ".join(args), timeout=max(RPC_TIMEOUT, 30.0))
        if not results:
            print("  No matches")
            return
        for r in results:
            print(f"  {r['offset']}  ({r['address']})")

    def cmd_dump(self, args):
        if len(args) < 2:
            print("  Usage: dump <offset> <length>")
            return
        data = self._rpc("dump", args[0], args[1])
        if not data:
            print("  FAIL")
            return
        off = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
        for i in range(0, len(data), 16):
            c = data[i:i + 16]
            h = " ".join(f"{b:02x}" for b in c)
            a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
            print(f"  {off + i:08x}  {h:<48s}  {a}")

    def cmd_export(self, args):
        if len(args) < 1:
            print("  Usage: export <function_name>")
            return
        offset = self._rpc("getexport", args[0])
        print(f"  {args[0]} -> 0x{offset:x}" if offset is not None else "  Not found")

    def cmd_info(self, args):
        info = self._rpc("info")
        print(f"  Base:     {info['base']}")
        print(f"  Size:     {info['size']} (0x{info['size']:x})")
        print(f"  Arch:     {info['arch']}")
        print(f"  Platform: {info['platform']}")
        print(f"  Houdini:  {info['houdini']}")
        print(f"  PID:      {info['pid']}")

    TYPE_SIZES = {"int": 4, "float": 4, "double": 8, "short": 2, "long": 8}
    TYPE_FMTS = {"int": "<i", "float": "<f", "double": "<d", "short": "<h", "long": "<q"}

    @staticmethod
    def value_to_pattern(dtype, value_str):
        fmt = NXRTHConsole.TYPE_FMTS.get(dtype)
        if fmt is None:
            raise ValueError(f"unknown type: {dtype}")
        cast = int if dtype in ("int", "short", "long") else float
        raw = struct.pack(fmt, cast(value_str))
        return " ".join(f"{b:02X}" for b in raw)

    def _interpret_value(self, raw, dtype):
        if raw is None:
            return "?"
        buf = bytes(raw)
        fmt = self.TYPE_FMTS.get(dtype, "<i")
        size = self.TYPE_SIZES.get(dtype, 4)
        if len(buf) < size:
            return "?"
        val = struct.unpack(fmt, buf[:size])[0]
        if dtype == "float":
            return f"{val:.4f}"
        if dtype == "double":
            return f"{val:.6f}"
        return val

    def cmd_vscan(self, args):
        if len(args) < 2:
            print("  Usage: vscan <int|float|double|short|long> <value>")
            return
        dtype, value_str = args[0], args[1]
        try:
            pattern = self.value_to_pattern(dtype, value_str)
        except (ValueError, struct.error) as e:
            print(f"  Error: {e}")
            return
        print(f"  Scanning writable memory for {dtype} {value_str} [{pattern}]...")
        results = self._rpc("scanmem", pattern, timeout=120.0)
        self.scan_results = results if results else []
        self.scan_type = dtype
        count = len(self.scan_results)
        print(f"  Found {count} matches" + (" (capped at 4096)" if count >= 4096 else ""))
        if count <= 20:
            for addr in self.scan_results:
                print(f"    {addr}")

    def cmd_vnarrow(self, args):
        if len(args) < 2:
            print("  Usage: vnarrow <int|float|double|short|long> <value>")
            return
        if not self.scan_results:
            print("  No previous scan results. Use vscan first.")
            return
        dtype, value_str = args[0], args[1]
        try:
            pattern = self.value_to_pattern(dtype, value_str)
        except (ValueError, struct.error) as e:
            print(f"  Error: {e}")
            return
        prev = len(self.scan_results)
        print(f"  Narrowing {prev} results for {dtype} {value_str}...")
        results = self._rpc("narrowmem", self.scan_results, pattern, timeout=30.0)
        self.scan_results = results if results else []
        self.scan_type = dtype
        count = len(self.scan_results)
        print(f"  {count} matches remain (eliminated {prev - count})")
        if count <= 20:
            size = self.TYPE_SIZES.get(dtype, 4)
            for addr in self.scan_results:
                raw = self._rpc("readabs", addr, size)
                val = self._interpret_value(raw, dtype)
                print(f"    {addr} = {val}")

    def cmd_vlist(self, args):
        if not self.scan_results:
            print("  No scan results")
            return
        dtype = self.scan_type or "int"
        size = self.TYPE_SIZES.get(dtype, 4)
        count = len(self.scan_results)
        show = min(count, 50)
        print(f"  {count} results ({dtype}):")
        for i in range(show):
            addr = self.scan_results[i]
            raw = self._rpc("readabs", addr, size)
            val = self._interpret_value(raw, dtype)
            print(f"    [{i}] {addr} = {val}")
        if count > show:
            print(f"    ... and {count - show} more")

    def cmd_vwrite(self, args):
        if len(args) < 1:
            print("  Usage: vwrite <value> [index]")
            return
        if not self.scan_results:
            print("  No scan results")
            return
        dtype = self.scan_type or "int"
        value_str = args[0]
        try:
            pattern = self.value_to_pattern(dtype, value_str)
        except (ValueError, struct.error) as e:
            print(f"  Error: {e}")
            return
        byte_values = [int(x, 16) for x in pattern.split()]
        if len(args) > 1:
            idx = int(args[1])
            if 0 <= idx < len(self.scan_results):
                ok = self._rpc("writeabs", self.scan_results[idx], byte_values)
                print(f"  {'OK' if ok else 'FAIL'}: {self.scan_results[idx]}")
            else:
                print(f"  Index out of range (0-{len(self.scan_results) - 1})")
        else:
            ok_count = 0
            for addr in self.scan_results:
                if self._rpc("writeabs", addr, byte_values):
                    ok_count += 1
            print(f"  Wrote to {ok_count}/{len(self.scan_results)} addresses")

    def cmd_vreset(self, args):
        self.scan_results = []
        self.scan_type = None
        print("  Scan results cleared")

    def cmd_cave(self, args):
        size = args[0] if args else "256"
        try:
            size_int = int(size, 0)
        except ValueError:
            print("  Usage: cave [size]  (default 256)")
            return
        addr = self._rpc("alloccave", size_int)
        print(f"  Cave allocated: {addr} ({size_int} bytes, rwx)")
        print(f"  Fill it with:  wabs {addr} <hexbytes>")

    def cmd_farjump(self, args):
        if len(args) < 2:
            print("  Usage: farjump <libg_offset> <target_abs_addr>")
            print("  Redirects offset -> target with a 16-byte ARM64 far branch.")
            return
        original = self._rpc("farjump", args[0], args[1])
        if not original:
            print("  FAIL")
            return
        orig_hex = "".join(f"{b:02x}" for b in original)
        print(f"  Redirected {args[0]} -> {args[1]}")
        print(f"  Original 16 bytes (for trampoline): {orig_hex}")

    def cmd_branch(self, args):
        if len(args) < 2:
            print("  Usage: branch <libg_offset> <target_abs_addr> [link]")
            print("  Encodes a B (or BL if 'link') and writes it at offset.")
            return
        link = len(args) > 2 and args[2].lower() in ("link", "bl", "1", "true")
        encoded = self._rpc("makebranch", args[0], args[1], link)
        if not encoded:
            print("  FAIL to encode")
            return
        hexstr = "".join(f"{b:02x}" for b in encoded)
        ok = self._rpc("writebytes", args[0], hexstr)
        kind = "BL" if link else "B"
        print(f"  {'OK' if ok else 'FAIL'}: {kind} {args[0]} -> {args[1]} [{hexstr}]")

    def cmd_wabs(self, args):
        if len(args) < 2:
            print("  Usage: wabs <abs_addr> <hexbytes>")
            return
        hexstr = args[1].replace(" ", "")
        try:
            byte_values = [int(hexstr[i:i + 2], 16) for i in range(0, len(hexstr), 2)]
        except ValueError:
            print("  Invalid hex")
            return
        ok = self._rpc("writeabs", args[0], byte_values)
        print(f"  {'OK' if ok else 'FAIL'}: wrote {len(byte_values)} bytes to {args[0]}")

    def cmd_rabs(self, args):
        if len(args) < 2:
            print("  Usage: rabs <abs_addr> <len>")
            return
        try:
            length = int(args[1], 0)
        except ValueError:
            print("  Invalid length")
            return
        data = self._rpc("readabs", args[0], length)
        if not data:
            print("  FAIL (unmapped?)")
            return
        base = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
        for i in range(0, len(data), 16):
            c = data[i:i + 16]
            h = " ".join(f"{b:02x}" for b in c)
            a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
            print(f"  {base + i:012x}  {h:<48s}  {a}")

    def cmd_dumpso(self, args):
        out_path = args[0] if args else "libg_dump.so"
        layout = self._rpc("layout")
        size = layout["size"]
        segments = layout["segments"]
        print(f"  libg.so base={layout['base']} size={size} (0x{size:x})")
        print(f"  Dumping {len(segments)} segment(s) to {out_path} ...")
        buf = bytearray(size)  # gaps between segments stay zero-filled
        chunk = 2 * 1024 * 1024
        total = 0
        for seg in segments:
            off, seglen = int(seg["offset"]), int(seg["size"])
            pos = 0
            while pos < seglen:
                n = min(chunk, seglen - pos)
                data = self._rpc("readbytes", str(off + pos), str(n), timeout=90.0)
                if not data:
                    print(f"\n  [!] read failed at offset 0x{off + pos:x}")
                    break
                buf[off + pos:off + pos + len(data)] = data
                pos += len(data)
                total += len(data)
                print(f"\r  {total / 1024 / 1024:.1f} MB dumped", end="", flush=True)
        print()
        try:
            with open(out_path, "wb") as fh:
                fh.write(buf)
        except OSError as error:
            print(f"  [!] could not write file: {error}")
            return
        print(f"  Wrote {len(buf)} bytes to {out_path}")
        print("  Ghidra: Raw Binary, language AARCH64:LE:64:v8a, base 0x0")

    def cmd_cavetest(self, args):
        """Linchpin test: does Houdini execute patched/cave ARM64 code?

        Redirects a hot, position-independent function into a code cave that
        increments a mailbox counter, runs the 4 stolen instructions, then
        far-jumps back. If the counter climbs, SMC + cave execution both work.
        """
        target = 0x011116e4
        if args:
            target = int(args[0], 16) if args[0].lower().startswith("0x") else int(args[0], 0)

        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        cave = self._rpc("alloccave", 128)
        mbox = self._rpc("alloccave", 16)
        mbox_i = int(mbox, 0)
        self._rpc("writeabs", mbox, [0] * 8)

        stolen = bytes(self._rpc("readbytes", str(target), "16"))
        if len(stolen) != 16:
            print("  FAIL: could not read 16 stolen bytes")
            return
        ret_abs = base + target + 16

        def u32(x):
            return struct.pack("<I", x & 0xFFFFFFFF)

        def movz(rd, imm, sh):
            return 0xD2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

        def movk(rd, imm, sh):
            return 0xF2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

        sc = b""
        sc += u32(movz(16, mbox_i & 0xFFFF, 0))
        sc += u32(movk(16, (mbox_i >> 16) & 0xFFFF, 16))
        sc += u32(movk(16, (mbox_i >> 32) & 0xFFFF, 32))
        sc += u32(movk(16, (mbox_i >> 48) & 0xFFFF, 48))
        sc += u32(0xF9400000 | (16 << 5) | 17)          # ldr  x17, [x16]
        sc += u32(0x91000000 | (1 << 10) | (17 << 5) | 17)  # add  x17, x17, #1
        sc += u32(0xF9000000 | (16 << 5) | 17)          # str  x17, [x16]
        sc += stolen                                    # 4 original instructions
        sc += u32(0x58000051)                           # ldr  x17, #8
        sc += u32(0xD61F0220)                           # br   x17
        sc += struct.pack("<Q", ret_abs)                # .quad target+16

        if not self._rpc("writeabs", cave, list(sc)):
            print("  FAIL: could not write cave shellcode")
            return
        self._rpc("farjump", str(target), cave)
        print(f"  Hooked 0x{target:08x} -> cave {cave} (mailbox {mbox})")
        print("  Watching counter for 6s ...")
        last = 0
        for i in range(12):
            time.sleep(0.5)
            v = self._rpc("readabs", mbox, 8)
            cnt = int.from_bytes(bytes(v), "little") if v else -1
            print(f"    t={i * 0.5:>4.1f}s  counter={cnt}")
            last = cnt
        if last > 0:
            print("  >>> SUCCESS: Houdini executes our cave code. SMC works.")
        else:
            print("  >>> Counter stayed 0: patch not picked up (translation cache).")

    def cmd_gothook(self, args):
        """Data/indirect hook test: redirect a hot GOT (import) slot to a cave.

        Indirect branches (br x17 through a GOT pointer) read their target at
        runtime, so Houdini cannot cache them -> overwriting the pointer works
        even though inline code patching does not. Cave increments a counter,
        then tail-jumps to the original pointer. Restores the slot afterwards.
        """
        got_off = 0x015057f0
        if args:
            got_off = int(args[0], 16) if args[0].lower().startswith("0x") else int(args[0], 0)

        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        got_abs = base + got_off
        got_s = f"0x{got_abs:x}"

        orig = self._rpc("readabs", got_s, 8)
        if not orig or len(orig) != 8:
            print("  FAIL: could not read GOT slot")
            return
        orig_i = int.from_bytes(bytes(orig), "little")
        print(f"  GOT slot 0x{got_off:08x} (abs {got_s}) -> orig 0x{orig_i:x}")

        cave = self._rpc("alloccave", 128)
        mbox = self._rpc("alloccave", 16)
        mbox_i = int(mbox, 0)
        self._rpc("writeabs", mbox, [0] * 8)

        def u32(x):
            return struct.pack("<I", x & 0xFFFFFFFF)

        def movz(rd, imm, sh):
            return 0xD2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

        def movk(rd, imm, sh):
            return 0xF2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

        sc = b""
        sc += u32(movz(16, mbox_i & 0xFFFF, 0))
        sc += u32(movk(16, (mbox_i >> 16) & 0xFFFF, 16))
        sc += u32(movk(16, (mbox_i >> 32) & 0xFFFF, 32))
        sc += u32(movk(16, (mbox_i >> 48) & 0xFFFF, 48))
        sc += u32(0xF9400000 | (16 << 5) | 17)          # ldr  x17, [x16]
        sc += u32(0x91000000 | (1 << 10) | (17 << 5) | 17)  # add  x17, x17, #1
        sc += u32(0xF9000000 | (16 << 5) | 17)          # str  x17, [x16]
        sc += u32(0x58000051)                           # ldr  x17, #8
        sc += u32(0xD61F0220)                           # br   x17
        sc += struct.pack("<Q", orig_i)                 # .quad original pointer

        if not self._rpc("writeabs", cave, list(sc)):
            print("  FAIL: could not write cave")
            return
        cave_i = int(cave, 0)
        # Overwrite the GOT pointer (aligned 8-byte data write).
        self._rpc("writeabs", got_s, list(struct.pack("<Q", cave_i)))
        print(f"  GOT redirected -> cave {cave} (mailbox {mbox}); watching 6s ...")
        last = 0
        try:
            for i in range(12):
                time.sleep(0.5)
                v = self._rpc("readabs", mbox, 8)
                cnt = int.from_bytes(bytes(v), "little") if v else -1
                print(f"    t={i * 0.5:>4.1f}s  counter={cnt}")
                last = cnt
        finally:
            # Restore the original pointer so we don't leave a hot import hooked.
            self._rpc("writeabs", got_s, list(struct.pack("<Q", orig_i)))
            print("  GOT slot restored")
        if last > 0:
            print("  >>> SUCCESS: indirect/data hook works. This is our hook path.")
        else:
            print("  >>> Counter 0: slot not called or write ineffective.")

    @staticmethod
    def _movz(rd, imm, sh):
        return 0xD2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

    @staticmethod
    def _movk(rd, imm, sh):
        return 0xF2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd

    def _load_imm64(self, rd, value):
        out = b""
        out += struct.pack("<I", self._movz(rd, value & 0xFFFF, 0))
        out += struct.pack("<I", self._movk(rd, (value >> 16) & 0xFFFF, 16))
        out += struct.pack("<I", self._movk(rd, (value >> 32) & 0xFFFF, 32))
        out += struct.pack("<I", self._movk(rd, (value >> 48) & 0xFFFF, 48))
        return out

    def cmd_flushtest(self, args):
        """Test inline hook made effective by a guest cache flush.

        1. Inline-patch a hot PI-safe function F -> counter cave (won't fire:
           stale translation).
        2. Install a flush cave on a hot GOT slot that runs DC CVAU / IC IVAU
           over F's line every call, then tail-calls the original import.
        3. If the counter starts climbing, Houdini re-translated F -> inline
           hooks are viable via cache flush (lets us hook direct-call funcs).
        """
        F = 0x011116e4
        if args:
            F = int(args[0], 16) if args[0].lower().startswith("0x") else int(args[0], 0)
        got_off = 0x015057f0

        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        fabs = base + F

        cmbox = self._rpc("alloccave", 16)
        cmbox_i = int(cmbox, 0)
        self._rpc("writeabs", cmbox, [0] * 8)

        stolen = bytes(self._rpc("readbytes", str(F), "16"))
        if len(stolen) != 16:
            print("  FAIL: stolen bytes")
            return

        # counter cave
        ccave = self._rpc("alloccave", 128)
        sc = b""
        sc += self._load_imm64(16, cmbox_i)
        sc += struct.pack("<I", 0xF9400000 | (16 << 5) | 17)          # ldr x17,[x16]
        sc += struct.pack("<I", 0x91000000 | (1 << 10) | (17 << 5) | 17)  # add x17,#1
        sc += struct.pack("<I", 0xF9000000 | (16 << 5) | 17)          # str x17,[x16]
        sc += stolen
        sc += struct.pack("<I", 0x58000051)                           # ldr x17,#8
        sc += struct.pack("<I", 0xD61F0220)                           # br x17
        sc += struct.pack("<Q", fabs + 16)
        self._rpc("writeabs", ccave, list(sc))
        self._rpc("farjump", str(F), ccave)
        print(f"  Inline-patched 0x{F:08x} -> counter cave {ccave}")

        # flush cave on GOT slot
        got_abs = base + got_off
        got_s = f"0x{got_abs:x}"
        orig = self._rpc("readabs", got_s, 8)
        orig_i = int.from_bytes(bytes(orig), "little")
        fcave = self._rpc("alloccave", 128)
        fc = b""
        fc += self._load_imm64(16, fabs)                              # x16 = F line
        fc += struct.pack("<I", 0xD50B7B20 | 16)                      # dc cvau, x16
        fc += struct.pack("<I", 0xD5033B9F)                           # dsb ish
        fc += struct.pack("<I", 0xD50B7520 | 16)                      # ic ivau, x16
        fc += struct.pack("<I", 0xD5033B9F)                           # dsb ish
        fc += struct.pack("<I", 0xD5033FDF)                           # isb
        fc += struct.pack("<I", 0x58000051)                           # ldr x17,#8
        fc += struct.pack("<I", 0xD61F0220)                           # br x17
        fc += struct.pack("<Q", orig_i)
        self._rpc("writeabs", fcave, list(fc))
        self._rpc("writeabs", got_s, list(struct.pack("<Q", int(fcave, 0))))
        print(f"  Flush cave on GOT 0x{got_off:08x} -> {fcave} (orig 0x{orig_i:x})")
        print("  Watching counter 6s ...")
        last = 0
        try:
            for i in range(12):
                time.sleep(0.5)
                v = self._rpc("readabs", cmbox, 8)
                cnt = int.from_bytes(bytes(v), "little") if v else -1
                print(f"    t={i * 0.5:>4.1f}s  counter={cnt}")
                last = cnt
        finally:
            self._rpc("writeabs", got_s, list(struct.pack("<Q", orig_i)))
            print("  GOT slot restored (F stays trampolined, harmless)")
        if last > 0:
            print("  >>> SUCCESS: cache flush works. We can hook ANY function.")
        else:
            print("  >>> Counter 0: Houdini ignores guest IC/DC. Use data hooks only.")

    def _flush_line_once(self, base, addr_abs, got_off=0x015057f0):
        """Force Houdini to re-translate the cache line at addr_abs by running
        DC CVAU / IC IVAU from a one-shot cave installed on a hot GOT slot."""
        got_abs = base + got_off
        got_s = f"0x{got_abs:x}"
        orig = self._rpc("readabs", got_s, 8)
        orig_i = int.from_bytes(bytes(orig), "little")
        fc = b""
        fc += self._load_imm64(16, addr_abs)
        fc += struct.pack("<I", 0xD50B7B20 | 16)   # dc cvau, x16
        fc += struct.pack("<I", 0xD5033B9F)         # dsb ish
        fc += struct.pack("<I", 0xD50B7520 | 16)   # ic ivau, x16
        fc += struct.pack("<I", 0xD5033B9F)         # dsb ish
        fc += struct.pack("<I", 0xD5033FDF)         # isb
        fc += struct.pack("<I", 0x58000051)         # ldr x17, #8
        fc += struct.pack("<I", 0xD61F0220)         # br x17
        fc += struct.pack("<Q", orig_i)
        fcave = self._rpc("alloccave", 64)
        self._rpc("writeabs", fcave, list(fc))
        self._rpc("writeabs", got_s, list(struct.pack("<Q", int(fcave, 0))))
        time.sleep(0.4)
        self._rpc("writeabs", got_s, list(struct.pack("<Q", orig_i)))

    def _build_cmdlog_cave(self, mbox_i, stolen, ret_abs):
        """Cave for hooking tryToExecuteCommand(x0=this, x1=cmd, x2=bool).
        Logs this/cmd/vtable/[cmd+8..+32] into a ring, runs stolen prologue,
        returns to F+16. Uses only x9-x17 (caller-saved at function entry)."""
        N = 24

        def I(x):
            return struct.pack("<I", x & 0xFFFFFFFF)

        code = self._load_imm64(9, mbox_i)                          # 0..15  x9=mbox
        code += I(0xB4000000 | ((84 // 4) << 5) | 1)               # 16 cbz x1,+84
        code += I(0xB9400000 | (9 << 5) | 10)                      # 20 ldr w10,[x9]
        code += I(0x71000000 | (N << 10) | (10 << 5) | 31)         # 24 cmp w10,#N
        code += I(0x54000000 | ((72 // 4) << 5) | 2)               # 28 b.hs +72
        code += I(0xD3400000 | (58 << 16) | (57 << 10) | (10 << 5) | 11)  # 32 lsl x11,x10,#6
        code += I(0x8B000000 | (11 << 16) | (9 << 5) | 11)         # 36 add x11,x9,x11
        code += I(0x91000000 | (8 << 10) | (11 << 5) | 11)         # 40 add x11,x11,#8
        code += I(0xF9000000 | (11 << 5) | 0)                      # 44 str x0,[x11]
        code += I(0xF9000000 | (1 << 10) | (11 << 5) | 1)          # 48 str x1,[x11,#8]
        code += I(0xF9400000 | (1 << 5) | 12)                      # 52 ldr x12,[x1]
        code += I(0xF9000000 | (2 << 10) | (11 << 5) | 12)         # 56 str x12,[x11,#16]
        code += I(0xF9400000 | (1 << 10) | (1 << 5) | 12)          # 60 ldr x12,[x1,#8]
        code += I(0xF9000000 | (3 << 10) | (11 << 5) | 12)         # 64 str x12,[x11,#24]
        code += I(0xF9400000 | (2 << 10) | (1 << 5) | 12)          # 68 ldr x12,[x1,#16]
        code += I(0xF9000000 | (4 << 10) | (11 << 5) | 12)         # 72 str x12,[x11,#32]
        code += I(0xF9400000 | (3 << 10) | (1 << 5) | 12)          # 76 ldr x12,[x1,#24]
        code += I(0xF9000000 | (5 << 10) | (11 << 5) | 12)         # 80 str x12,[x11,#40]
        code += I(0xF9400000 | (4 << 10) | (1 << 5) | 12)          # 84 ldr x12,[x1,#32]
        code += I(0xF9000000 | (6 << 10) | (11 << 5) | 12)         # 88 str x12,[x11,#48]
        code += I(0x11000000 | (1 << 10) | (10 << 5) | 10)         # 92 add w10,w10,#1
        code += I(0xB9000000 | (9 << 5) | 10)                      # 96 str w10,[x9]
        code += stolen                                             # 100 stolen (16)
        code += I(0x58000051)                                      # 116 ldr x17,#8
        code += I(0xD61F0220)                                      # 120 br x17
        code += struct.pack("<Q", ret_abs)                         # 124 .quad F+16
        return code

    def cmd_cmdhook(self, args):
        """Install a persistent inline hook on tryToExecuteCommand that logs
        every command (this/cmd/vtable/params) into a ring buffer."""
        F = 0x00ae3bc4
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        fabs = base + F

        mbox = self._rpc("alloccave", 2048)
        self._rpc("writeabs", mbox, [0] * 8)
        stolen = bytes(self._rpc("readbytes", str(F), "16"))
        if len(stolen) != 16:
            print("  FAIL: stolen bytes")
            return
        cave = self._rpc("alloccave", 256)
        sc = self._build_cmdlog_cave(int(mbox, 0), stolen, fabs + 16)
        self._rpc("writeabs", cave, list(sc))
        self._rpc("farjump", str(F), cave)
        self._flush_line_once(base, fabs)
        self.cmdlog_mbox = mbox
        print(f"  Hooked tryToExecuteCommand @ 0x{F:08x}")
        print(f"  Command ring @ {mbox}")
        print("  >>> Now PLANT WHEAT in-game, then run: cmdlog")

    def cmd_cmdlog(self, args):
        if not self.cmdlog_mbox:
            print("  Run cmdhook first.")
            return
        mbox_i = int(self.cmdlog_mbox, 0)
        base = self.engine_base
        size = 0x1654c00
        head = self._rpc("readabs", self.cmdlog_mbox, 8)
        idx = int.from_bytes(bytes(head)[:4], "little")
        print(f"  {idx} command(s) captured:")
        for i in range(min(idx, 24)):
            eab = mbox_i + 8 + i * 64
            e = self._rpc("readabs", f"0x{eab:x}", 56)
            this, cmd, vt, m8, m16, m24, m32 = struct.unpack("<7Q", bytes(e))
            if base and base <= vt < base + size:
                vtxt = f"vtbl+0x{vt - base:08x}"
            else:
                vtxt = f"vtbl=0x{vt:x}"
            print(f"    [{i:2d}] {vtxt}  params=[0x{m8:x} 0x{m16:x} 0x{m24:x} 0x{m32:x}]")
        print("  (vtbl offset identifies the command class)")

    def _build_capture_cave(self, mbox_i, stolen, ret_abs):
        """Hook tryToExecuteCommand(x1=cmd): copy the command's first 0x40 bytes
        (vtable at +0, params at +0x24/+0x28) into a ring. No stack frame; uses
        x9-x12 (caller-saved at entry), does not touch x0-x2."""
        N = 24
        prog = []

        def emit(x):
            prog.append(("w", x & 0xFFFFFFFF))

        def li(rd, v):
            for x in self._le_words(self._load_imm64(rd, v)):
                emit(x)

        li(9, mbox_i)                                   # x9 = mbox
        prog.append(("cbzx", 1, "done"))               # cbz x1, done
        emit(0xB9400000 | (9 << 5) | 10)               # ldr w10,[x9] idx
        emit(0x71000000 | (N << 10) | (10 << 5) | 31)  # cmp w10,#N
        prog.append(("bhs", "done"))                   # b.hs done
        emit(0xD3400000 | (58 << 16) | (57 << 10) | (10 << 5) | 11)  # lsl x11,x10,#6
        emit(0x8B000000 | (11 << 16) | (9 << 5) | 11)  # add x11,x9,x11
        emit(0x91000000 | (8 << 10) | (11 << 5) | 11)  # add x11,x11,#8
        for k in range(8):                             # copy [x1+0..+0x38]
            emit(0xF9400000 | (k << 10) | (1 << 5) | 12)   # ldr x12,[x1,#k*8]
            emit(0xF9000000 | (k << 10) | (11 << 5) | 12)  # str x12,[x11,#k*8]
        emit(0x11000000 | (1 << 10) | (10 << 5) | 10)  # add w10,#1
        emit(0xB9000000 | (9 << 5) | 10)               # str w10,[x9]
        prog.append(("L", "done"))
        for i in range(0, 16, 4):
            emit(int.from_bytes(stolen[i:i + 4], "little"))
        emit(0x58000051)                               # ldr x17,#8
        emit(0xD61F0220)                               # br x17
        offs = {}
        n = 0
        for e in prog:
            if e[0] == "L":
                offs[e[1]] = n * 4
            else:
                n += 1
        words = []
        idx = 0
        for e in prog:
            if e[0] == "L":
                continue
            cur = idx * 4
            idx += 1
            if e[0] == "w":
                words.append(e[1])
            elif e[0] == "cbzx":
                d = (offs[e[2]] - cur) // 4
                words.append(0xB4000000 | ((d & 0x7FFFF) << 5) | e[1])
            elif e[0] == "bhs":
                d = (offs[e[1]] - cur) // 4
                words.append(0x54000000 | ((d & 0x7FFFF) << 5) | 2)
        return b"".join(struct.pack("<I", x) for x in words) + struct.pack("<Q", ret_abs)

    def cmd_capture(self, args):
        """Capture the raw commands passed to tryToExecuteCommand while you do an
        action in-game (e.g. harvest). Re-arms the hook every ~0.8s (Promon
        reverts it) so it stays live for the whole window."""
        secs = int(args[0]) if args and args[0].isdigit() else 12
        F = 0x00ae3bc4
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        fabs = base + F
        mbox = self._rpc("alloccave", 2048)
        self._rpc("writeabs", mbox, [0] * 8)
        stolen = self._read_stolen(F)
        if stolen is None:
            print("  FAIL: tryToExecuteCommand prologue not relocatable (restart the game)")
            return
        cave = self._rpc("alloccave", 256)
        self._rpc("writeabs", cave, list(self._build_capture_cave(int(mbox, 0), stolen, fabs + 16)))
        print(f"  Capturing tryToExecuteCommand for {secs}s -- DO THE ACTION (harvest a field) NOW...")
        deadline = time.monotonic() + secs
        while time.monotonic() < deadline:
            self._rpc("farjump", str(F), cave)
            self._flush_line_once(base, fabs)   # ~0.4s; keeps the patch fresh
            time.sleep(0.4)
        idx = int.from_bytes(bytes(self._rpc("readabs", mbox, 8))[:4], "little")
        size = 0x1654c00
        print(f"  {idx} command(s) captured:")
        seen = set()
        for i in range(min(idx, 24)):
            eab = int(mbox, 0) + 8 + i * 0x40
            e = self._rpc("readabs", f"0x{eab:x}", 0x40)
            if not e:
                continue
            qs = struct.unpack("<8Q", bytes(e))
            vt = qs[0]
            if base <= vt < base + size:
                vtxt = f"vtbl+0x{vt - base:08x}"
            else:
                vtxt = f"vtbl=0x{vt:x}"
            key = vt
            tag = "" if key not in seen else "  (dup)"
            seen.add(key)
            # params region: qs[4]=+0x20/+0x24, qs[5]=+0x28/+0x2c, qs[6]=+0x30/+0x34/+0x35
            p24 = (qs[4] >> 32) & 0xFFFFFFFF
            p28 = qs[5] & 0xFFFFFFFF
            p2c = (qs[5] >> 32) & 0xFFFFFFFF
            p30 = qs[6] & 0xFFFFFFFF
            p34 = (qs[6] >> 32) & 0xFF
            p35 = (qs[6] >> 40) & 0xFF
            print(f"    [{i:2d}] {vtxt}  +24={p24} +28={p28} +2c={p2c} "
                  f"+30={p30} +34={p34} +35={p35}{tag}")

    def _build_arghook_cave(self, mbox_i, stolen, ret_abs):
        """Log x0-x7 (no dereference) into a ring for any hooked function.
        Uses only x9-x17 (caller-saved at entry)."""
        N = 24

        def I(x):
            return struct.pack("<I", x & 0xFFFFFFFF)

        code = self._load_imm64(9, mbox_i)                          # 0..15  x9=mbox
        code += I(0xB9400000 | (9 << 5) | 10)                      # 16 ldr w10,[x9]
        code += I(0x71000000 | (N << 10) | (10 << 5) | 31)         # 20 cmp w10,#N
        code += I(0x54000000 | ((40 // 4) << 5) | 2)               # 24 b.hs +40
        code += I(0xD3400000 | (58 << 16) | (57 << 10) | (10 << 5) | 11)  # 28 lsl x11,x10,#6
        code += I(0x8B000000 | (11 << 16) | (9 << 5) | 11)         # 32 add x11,x9,x11
        code += I(0x91000000 | (8 << 10) | (11 << 5) | 11)         # 36 add x11,x11,#8
        code += I(0xA9000000 | (1 << 10) | (11 << 5) | 0)          # 40 stp x0,x1,[x11]
        code += I(0xA9000000 | (2 << 15) | (3 << 10) | (11 << 5) | 2)   # 44 stp x2,x3,[x11,#16]
        code += I(0xA9000000 | (4 << 15) | (5 << 10) | (11 << 5) | 4)   # 48 stp x4,x5,[x11,#32]
        code += I(0xA9000000 | (6 << 15) | (7 << 10) | (11 << 5) | 6)   # 52 stp x6,x7,[x11,#48]
        code += I(0x11000000 | (1 << 10) | (10 << 5) | 10)         # 56 add w10,w10,#1
        code += I(0xB9000000 | (9 << 5) | 10)                      # 60 str w10,[x9]
        code += stolen                                             # 64 stolen (16)
        code += I(0x58000051)                                      # 80 ldr x17,#8
        code += I(0xD61F0220)                                      # 84 br x17
        code += struct.pack("<Q", ret_abs)                         # 88 .quad F+16
        return code

    def cmd_arghook(self, args):
        """Install a persistent x0-x7 logger on any libg.so function offset."""
        if not args:
            print("  Usage: arghook <func_off>")
            return
        F = int(args[0], 16) if args[0].lower().startswith("0x") else int(args[0], 0)
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        fabs = base + F
        mbox = self._rpc("alloccave", 2048)
        self._rpc("writeabs", mbox, [0] * 8)
        stolen = bytes(self._rpc("readbytes", str(F), "16"))
        if len(stolen) != 16:
            print("  FAIL: stolen bytes")
            return
        cave = self._rpc("alloccave", 256)
        sc = self._build_arghook_cave(int(mbox, 0), stolen, fabs + 16)
        self._rpc("writeabs", cave, list(sc))
        self._rpc("farjump", str(F), cave)
        self._flush_line_once(base, fabs)
        self.cmdlog_mbox = mbox
        print(f"  Arg-hooked 0x{F:08x}; ring @ {mbox}")
        print("  Trigger the action in-game, then run: arglog")

    def cmd_arglog(self, args):
        if not self.cmdlog_mbox:
            print("  Run arghook first.")
            return
        mbox_i = int(self.cmdlog_mbox, 0)
        base = self.engine_base
        size = 0x1654c00
        idx = int.from_bytes(bytes(self._rpc("readabs", self.cmdlog_mbox, 8))[:4], "little")
        print(f"  {idx} call(s) captured:")
        for i in range(min(idx, 24)):
            eab = mbox_i + 8 + i * 64
            regs = struct.unpack("<8Q", bytes(self._rpc("readabs", f"0x{eab:x}", 64)))
            parts = []
            for r, v in enumerate(regs):
                if base and base <= v < base + size:
                    parts.append(f"x{r}=lib+0x{v - base:x}")
                elif v < 0x100000000:
                    parts.append(f"x{r}={v}")
                else:
                    parts.append(f"x{r}=0x{v:x}")
            print(f"    [{i:2d}] " + "  ".join(parts))

    def _build_plant_cave(self, mbox_i, stolen, base, fabs):
        """Call-gate hooked on tryToExecuteCommand(x0=gameMode,...). When the
        mailbox flag is set, loop i=0..count-1 doing new(0x30) ->
        PlantCommand_ctor(cmd, startField+i, crop, 0) ->
        tryToExecuteCommand(gameMode, cmd, 0), then clear the flag. This plants
        a whole range of fields in one trigger. Mailbox: +0 flag, +8 start,
        +0x10 crop, +0x18 heartbeat, +0x1c count. Uses a saved-context frame;
        loop vars live at [sp,#0x58]=count, [sp,#0x5c]=i, [sp,#0x50]=cmd."""
        NEW = base + 0x141c480
        TRY = base + 0x00ae3bc4
        prog = []

        def emit(x):
            prog.append(("w", x & 0xFFFFFFFF))

        def li(rd, v):
            for x in self._le_words(self._load_imm64(rd, v)):
                emit(x)

        def mvz(rd, imm):
            emit(0x52800000 | ((imm & 0xFFFF) << 5) | rd)          # mov Wd,#imm

        def lbl(n):
            prog.append(("L", n))

        emit(0xD1000000 | (0x70 << 10) | (31 << 5) | 31)          # sub sp,sp,#0x70
        emit(0xA9000000 | (1 << 10) | (31 << 5) | 0)              # stp x0,x1,[sp]
        emit(0xA9000000 | (2 << 15) | (3 << 10) | (31 << 5) | 2)
        emit(0xA9000000 | (4 << 15) | (5 << 10) | (31 << 5) | 4)
        emit(0xA9000000 | (6 << 15) | (7 << 10) | (31 << 5) | 6)
        emit(0xA9000000 | (8 << 15) | (30 << 10) | (31 << 5) | 8)
        emit(0xFD000000 | ((0x60 // 8) << 10) | (31 << 5) | 0)    # str d0,[sp,#0x60] (dt)
        li(9, mbox_i)
        emit(0xF9000000 | (1 << 10) | (9 << 5) | 0)               # str x0,[x9,#8] gameMode
        emit(0xB9400000 | (6 << 10) | (9 << 5) | 12)              # ldr w12,[x9,#0x18]
        emit(0x11000000 | (1 << 10) | (12 << 5) | 12)             # add w12,#1
        emit(0xB9000000 | (6 << 10) | (9 << 5) | 12)              # str w12,[x9,#0x18]
        emit(0xB9400000 | (9 << 5) | 10)                          # ldr w10,[x9] flag
        prog.append(("cbz", 10, "rest"))
        emit(0xB9000000 | (9 << 5) | 31)                          # str wzr,[x9] clear flag
        emit(0xB9400000 | (7 << 10) | (9 << 5) | 13)              # ldr w13,[x9,#0x1c] count
        emit(0xB9000000 | ((0x58 // 4) << 10) | (31 << 5) | 13)   # str w13,[sp,#0x58]
        emit(0xB9000000 | ((0x5c // 4) << 10) | (31 << 5) | 31)   # str wzr,[sp,#0x5c] i=0
        lbl("loop")
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c] i
        emit(0xB9400000 | ((0x58 // 4) << 10) | (31 << 5) | 14)   # ldr w14,[sp,#0x58] count
        emit(0x6B00001F | (14 << 16) | (13 << 5))                 # cmp w13,w14
        prog.append(("bge", "rest"))
        mvz(0, 0x30)                                              # mov w0,#0x30
        li(11, NEW)
        emit(0xD63F0000 | (11 << 5))                              # blr new
        emit(0xF9000000 | ((0x50 // 8) << 10) | (31 << 5) | 0)    # str x0,[sp,#0x50] cmd
        emit(0xF9400000 | ((0x50 // 8) << 10) | (31 << 5) | 0)    # ldr x0,[sp,#0x50]
        li(9, mbox_i)
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c] i
        emit(0x8B000000 | (13 << 16) | (2 << 10) | (9 << 5) | 14)  # add x14,x9,x13,lsl#2
        emit(0xB9400000 | ((0x28 // 4) << 10) | (14 << 5) | 1)    # ldr w1,[x14,#0x28] ids[i]
        emit(0xB9400000 | (4 << 10) | (9 << 5) | 2)               # ldr w2,[x9,#0x10] crop
        mvz(3, 0)                                                 # mov w3,#0
        emit(0xF9400000 | ((0x20 // 8) << 10) | (9 << 5) | 11)    # ldr x11,[x9,#0x20] ctor from mailbox
        emit(0xD63F0000 | (11 << 5))                              # blr ctor
        emit(0xF9400000 | (31 << 5) | 0)                          # ldr x0,[sp] gameMode
        emit(0xF9400000 | ((0x50 // 8) << 10) | (31 << 5) | 1)    # ldr x1,[sp,#0x50] cmd
        mvz(2, 0)                                                 # mov w2,#0
        li(11, TRY)
        emit(0xD63F0000 | (11 << 5))                              # blr tryToExec
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c]
        emit(0x11000000 | (1 << 10) | (13 << 5) | 13)             # add w13,#1
        emit(0xB9000000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # str w13,[sp,#0x5c]
        prog.append(("b", "loop"))
        lbl("rest")
        emit(0xFD400000 | ((0x60 // 8) << 10) | (31 << 5) | 0)    # ldr d0,[sp,#0x60] (dt)
        emit(0xA9400000 | (1 << 10) | (31 << 5) | 0)              # ldp x0,x1,[sp]
        emit(0xA9400000 | (2 << 15) | (3 << 10) | (31 << 5) | 2)
        emit(0xA9400000 | (4 << 15) | (5 << 10) | (31 << 5) | 4)
        emit(0xA9400000 | (6 << 15) | (7 << 10) | (31 << 5) | 6)
        emit(0xA9400000 | (8 << 15) | (30 << 10) | (31 << 5) | 8)
        emit(0x91000000 | (0x70 << 10) | (31 << 5) | 31)          # add sp,sp,#0x70
        for i in range(0, 16, 4):
            emit(int.from_bytes(stolen[i:i + 4], "little"))       # stolen prologue
        emit(0x58000051)                                          # ldr x17,#8
        emit(0xD61F0220)                                          # br x17

        offs = {}
        n = 0
        for e in prog:
            if e[0] == "L":
                offs[e[1]] = n * 4
            else:
                n += 1
        words = []
        idx = 0
        for e in prog:
            if e[0] == "L":
                continue
            cur = idx * 4
            idx += 1
            if e[0] == "w":
                words.append(e[1])
            elif e[0] == "b":
                d = (offs[e[1]] - cur) // 4
                words.append(0x14000000 | (d & 0x03FFFFFF))
            elif e[0] == "bge":
                d = (offs[e[1]] - cur) // 4
                words.append(0x54000000 | ((d & 0x7FFFF) << 5) | 0xA)
            elif e[0] == "cbz":
                d = (offs[e[2]] - cur) // 4
                words.append(0x34000000 | ((d & 0x7FFFF) << 5) | e[1])
        code = b"".join(struct.pack("<I", x) for x in words)
        code += struct.pack("<Q", fabs + 16)
        return code

    def _build_sell_cave(self, mbox_i, stolen, base, fabs):
        """Call-gate on the tick that puts items up for sale in roadside-shop
        crates. Same save/restore/heartbeat/flag frame as the plant cave, but the
        loop body does new(0x38) -> SellCommand_ctor(cmd, slot, item, count,
        price, ad, flag6) -> tryToExecuteCommand for each slot. Mailbox: +0 flag,
        +8 gameMode, +0x10 item, +0x14 count, +0x18 heartbeat, +0x1c slotcount,
        +0x20 price, +0x24 ad(u8), +0x25 flag6(u8), +0x28 ctor, +0x30.. slots."""
        NEW = base + 0x141c480
        TRY = base + 0x00ae3bc4
        prog = []

        def emit(x):
            prog.append(("w", x & 0xFFFFFFFF))

        def li(rd, v):
            for x in self._le_words(self._load_imm64(rd, v)):
                emit(x)

        def mvz(rd, imm):
            emit(0x52800000 | ((imm & 0xFFFF) << 5) | rd)

        def lbl(n):
            prog.append(("L", n))

        emit(0xD1000000 | (0x70 << 10) | (31 << 5) | 31)          # sub sp,sp,#0x70
        emit(0xA9000000 | (1 << 10) | (31 << 5) | 0)              # stp x0,x1,[sp]
        emit(0xA9000000 | (2 << 15) | (3 << 10) | (31 << 5) | 2)
        emit(0xA9000000 | (4 << 15) | (5 << 10) | (31 << 5) | 4)
        emit(0xA9000000 | (6 << 15) | (7 << 10) | (31 << 5) | 6)
        emit(0xA9000000 | (8 << 15) | (30 << 10) | (31 << 5) | 8)
        emit(0xFD000000 | ((0x60 // 8) << 10) | (31 << 5) | 0)    # str d0,[sp,#0x60]
        li(9, mbox_i)
        emit(0xF9000000 | (1 << 10) | (9 << 5) | 0)               # str x0,[x9,#8] gameMode
        emit(0xB9400000 | (6 << 10) | (9 << 5) | 12)              # ldr w12,[x9,#0x18]
        emit(0x11000000 | (1 << 10) | (12 << 5) | 12)             # add w12,#1
        emit(0xB9000000 | (6 << 10) | (9 << 5) | 12)              # str w12,[x9,#0x18] heartbeat
        emit(0xB9400000 | (9 << 5) | 10)                          # ldr w10,[x9] flag
        prog.append(("cbz", 10, "rest"))
        emit(0xB9000000 | (9 << 5) | 31)                          # str wzr,[x9] clear flag
        emit(0xB9400000 | (7 << 10) | (9 << 5) | 13)              # ldr w13,[x9,#0x1c] slotcount
        emit(0xB9000000 | ((0x58 // 4) << 10) | (31 << 5) | 13)   # str w13,[sp,#0x58]
        emit(0xB9000000 | ((0x5c // 4) << 10) | (31 << 5) | 31)   # str wzr,[sp,#0x5c] i=0
        lbl("loop")
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c] i
        emit(0xB9400000 | ((0x58 // 4) << 10) | (31 << 5) | 14)   # ldr w14,[sp,#0x58] slotcount
        emit(0x6B00001F | (14 << 16) | (13 << 5))                 # cmp w13,w14
        prog.append(("bge", "rest"))
        mvz(0, 0x38)                                              # mov w0,#0x38
        li(11, NEW)
        emit(0xD63F0000 | (11 << 5))                              # blr new  -> x0=cmd
        emit(0xF9000000 | ((0x50 // 8) << 10) | (31 << 5) | 0)    # str x0,[sp,#0x50] cmd
        emit(0xF9400000 | ((0x50 // 8) << 10) | (31 << 5) | 0)    # ldr x0,[sp,#0x50] this
        li(9, mbox_i)
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c] i
        emit(0x8B000000 | (13 << 16) | (2 << 10) | (9 << 5) | 14)  # add x14,x9,x13,lsl#2
        emit(0xB9400000 | ((0x30 // 4) << 10) | (14 << 5) | 1)    # ldr w1,[x14,#0x30] slots[i]
        emit(0xB9400000 | ((0x10 // 4) << 10) | (9 << 5) | 2)     # ldr w2,[x9,#0x10] item
        emit(0xB9400000 | ((0x14 // 4) << 10) | (9 << 5) | 3)     # ldr w3,[x9,#0x14] count
        emit(0xB9400000 | ((0x20 // 4) << 10) | (9 << 5) | 4)     # ldr w4,[x9,#0x20] price
        emit(0x39400000 | (0x24 << 10) | (9 << 5) | 5)            # ldrb w5,[x9,#0x24] ad
        emit(0x39400000 | (0x25 << 10) | (9 << 5) | 6)            # ldrb w6,[x9,#0x25] flag6
        emit(0xF9400000 | ((0x28 // 8) << 10) | (9 << 5) | 11)    # ldr x11,[x9,#0x28] ctor
        emit(0xD63F0000 | (11 << 5))                              # blr ctor
        emit(0xF9400000 | (31 << 5) | 0)                          # ldr x0,[sp] gameMode
        emit(0xF9400000 | ((0x50 // 8) << 10) | (31 << 5) | 1)    # ldr x1,[sp,#0x50] cmd
        mvz(2, 0)                                                 # mov w2,#0
        li(11, TRY)
        emit(0xD63F0000 | (11 << 5))                              # blr tryToExec
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c]
        emit(0x11000000 | (1 << 10) | (13 << 5) | 13)             # add w13,#1
        emit(0xB9000000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # str w13,[sp,#0x5c]
        prog.append(("b", "loop"))
        lbl("rest")
        emit(0xFD400000 | ((0x60 // 8) << 10) | (31 << 5) | 0)    # ldr d0,[sp,#0x60]
        emit(0xA9400000 | (1 << 10) | (31 << 5) | 0)              # ldp x0,x1,[sp]
        emit(0xA9400000 | (2 << 15) | (3 << 10) | (31 << 5) | 2)
        emit(0xA9400000 | (4 << 15) | (5 << 10) | (31 << 5) | 4)
        emit(0xA9400000 | (6 << 15) | (7 << 10) | (31 << 5) | 6)
        emit(0xA9400000 | (8 << 15) | (30 << 10) | (31 << 5) | 8)
        emit(0x91000000 | (0x70 << 10) | (31 << 5) | 31)          # add sp,sp,#0x70
        for i in range(0, 16, 4):
            emit(int.from_bytes(stolen[i:i + 4], "little"))       # stolen prologue
        emit(0x58000051)                                          # ldr x17,#8
        emit(0xD61F0220)                                          # br x17

        offs = {}
        n = 0
        for e in prog:
            if e[0] == "L":
                offs[e[1]] = n * 4
            else:
                n += 1
        words = []
        idx = 0
        for e in prog:
            if e[0] == "L":
                continue
            cur = idx * 4
            idx += 1
            if e[0] == "w":
                words.append(e[1])
            elif e[0] == "b":
                d = (offs[e[1]] - cur) // 4
                words.append(0x14000000 | (d & 0x03FFFFFF))
            elif e[0] == "bge":
                d = (offs[e[1]] - cur) // 4
                words.append(0x54000000 | ((d & 0x7FFFF) << 5) | 0xA)
            elif e[0] == "cbz":
                d = (offs[e[2]] - cur) // 4
                words.append(0x34000000 | ((d & 0x7FFFF) << 5) | e[1])
        code = b"".join(struct.pack("<I", x) for x in words)
        code += struct.pack("<Q", fabs + 16)
        return code

    @staticmethod
    def _le_words(byte_seq):
        return [int.from_bytes(byte_seq[i:i + 4], "little") for i in range(0, len(byte_seq), 4)]

    @staticmethod
    def _stolen_is_pi(stolen):
        """True if the 16 stolen bytes are 4 position-independent ARM64 instrs
        (safe to relocate into a cave). Rejects ADRP/ADR/B/BL/B.cond/CBZ/CBNZ/
        TBZ/TBNZ/LDR-literal, which would break when moved."""
        for i in range(0, 16, 4):
            w = int.from_bytes(stolen[i:i + 4], "little")
            if w & 0x9F000000 == 0x90000000:  # ADRP
                return False
            if w & 0x9F000000 == 0x10000000:  # ADR
                return False
            if w & 0xFC000000 == 0x14000000:  # B
                return False
            if w & 0xFC000000 == 0x94000000:  # BL
                return False
            if w & 0xFF000010 == 0x54000000:  # B.cond
                return False
            if w & 0x7E000000 == 0x34000000:  # CBZ/CBNZ
                return False
            if w & 0x7E000000 == 0x36000000:  # TBZ/TBNZ
                return False
            if w & 0x3B000000 == 0x18000000:  # LDR (literal)
                return False
        return True

    def _read_stolen(self, F, tries=10):
        """Read the 16-byte prologue at offset F, retrying if it is not
        position-independent. A leftover far-jump from a previous run (game not
        fully restarted) or a transient Promon patch makes the prologue a branch;
        Promon reverts inline patches within ~1.5s, so we wait and re-read."""
        for i in range(tries):
            stolen = bytes(self._rpc("readbytes", str(F), "16"))
            if len(stolen) == 16 and self._stolen_is_pi(stolen):
                return stolen
            if i == 0:
                print("  prologue patched (leftover hook?); waiting for revert...")
            time.sleep(0.8)
        return None

    def _install_plant_gate(self):
        # Build the call-gate cave for the main game tick (x0 = GameMode at
        # entry, before the command-drain loop: a safe, per-frame context).
        # We do NOT leave the inline patch in place — Promon SHIELD reverts code
        # patches after ~1.5s — so the patch is (re)applied per plant by _arm_hook.
        F = 0x00ae2430
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        self.plant_base = base
        self.plant_F = F
        fabs = base + F
        mbox = self._rpc("alloccave", 512)  # header + up to ~120 field ids
        self._rpc("writeabs", mbox, [0] * 32)
        stolen = self._read_stolen(F)
        if stolen is None:
            raise LoaderError("tick prologue not relocatable (leftover hook not reverting; "
                              "fully restart the game and retry)")
        cave = self._rpc("alloccave", 384)
        sc = self._build_plant_cave(int(mbox, 0), stolen, base, fabs)
        self._rpc("writeabs", cave, list(sc))
        self.plant_cave = cave
        self.plant_mbox = mbox
        print(f"  Plant gate built on main game tick; mbox {mbox}")

    def _install_sell_gate(self):
        """Install the roadside-shop sell gate on the same tick (own cave+mbox).
        Only one cave is farjumped into the tick at a time; each command re-arms
        its own before firing, so the plant and sell gates coexist."""
        F = 0x00ae2430
        if not self.plant_base:
            self.plant_base = int(str(self._rpc("info")["base"]), 0)
        base = self.plant_base
        self.sell_F = F
        fabs = base + F
        mbox = self._rpc("alloccave", 512)
        self._rpc("writeabs", mbox, [0] * 32)
        stolen = self._read_stolen(F)
        if stolen is None:
            raise LoaderError("tick prologue not relocatable (fully restart the game and retry)")
        cave = self._rpc("alloccave", 512)
        self._rpc("writeabs", cave, list(self._build_sell_cave(int(mbox, 0), stolen, base, fabs)))
        self.sell_cave = cave
        self.sell_mbox = mbox
        print(f"  Sell gate built on main game tick; mbox {mbox}")

    def _arm_hook(self, F=None, cave=None, mbox=None):
        """(Re)apply the inline tick patch and flush its translation, then wait
        until the hook is confirmed live via the cave heartbeat. Promon reverts
        code patches after ~1.5s, so we re-arm on every use just before firing.
        Defaults to the plant gate; pass F/cave/mbox to arm the sell gate."""
        F = F if F is not None else self.plant_F
        cave = cave or self.plant_cave
        mbox = mbox or self.plant_mbox
        base = self.plant_base
        fabs = base + F
        hb_addr = f"0x{int(mbox, 0) + 0x18:x}"
        hb0 = int.from_bytes(bytes(self._rpc("readabs", hb_addr, 4)), "little")
        self._rpc("farjump", str(F), cave)
        got_abs = base + 0x015057f0
        got_s = f"0x{got_abs:x}"
        orig_i = int.from_bytes(bytes(self._rpc("readabs", got_s, 8)), "little")
        fc = self._load_imm64(16, fabs)
        fc += struct.pack("<I", 0xD50B7B20 | 16)   # dc cvau, x16
        fc += struct.pack("<I", 0xD5033B9F)         # dsb ish
        fc += struct.pack("<I", 0xD50B7520 | 16)   # ic ivau, x16
        fc += struct.pack("<I", 0xD5033B9F)
        fc += struct.pack("<I", 0xD5033FDF)         # isb
        fc += struct.pack("<I", 0x58000051)         # ldr x17,#8
        fc += struct.pack("<I", 0xD61F0220)         # br x17
        fc += struct.pack("<Q", orig_i)
        fcave = self._rpc("alloccave", 64)
        self._rpc("writeabs", fcave, list(fc))
        self._rpc("writeabs", got_s, list(struct.pack("<Q", int(fcave, 0))))
        live = False
        for _ in range(20):
            time.sleep(0.1)
            hb = int.from_bytes(bytes(self._rpc("readabs", hb_addr, 4)), "little")
            if hb > hb0:
                live = True
                break
        self._rpc("writeabs", got_s, list(struct.pack("<Q", orig_i)))
        return live

    PLANT_CTOR = 0x00bf2d6c      # PlantCommand ctor(cmd, fieldId, cropId, 0)
    HARVEST_CTOR = 0x00be8b40    # HarvestCommand ctor(cmd, fieldId) [ignores crop]
    SELL_CTOR = 0x00bf4394       # SellCommand ctor(cmd, slot, item, count, price, ad, flag6)
    WHEAT_ITEM = 400001          # roadside-shop item id for wheat

    def _do_field_command(self, ctor_off, crop_id, name, explicit_ids=None):
        """Shared field-command driver. Installs+arms the tick gate (captures a
        fresh gameMode), enumerates fields (unless explicit_ids given), writes
        the command ctor + ids into the mailbox, then fires. The cave loops
        new(0x30) -> ctor(cmd, fieldId, crop, 0) -> tryToExecuteCommand for each
        field; the ctor is read from the mailbox so one gate serves plant/harvest.
        Mailbox: +0 flag, +8 gameMode, +0x10 crop, +0x18 heartbeat, +0x1c count,
        +0x20 ctor addr, +0x28.. u32 field ids."""
        if not self.plant_mbox:
            self._install_plant_gate()
        # Promon reverts the inline patch between uses -> arm each time. Not live
        # => gameMode at mbox+8 is stale; abort rather than act on it.
        if not self._arm_hook():
            print("  [!] Hook not live (open the farm screen and retry).")
            return
        m = int(self.plant_mbox, 0)
        if explicit_ids is None:
            ids = self._enumerate_fields(self._read_u64(m + 0x08))
            if not ids:
                print("  No fields found (in the farm?).")
                return
        else:
            ids = explicit_ids
        if len(ids) > 120:
            ids = ids[:120]
        ctor_abs = self.plant_base + ctor_off
        self._rpc("writeabs", f"0x{m + 0x10:x}", list(struct.pack("<I", crop_id)))
        self._rpc("writeabs", f"0x{m + 0x1c:x}", list(struct.pack("<I", len(ids))))
        self._rpc("writeabs", f"0x{m + 0x20:x}", list(struct.pack("<Q", ctor_abs)))
        self._rpc("writeabs", f"0x{m + 0x28:x}",
                  list(b"".join(struct.pack("<I", i) for i in ids)))
        self._rpc("writeabs", self.plant_mbox, list(struct.pack("<I", 1)))
        print(f"  {name}: {len(ids)} field(s): {ids[:20]}")
        for i in range(30):
            time.sleep(0.1)
            if int.from_bytes(bytes(self._rpc("readabs", self.plant_mbox, 4)), "little") == 0:
                print(f"  >>> DONE after {(i + 1) * 0.1:.2f}s ({len(ids)} field(s))")
                return
        print("  Flag still set after 3s (Promon may have reverted; retry).")

    def cmd_plant(self, args):
        if len(args) < 1:
            print("  Usage: plant <fieldId> [cropId]   |   plant all")
            print("         wheat cropId=400001; 'all' reads current field ids live")
            return
        crop_id = int(args[1], 0) if len(args) > 1 else 400001
        if args[0].lower() == "all":
            self._do_field_command(self.PLANT_CTOR, crop_id, "Plant")
        else:
            self._do_field_command(self.PLANT_CTOR, crop_id, "Plant",
                                   explicit_ids=[int(args[0], 0)])

    def cmd_harvest(self, args):
        if args and args[0].lower() != "all":
            self._do_field_command(self.HARVEST_CTOR, 0, "Harvest",
                                   explicit_ids=[int(args[0], 0)])
        else:
            self._do_field_command(self.HARVEST_CTOR, 0, "Harvest")

    def cmd_sell(self, args):
        """Put an item up for sale in a roadside-shop crate.
        Usage: sell <slot> [count=10] [price=1] [ad=0] [itemId=400001]
        Open the shop first. slot = crate index (0-based). ad=1 advertises."""
        if not args:
            print("  Usage: sell <slot> [count=10] [price=1] [ad=0] [item=400001]")
            print("         open the roadside shop first; slot is the crate index")
            return
        slot = int(args[0], 0)
        count = int(args[1], 0) if len(args) > 1 else 10
        price = int(args[2], 0) if len(args) > 2 else 1
        ad = 1 if len(args) > 3 and args[3].lower() not in ("0", "no", "false", "n") else 0
        item = int(args[4], 0) if len(args) > 4 else self.WHEAT_ITEM
        if not self.sell_mbox:
            self._install_sell_gate()
        if not self._arm_hook(self.sell_F, self.sell_cave, self.sell_mbox):
            print("  [!] Sell hook not live (open the shop screen and retry).")
            return
        m = int(self.sell_mbox, 0)
        ctor_abs = self.plant_base + self.SELL_CTOR
        self._rpc("writeabs", f"0x{m + 0x10:x}", list(struct.pack("<I", item)))
        self._rpc("writeabs", f"0x{m + 0x14:x}", list(struct.pack("<I", count)))
        self._rpc("writeabs", f"0x{m + 0x1c:x}", list(struct.pack("<I", 1)))     # slotcount
        self._rpc("writeabs", f"0x{m + 0x20:x}", list(struct.pack("<I", price)))
        self._rpc("writeabs", f"0x{m + 0x24:x}", [ad & 1, 1])                    # ad, flag6=1
        self._rpc("writeabs", f"0x{m + 0x28:x}", list(struct.pack("<Q", ctor_abs)))
        self._rpc("writeabs", f"0x{m + 0x30:x}", list(struct.pack("<I", slot)))
        self._rpc("writeabs", self.sell_mbox, list(struct.pack("<I", 1)))
        print(f"  Sell: item {item} x{count} @ {price} coin, slot {slot}, ad={ad}")
        for i in range(30):
            time.sleep(0.1)
            if int.from_bytes(bytes(self._rpc("readabs", self.sell_mbox, 4)), "little") == 0:
                print(f"  >>> DONE after {(i + 1) * 0.1:.2f}s")
                return
        print("  Flag still set after 3s (Promon may have reverted; retry).")

    def cmd_farm(self, args):
        """Auto-farm loop: harvest all -> plant all -> wait -> repeat until Ctrl+C.
        Harvest on non-ready fields and plant on occupied fields are safe no-ops,
        so the loop self-syncs from any starting state.
        Usage: farm [wait_seconds=120] [cropId=400001]"""
        wait = int(args[0], 0) if args and args[0].isdigit() else 128
        crop = int(args[1], 0) if len(args) > 1 else 400001
        print(f"  Auto-farm: harvest all -> plant all every {wait}s. Ctrl+C to stop.")
        cycle = 0
        try:
            while True:
                cycle += 1
                print(f"  === cycle {cycle} ===")
                # Enumerate ONCE and reuse for both, so harvest and plant always
                # act on the SAME field set (no split mismatch) and we pay the
                # field-finding cost once per cycle instead of twice.
                ids = self._enumerate_fields()
                if not ids:
                    print("  no fields found; retrying next cycle")
                else:
                    self._do_field_command(self.HARVEST_CTOR, 0, "Harvest", explicit_ids=ids)
                    self._do_field_command(self.PLANT_CTOR, crop, "Plant", explicit_ids=ids)
                left = wait
                while left > 0:
                    print(f"\r  growing... {left:3d}s ", end="", flush=True)
                    step = min(2, left)
                    time.sleep(step)
                    left -= step
                print("\r" + " " * 24 + "\r", end="")
        except KeyboardInterrupt:
            print(f"\n  Auto-farm stopped after {cycle} cycle(s).")

    FIELD_VTABLE_OFF = 0x14cfea0
    FIELD_ID_OFF = 0x10
    # gameMode -> field vector (std::vector<Field>, begin@+0 / end@+8), found by
    # findfields. Compile-time offsets, stable across sessions. Each Field is
    # 0x80 bytes with its global id at +0x10.
    FIELD_CHAIN = (0x10, 0x138, 0x10, 0x20)
    FIELD_STRIDE = 0x80

    def _read_u64(self, addr):
        v = self._rpc("readabs", f"0x{addr:x}", 8)
        if not v or len(v) < 8:
            return 0
        return int.from_bytes(bytes(v)[:8], "little")

    def _capture_gamemode(self):
        """Ensure the plant gate is installed+armed (its cave stores gameMode
        into the mailbox every tick), then read gameMode. No scanning."""
        if not self.plant_mbox:
            self._install_plant_gate()
        self._arm_hook()
        gm = self._read_u64(int(self.plant_mbox, 0) + 0x08)
        return gm

    def _contiguous_walk(self, first, vt_abs):
        """Walk the contiguous 0x80-stride Field array containing `first`."""
        start = first
        for _ in range(64):
            if self._read_u64(start - self.FIELD_STRIDE) == vt_abs:
                start -= self.FIELD_STRIDE
            else:
                break
        ids = []
        addr = start
        for _ in range(64):
            rec = self._rpc("readabs", f"0x{addr:x}", 0x18)
            if not rec or len(rec) < 0x18:
                break
            rb = bytes(rec)
            if int.from_bytes(rb[0:8], "little") != vt_abs:
                break
            val = int.from_bytes(rb[self.FIELD_ID_OFF:self.FIELD_ID_OFF + 4], "little")
            if 100000 <= val <= 5000000:
                ids.append(val)
            addr += self.FIELD_STRIDE
        return ids

    # Known gameMode->Field paths (offset chains). These are BFS-discovered and
    # vary by session/state, so we try each and validate the landing is a Field;
    # if none hit, _find_a_field BFS-searches. First entry reaches the real
    # 400000+ field array; second is the older (often transient) chain.
    FIELD_PATHS = (
        (0x10, 0x138, 0x0, 0x40, 0x0),
        (0x10, 0x138, 0x10, 0x20),
    )

    def _walk_path(self, gamemode, path, vt_abs):
        """Follow an offset chain from gameMode; return the landing if it is a
        Field, else 0."""
        p = gamemode
        for off in path:
            p = self._read_u64(p + off)
            if not p:
                return 0
        return p if self._read_u64(p) == vt_abs else 0

    def _read_batch(self, addrs, size=0x200):
        """Read `size` bytes at each address in one (batched) RPC. Returns a list
        of `size`-byte blobs aligned with addrs (zero-filled where unreadable)."""
        out = []
        B = 400
        for i in range(0, len(addrs), B):
            chunk = addrs[i:i + B]
            raw = self._rpc("readmany", [f"0x{a:x}" for a in chunk], size)
            raw = bytes(raw) if raw else b"\x00" * (len(chunk) * size)
            if len(raw) < len(chunk) * size:
                raw = raw + b"\x00" * (len(chunk) * size - len(raw))
            for k in range(len(chunk)):
                out.append(raw[k * size:(k + 1) * size])
        return out

    def _bfs_field(self, root, vt_abs, prefix=(), max_reads=20000):
        """Batched BFS from root over heap pointers to the FIRST Field-vtable
        object. Returns (addr, full_path) = prefix + offsets walked; else
        (0, None). Reads each BFS level in one round-trip (readmany)."""
        visited = {root}
        frontier = [(root, list(prefix))]
        reads = 0
        while frontier and reads < max_reads:
            segs = self._read_batch([a for a, _ in frontier])
            reads += len(frontier)
            nextf = []
            for (addr, path), data in zip(frontier, segs):
                qs = struct.unpack("<%dQ" % (len(data) // 8), data[:(len(data) // 8) * 8])
                if qs[0] == vt_abs:
                    return addr, path
                if len(path) - len(prefix) > 6:
                    continue
                for j, p in enumerate(qs):
                    if 0x700000000000 <= p < 0x800000000000 and p not in visited:
                        visited.add(p)
                        nextf.append((p, path + [j * 8]))
            frontier = nextf[:20000]
        return 0, None

    def _find_a_field(self, gamemode, vt_abs):
        """Return one live Field object address. Tries the cached path + known
        paths (instant), then a SHALLOW BFS rooted at the [gm+0x10]+0x138 manager
        (fast), then a full BFS from gameMode. Caches the winning path so the farm
        loop only pays the BFS once per field-array reallocation."""
        for path in ([self._cached_field_path] if self._cached_field_path else []) + list(self.FIELD_PATHS):
            f = self._walk_path(gamemode, path, vt_abs)
            if f:
                self._cached_field_path = tuple(path)
                return f
        mgr = self._read_u64(self._read_u64(gamemode + 0x10) + 0x138)
        if mgr:
            addr, path = self._bfs_field(mgr, vt_abs, prefix=(0x10, 0x138), max_reads=6000)
            if addr:
                self._cached_field_path = tuple(path)
                return addr
        addr, path = self._bfs_field(gamemode, vt_abs)
        if addr:
            self._cached_field_path = tuple(path)
        return addr

    # Each Field points at shared owner/manager objects via these offsets (same
    # value for every Field). BFS from an owner reaches ALL Fields across arenas,
    # so enumeration is robust to the array being split into separate blocks.
    FIELD_OWNER_OFFS = (0x38, 0x30, 0x48)

    def _bfs_collect_fields(self, root, vt_abs, max_reads=20000, max_depth=6):
        """Batched BFS from root, collecting EVERY Field-vtable object reached
        (does not recurse into Fields). Reads each level in one round-trip."""
        visited = {root}
        frontier = [root]
        found = set()
        reads = 0
        depth = 0
        while frontier and reads < max_reads and depth <= max_depth:
            segs = self._read_batch(frontier)
            reads += len(frontier)
            nextf = []
            for addr, data in zip(frontier, segs):
                qs = struct.unpack("<%dQ" % (len(data) // 8), data[:(len(data) // 8) * 8])
                if qs[0] == vt_abs:
                    found.add(addr)
                    continue
                for p in qs:
                    if 0x700000000000 <= p < 0x800000000000 and p not in visited:
                        visited.add(p)
                        nextf.append(p)
            frontier = nextf[:20000]
            depth += 1
        return found

    def _read_field_id(self, addr, vt_abs):
        rec = self._rpc("readabs", f"0x{addr:x}", 0x18)
        if not rec or len(rec) < 0x18:
            return None
        rb = bytes(rec)
        if int.from_bytes(rb[0:8], "little") != vt_abs:
            return None
        fid = int.from_bytes(rb[self.FIELD_ID_OFF:self.FIELD_ID_OFF + 4], "little")
        return fid if 100000 <= fid <= 5000000 else None

    def _enumerate_field_objs(self, gamemode=None):
        """Return [(addr, id)] for EVERY Field (sorted by id). Finds one Field,
        then collects all Fields three ways and unions them: the contiguous
        0x80-stride block, a single-arena scan, and a BFS from the Field's shared
        owner (Field+0x38 / +0x30) which reaches Fields in OTHER arenas too. The
        owner BFS is what makes a split field-array enumerate completely."""
        if gamemode is None:
            gamemode = self._capture_gamemode()
        if not gamemode:
            return []
        base = int(str(self._rpc("info")["base"]), 0)
        vt_abs = base + self.FIELD_VTABLE_OFF
        first = self._find_a_field(gamemode, vt_abs)
        if not first:
            return []
        objs = {}
        # 1) contiguous block around `first`
        start = first
        for _ in range(64):
            if self._read_u64(start - self.FIELD_STRIDE) == vt_abs:
                start -= self.FIELD_STRIDE
            else:
                break
        addr = start
        for _ in range(64):
            fid = self._read_field_id(addr, vt_abs)
            if fid is None:
                break
            objs[addr] = fid
            addr += self.FIELD_STRIDE
        # 2) single-arena scan around `first` -> every 0x80 Field in that heap
        # arena (all 18 live in one size-class arena, so this alone is usually
        # complete). scanone touches ONE game range, so it is Promon-safe; we do
        # NOT do scattered pointer-BFS here (that reads all over memory fast and
        # trips Promon into freezing the game).
        vt_pat = " ".join(f"{b:02X}" for b in struct.pack("<Q", vt_abs))
        for mm in (self._rpc("scanone", f"0x{first:x}", vt_pat, timeout=30.0) or []):
            a = int(mm, 0)
            if a not in objs:
                fid = self._read_field_id(a, vt_abs)
                if fid is not None:
                    objs[a] = fid
        # 3) slot-page walk. Each Field has a slot (Field+0x48) and the slot points
        # back at it (slot+8). Slots are allocated from PAGE-SIZED POOLS: eight
        # 0x200-byte slots per 4KB page. The Field objects themselves are also
        # page-chunked, so the contiguous walk above stops at a page boundary and
        # misses the rest - but the slots for those Fields usually sit in a page
        # we already know. Walking every slot of each known page therefore reaches
        # Fields whose objects live in other blocks, using ~8 targeted reads per
        # page (no scanning -> Promon-safe). Newly found Fields can reveal further
        # pages, so repeat until nothing new turns up.
        seen_pages = set()
        for _ in range(4):
            pages = set()
            for a in list(objs):
                s = self._read_u64(a + 0x48)
                if 0x700000000000 <= s < 0x800000000000:
                    pages.add(s & ~0xFFF)
            pages -= seen_pages
            if not pages:
                break
            seen_pages |= pages
            for pg in pages:
                for off in range(0, 0x1000, 0x200):
                    slot = pg + off
                    fp = self._read_u64(slot + 0x8)
                    if not (0x700000000000 <= fp < 0x800000000000):
                        continue
                    if fp in objs or self._read_u64(fp) != vt_abs:
                        continue
                    if self._read_u64(fp + 0x48) != slot:   # must agree both ways
                        continue
                    fid = self._read_field_id(fp, vt_abs)
                    if fid is not None:
                        objs[fp] = fid
        # 4) liveness filter: a LIVE Field's slot (Field+0x48) points back to it
        # (slot+0x8 == Field). Freed/stale Field objects still carry the vtable
        # and a plausible id but their slot was reassigned, so they fail this and
        # get dropped. Guarded: if the filter would kill everything (assumption
        # wrong), keep the unfiltered set instead.
        live = {}
        for a, fid in objs.items():
            slot = self._read_u64(a + 0x48)
            if 0x700000000000 <= slot < 0x800000000000 and self._read_u64(slot + 0x8) == a:
                live[a] = fid
        if live:
            objs = live
        return sorted(objs.items(), key=lambda kv: kv[1])

    def _enumerate_fields(self, gamemode=None):
        """Current field ids. Field ids are CONSECUTIVE within one generation,
        and freed Field objects from earlier cycles keep their old ids in memory,
        so a raw sweep can mix two generations (e.g. 400000-400023 stale plus
        400024-400047 live). Take the longest consecutive run, newest on a tie -
        that is the live generation.

        Never invent ids that were not actually observed: an earlier version
        gap-filled between min and max, which turned a 24-field farm into
        'nharvest -> 40' and fired commands at non-existent fields."""
        ids = sorted({fid for _, fid in self._enumerate_field_objs(gamemode)})
        runs, cur = [], []
        for i in ids:
            if cur and i == cur[-1] + 1:
                cur.append(i)
            else:
                if cur:
                    runs.append(cur)
                cur = [i]
        if cur:
            runs.append(cur)
        best = max(runs, key=lambda r: (len(r), r[-1])) if runs else []
        # Successive generations are numbered back-to-back (400000-400023 then
        # 400024-400047), so a stale generation merges into the same run. If the
        # run is far longer than the farm actually is, keep the NEWEST slice.
        prev = getattr(self, "_last_field_count", 0)
        if prev and len(best) > 1.5 * prev:
            best = best[-prev:]
        self.current_fields = best
        return best

    def cmd_fieldscan(self, args):
        """Diagnostic: scan the heap for a known field id and, for each match,
        dump the surrounding qwords flagging libg.so pointers (vtable candidates)
        so we can see the real field-object layout (where the id sits relative
        to the vtable)."""
        if not args:
            print("  Usage: fieldscan <knownFieldId>")
            return
        fid = int(args[0], 0)
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        size = 0x1654c00
        pat = " ".join(f"{b:02X}" for b in struct.pack("<I", fid))
        print(f"  Scanning heap for {fid} [{pat}] ...")
        print("  [!] dev scan (Memory.scanSync) - may freeze the game via Promon; plant all no longer needs this.")
        matches = self._rpc("scanheap", pat, timeout=60.0) or []
        print(f"  {len(matches)} matches; object-like ones (libg pointer within -0x40..+0x8):")
        shown = 0
        for maddr in matches:
            m = int(maddr, 0)
            win = self._rpc("readabs", f"0x{m - 0x40:x}", 0x50)
            if not win or len(win) < 0x50:
                continue
            qs = struct.unpack("<10Q", bytes(win)[:0x50])  # offsets -0x40..+0x8
            libptrs = [((i * 8) - 0x40, q) for i, q in enumerate(qs) if base <= q < base + size]
            if not libptrs:
                continue
            shown += 1
            if shown > 12:
                break
            parts = " ".join(f"[id{o:+#x}]=+0x{q - base:x}" for o, q in libptrs)
            print(f"    id@0x{m:x}  ->  {parts}")
        if shown == 0:
            print("  No libg pointer near any match. Field id may not be a raw member with a vtable.")

    def cmd_vtscan(self, args):
        """Scan the heap for objects whose vtable (+0) == base+vtable_off, and
        report the u32 value each holds at +id_off. The field class is the one
        that yields the ~18 distinct field ids (400000..)."""
        if len(args) < 1:
            print("  Usage: vtscan <vtable_off> [id_off=0x10]")
            return
        vt_off = int(args[0], 0)
        id_off = int(args[1], 0) if len(args) > 1 else 0x10
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        vt_abs = base + vt_off
        pat = " ".join(f"{b:02X}" for b in struct.pack("<Q", vt_abs))
        print("  [!] dev scan (Memory.scanSync) - may freeze the game via Promon; plant all no longer needs this.")
        matches = self._rpc("scanheap", pat, timeout=60.0) or []
        vals = []
        for m in matches:
            obj = int(m, 0)
            v = self._rpc("readabs", f"0x{obj + id_off:x}", 4)
            if v and len(v) == 4:
                vals.append(int.from_bytes(bytes(v), "little"))
        uniq = sorted(set(vals))
        print(f"  {len(matches)} objects with vtable +0x{vt_off:x}; {len(uniq)} distinct values at +0x{id_off:x}:")
        print(f"    {uniq[:40]}")

    def cmd_fields(self, args):
        """List the current field ids by scanning heap for the field vtable."""
        ids = self._enumerate_fields()
        print(f"  {len(ids)} field(s) found: {ids}")

    def cmd_livediag(self, args):
        """Show every Field-vtable object in the arena with its slot back-ref so
        we can see which are LIVE (slot+0x8 points back to the Field) vs stale
        (freed but still carrying the vtable/id). Diagnoses over-counting."""
        gm = self._capture_gamemode()
        if not gm:
            print("  no gameMode"); return
        base = int(str(self._rpc("info")["base"]), 0)
        vt = base + self.FIELD_VTABLE_OFF
        first = self._find_a_field(gm, vt)
        if not first:
            print("  no field"); return
        vt_pat = " ".join(f"{b:02X}" for b in struct.pack("<Q", vt))
        cands = []
        for mm in (self._rpc("scanone", f"0x{first:x}", vt_pat, timeout=30.0) or []):
            a = int(mm, 0)
            fid = self._read_field_id(a, vt)
            if fid is not None:
                cands.append((fid, a))
        cands.sort()
        live = 0
        print(f"  {len(cands)} field-vtable object(s) in arena:")
        for fid, a in cands:
            slot = self._read_u64(a + 0x48)
            back = self._read_u64(slot + 0x8) if 0x700000000000 <= slot < 0x800000000000 else 0
            ok = back == a
            live += ok
            print(f"    id={fid} @0x{a:x} slot=0x{slot:x} back=0x{back:x} {'LIVE' if ok else 'stale'}")
        print(f"  => {live} live / {len(cands)} total")

    def cmd_mgrdiag(self, args):
        """Find one Field, then inspect its owner managers (Field+0x38/+0x30) for
        a vector of Field pointers (the canonical field list) so we can read it
        DIRECTLY instead of BFS-ing. Reports vector offset + count. No scan."""
        gm = self._capture_gamemode()
        if not gm:
            print("  no gameMode"); return
        base = int(str(self._rpc("info")["base"]), 0)
        vt = base + self.FIELD_VTABLE_OFF

        def is_heap(p):
            return 0x700000000000 <= p < 0x800000000000

        def is_field(p):
            return is_heap(p) and self._read_u64(p) == vt

        first = self._find_a_field(gm, vt)
        if not first:
            print("  no field"); return
        print(f"  field @0x{first:x} id={self._read_field_id(first, vt)}")
        for po in (0x38, 0x30, 0x48, 0x40):
            mgr = self._read_u64(first + po)
            if not is_heap(mgr):
                continue
            print(f"  --- Field+0x{po:x} owner = 0x{mgr:x} ---")
            data = self._rpc("readabs", f"0x{mgr:x}", 0x120)
            if not data:
                continue
            qs = struct.unpack(f"<{len(data) // 8}Q", bytes(data)[:(len(data) // 8) * 8])
            for j in range(len(qs) - 1):
                b, e = qs[j], qs[j + 1]
                if is_heap(b) and is_heap(e) and b < e and (e - b) % 8 == 0 and (e - b) // 8 <= 300:
                    cnt = (e - b) // 8
                    fc = sum(1 for k in range(min(cnt, 64)) if is_field(self._read_u64(b + k * 8)))
                    if fc >= 2:
                        print(f"    +0x{j * 8:x}: VECTOR begin=0x{b:x} end=0x{e:x} count={cnt} fieldptrs={fc}")
                if is_field(b):
                    print(f"    +0x{j * 8:x}: -> FIELD id={self._read_field_id(b, vt)}")
                lo = b & 0xFFFFFFFF
                if 100000 <= lo <= 5000000 and not is_heap(b):
                    print(f"    +0x{j * 8:x}: id-like {lo}")

    def cmd_fdump(self, args):
        """Dump the raw 0x80 bytes of Field object(s) so we can diff empty /
        growing / ready states and locate the crop-state offset. `fdump [n=2]`.
        Targeted reads only (no scan)."""
        objs = self._enumerate_field_objs()
        if not objs:
            print("  no fields (open the farm?)")
            return
        n = int(args[0], 0) if args else 2
        for addr, fid in objs[:n]:
            rec = self._rpc("readabs", f"0x{addr:x}", 0x80)
            if not rec or len(rec) < 0x80:
                continue
            b = bytes(rec)
            print(f"  field id={fid} @0x{addr:x}:")
            for o in range(0, 0x80, 16):
                q0 = int.from_bytes(b[o:o + 8], "little")
                q1 = int.from_bytes(b[o + 8:o + 16], "little")
                print(f"    +0x{o:02x}: {q0:016x}  {q1:016x}")

    def cmd_fieldsdiag(self, args):
        """Diagnostic (no scan): walk gameMode->field vector, print begin/end/
        count, the contiguous block size, and both block boundaries so we can
        see the real field-storage layout."""
        if not self.plant_mbox:
            self._install_plant_gate()
        if not self._arm_hook():
            print("  [!] Hook not live (open the farm and retry).")
            return
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        vt = base + self.FIELD_VTABLE_OFF
        gm = self._read_u64(int(self.plant_mbox, 0) + 0x08)
        print(f"  gameMode=0x{gm:x}  field_vtable=0x{vt:x}")
        p = gm
        for off in self.FIELD_CHAIN:
            nxt = self._read_u64(p + off)
            print(f"    [0x{p:x} + 0x{off:x}] = 0x{nxt:x}")
            p = nxt
            if not p:
                print("  chain broke"); return
        begin = self._read_u64(p)
        end = self._read_u64(p + 8)
        cap = self._read_u64(p + 0x10)
        print(f"  vector@0x{p:x}: begin=0x{begin:x} end=0x{end:x} cap=0x{cap:x}")
        if begin and end > begin:
            print(f"  vector count = (end-begin)/0x80 = {(end - begin) // 0x80}")
        if not begin or self._read_u64(begin) != vt:
            print(f"  begin is NOT a Field (vtable mismatch)")
            return
        start = begin
        for _ in range(64):
            if self._read_u64(start - 0x80) == vt:
                start -= 0x80
            else:
                break
        ids = []
        addr = start
        for _ in range(64):
            if self._read_u64(addr) != vt:
                break
            v = self._rpc("readabs", f"0x{addr + 0x10:x}", 4)
            ids.append(int.from_bytes(bytes(v), "little"))
            addr += 0x80
        print(f"  contiguous block: {len(ids)} fields  {ids}")
        b0 = self._read_u64(start - 0x80)
        a0 = self._read_u64(addr)
        print(f"  before block [0x{start - 0x80:x}]=0x{b0:x} isField={b0 == vt}")
        print(f"  after  block [0x{addr:x}]=0x{a0:x} isField={a0 == vt}")
        # probe: is a second field block elsewhere in the vector's entries?
        print(f"  vector[+8]=0x{self._read_u64(p + 8):x} [+0x10]=0x{self._read_u64(p + 0x10):x} "
              f"[+0x18]=0x{self._read_u64(p + 0x18):x}")

    def cmd_findfields(self, args):
        """BFS from a root pointer (gameMode) following heap pointers to locate
        a field object (vtable +0x14cfea0) and its container, reporting the
        offset path. Read-only (no scan) -> Promon-safe. Gives us a stable
        gameMode->field-array chain so plant all never has to scan."""
        if not args:
            print("  Usage: findfields <gameModeAddr>")
            return
        root = int(args[0], 0)
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        vt_abs = base + self.FIELD_VTABLE_OFF
        from collections import deque
        visited = set()
        q = deque([(root, None, [])])
        reads = 0
        while q and reads < 15000:
            addr, parent, path = q.popleft()
            if addr in visited or len(path) > 6:
                continue
            visited.add(addr)
            data = self._rpc("readabs", f"0x{addr:x}", 0x200)
            reads += 1
            if not data or len(data) < 8:
                continue
            qs = struct.unpack(f"<{len(data)//8}Q", bytes(data)[:(len(data)//8)*8])
            if qs[0] == vt_abs:
                cnt = None
                if parent is not None:
                    cv = self._rpc("readabs", f"0x{parent + 0xc:x}", 4)
                    if cv:
                        cnt = int.from_bytes(bytes(cv), "little")
                pathstr = " ".join(f"+0x{o:x}" for o in path)
                print(f"  FOUND field obj @ 0x{addr:x}")
                print(f"  container(parent) @ 0x{parent:x}  [+0xc]={cnt}")
                print(f"  path from gameMode: {pathstr}")
                for k in range(5):
                    idv = self._rpc("readabs", f"0x{addr + k*0x80 + 0x10:x}", 4)
                    if idv:
                        print(f"    [array {k}] id={int.from_bytes(bytes(idv),'little')}")
                print(f"  ({reads} reads)")
                return
            for j, p in enumerate(qs):
                if 0x700000000000 <= p < 0x800000000000:
                    q.append((p, addr, path + [j * 8]))
        print(f"  field object not reached within {reads} reads")

    @staticmethod
    def _pfmt(path):
        return " ".join(f"+0x{o:x}" for o in path)

    def cmd_findmgr(self, args):
        """BFS from gameMode for a vector holding MANY Field objects (the STABLE
        field container), not just the first field like findfields. Reports the
        offset chain + field count. Targeted reads only (no scan) -> Promon-safe.
        Takes ~30-60s (walks the object graph)."""
        gm = int(args[0], 0) if args else self._capture_gamemode()
        if not gm:
            print("  no gameMode (open the farm and retry)")
            return
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        vt = base + self.FIELD_VTABLE_OFF

        def is_heap(p):
            return 0x700000000000 <= p < 0x800000000000

        def is_field(p):
            return is_heap(p) and self._read_u64(p) == vt

        from collections import deque
        visited = set()
        q = deque([(gm, [])])
        reads = 0
        best = None
        print(f"  searching from gameMode=0x{gm:x} (field vtable=0x{vt:x}) ...")
        while q and reads < 12000:
            addr, path = q.popleft()
            if addr in visited or len(path) > 6:
                continue
            visited.add(addr)
            data = self._rpc("readabs", f"0x{addr:x}", 0x400)
            reads += 1
            if not data or len(data) < 16:
                continue
            n = len(data) // 8
            qs = struct.unpack(f"<{n}Q", bytes(data)[:n * 8])
            for j in range(n - 1):
                begin, end = qs[j], qs[j + 1]
                if not (is_heap(begin) and is_heap(end) and begin < end):
                    continue
                span = end - begin
                if span % 0x80 == 0 and 5 <= span // 0x80 <= 64:      # inline vector<Field>
                    cnt = span // 0x80
                    if is_field(begin) and is_field(begin + 0x80):
                        if not best or cnt > best[1]:
                            best = (path + [j * 8], cnt, "inline", addr + j * 8, begin)
                        print(f"  inline vec: {self._pfmt(path + [j * 8])}  count={cnt}  @0x{addr + j * 8:x}")
                elif span % 8 == 0 and 5 <= span // 8 <= 64:          # vector<Field*>
                    cnt = span // 8
                    if is_field(self._read_u64(begin)) or is_field(self._read_u64(begin + 8)):
                        fc = sum(1 for k in range(cnt) if is_field(self._read_u64(begin + k * 8)))
                        if fc >= 5:
                            if not best or fc > best[1]:
                                best = (path + [j * 8], fc, "ptr", addr + j * 8, begin)
                            print(f"  ptr vec: {self._pfmt(path + [j * 8])}  fields={fc}/{cnt}  @0x{addr + j * 8:x}")
            for j in range(n):
                p = qs[j]
                if is_heap(p) and p not in visited and len(path) < 6:
                    q.append((p, path + [j * 8]))
        if best:
            print(f"  BEST: path={self._pfmt(best[0])}  count={best[1]}  kind={best[2]}  "
                  f"vec@0x{best[3]:x}  begin=0x{best[4]:x}  ({reads} reads)")
        else:
            print(f"  no field vector found ({reads} reads)")

    def cmd_objdump(self, args):
        """Annotated qword dump of any address (no scanning): flags libg.so
        pointers, heap pointers, and small ints so we can trace pointer chains."""
        if not args:
            print("  Usage: objdump <addr> [qwords]")
            return
        addr = int(args[0], 16) if args[0].lower().startswith("0x") else int(args[0], 0)
        n = int(args[1], 0) if len(args) > 1 else 32
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        size = 0x1654c00
        data = self._rpc("readabs", f"0x{addr:x}", n * 8)
        if not data:
            print("  read failed (unmapped)")
            return
        qs = struct.unpack(f"<{len(data)//8}Q", bytes(data)[:(len(data) // 8) * 8])
        print(f"  @ 0x{addr:x}:")
        for i, q in enumerate(qs):
            off = i * 8
            if base <= q < base + size:
                tag = f"lib+0x{q - base:x}"
            elif 0x700000000000 <= q < 0x800000000000:
                tag = f"heapptr 0x{q:x}"
            elif q < 0x100000000:
                tag = f"int {q}"
            else:
                tag = f"0x{q:x}"
            print(f"    +0x{off:03x} = {tag}")

    def cmd_fielddump(self, args):
        """Dump the first field object's qwords (annotated) so we can find the
        offset that indicates empty vs occupied (a null vs non-null crop ptr)."""
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        size = 0x1654c00
        vt_abs = base + self.FIELD_VTABLE_OFF
        pat = " ".join(f"{b:02X}" for b in struct.pack("<Q", vt_abs))
        print("  [!] dev scan (Memory.scanSync) - may freeze the game via Promon; plant all no longer needs this.")
        matches = self._rpc("scanheap", pat, timeout=60.0) or []
        # pick the field whose id matches args[0] if given, else the first
        target = None
        want = int(args[0], 0) if args else None
        for mm in matches:
            obj = int(mm, 0)
            idv = self._rpc("readabs", f"0x{obj + self.FIELD_ID_OFF:x}", 4)
            if not idv:
                continue
            fid = int.from_bytes(bytes(idv), "little")
            if want is None or fid == want:
                target = (obj, fid)
                break
        if target is None:
            print("  field not found")
            return
        obj, fid = target
        data = self._rpc("readabs", f"0x{obj:x}", 0xA0)
        if not data:
            print("  read fail")
            return
        qs = struct.unpack("<20Q", bytes(data)[:0xA0])
        print(f"  field id {fid} @ 0x{obj:x}:")
        for i, q in enumerate(qs):
            off = i * 8
            if base <= q < base + size:
                tag = f"lib+0x{q - base:x}"
            elif 0x700000000000 <= q < 0x800000000000:
                tag = f"heapptr 0x{q:x}"
            elif q < 0x100000000:
                tag = f"int {q}"
            else:
                tag = f"0x{q:x}"
            print(f"    +0x{off:02x} = {tag}")

    def console_loop(self):
        commands = {
            "read": self.cmd_read, "write": self.cmd_write,
            "nop": self.cmd_nop, "call": self.cmd_call,
            "hook": self.cmd_hook, "scan": self.cmd_scan,
            "dump": self.cmd_dump, "export": self.cmd_export,
            "info": self.cmd_info,
            "vscan": self.cmd_vscan, "vnarrow": self.cmd_vnarrow,
            "vlist": self.cmd_vlist, "vwrite": self.cmd_vwrite,
            "vreset": self.cmd_vreset,
            "cave": self.cmd_cave, "farjump": self.cmd_farjump,
            "branch": self.cmd_branch, "wabs": self.cmd_wabs,
            "rabs": self.cmd_rabs, "dumpso": self.cmd_dumpso,
            "cavetest": self.cmd_cavetest, "gothook": self.cmd_gothook,
            "flushtest": self.cmd_flushtest,
            "cmdhook": self.cmd_cmdhook, "cmdlog": self.cmd_cmdlog,
            "capture": self.cmd_capture,
            "arghook": self.cmd_arghook, "arglog": self.cmd_arglog,
            "plant": self.cmd_plant, "harvest": self.cmd_harvest,
            "farm": self.cmd_farm, "sell": self.cmd_sell,
            "loadnative": self.cmd_loadnative,
            "nping": self.cmd_nping, "ndiag": self.cmd_ndiag,
            "nfields": self.cmd_nfields, "nplant": self.cmd_nplant,
            "nharvest": self.cmd_nharvest, "nsell": self.cmd_nsell,
            "nfarm": self.cmd_nfarm, "nediag": self.cmd_nediag,
            "nfdiag": self.cmd_nfdiag, "nspoof": self.cmd_nspoof,
            "nquago": self.cmd_nquago, "nstate": self.cmd_nstate,
            "fieldscan": self.cmd_fieldscan, "fields": self.cmd_fields,
            "fieldsdiag": self.cmd_fieldsdiag, "findmgr": self.cmd_findmgr,
            "fdump": self.cmd_fdump, "mgrdiag": self.cmd_mgrdiag,
            "livediag": self.cmd_livediag,
            "vtscan": self.cmd_vtscan, "fielddump": self.cmd_fielddump,
            "objdump": self.cmd_objdump, "findfields": self.cmd_findfields,
        }

        print("\n+--------------------------------------+" )
        print("|         NXRTH INTERNAL CONSOLE       |")
        print("+--------------------------------------+" )
        print("|  --- Engine (libg.so offsets) ---     |")
        print("|  read   <type> <off> [len]           |")
        print("|  write  <type> <off> <val>           |")
        print("|  nop    <off> <count>                |")
        print("|  scan   <pattern>                    |")
        print("|  dump   <off> <len>                  |")
        print("|  info                                |")
        print("|  --- Value Scanner (heap) ---        |")
        print("|  vscan  <type> <value>               |")
        print("|  vnarrow <type> <value>              |")
        print("|  vlist                               |")
        print("|  vwrite <value> [index]              |")
        print("|  vreset                              |")
        print("|  --- ARM64 Inline Patching ---       |")
        print("|  cave   [size]                       |")
        print("|  farjump <off> <abs_addr>            |")
        print("|  branch <off> <abs_addr> [link]      |")
        print("|  wabs   <abs_addr> <hexbytes>        |")
        print("|  rabs   <abs_addr> <len>             |")
        print("|  --- Reverse Engineering ---         |")
        print("|  dumpso [out_path]                   |")
        print("|  cavetest [off]                      |")
        print("|  gothook [got_off]                   |")
        print("|  flushtest [off]                     |")
        print("|  cmdhook / cmdlog                     |")
        print("|  arghook <off> / arglog              |")
        print("|  --- NATIVE ENGINE (use these) ---   |")
        print("|  loadnative      (load the module)   |")
        print("|  nfields   /  nfdiag (validate enum) |")
        print("|  nplant [crop] / nharvest            |")
        print("|  nsell <slot> [cnt] [price] [ad]     |")
        print("|  nfarm [wait] [crop]  (auto loop)    |")
        print("|  --- legacy (frida caves) ---        |")
        print("|  plant/harvest/farm/sell/fields      |")
        print("|  capture [secs]                      |")
        print("|  quit                                |")
        print("+--------------------------------------+\n")

        while True:
            try:
                if not self._attached():
                    reason = self.detached_reason or self.script_error or "connection lost"
                    print(f"  [!] Session ended: {reason}")
                    return 1
                line = input("nxrth> ").strip()
                if not line:
                    continue
                if line in ("quit", "exit", "q"):
                    return 0
                parts = shlex.split(line)
                cmd, args = parts[0], parts[1:]
                if cmd in commands:
                    with self._cmd_lock:          # serialize with the socket + farm thread
                        commands[cmd](args)
                else:
                    print(f"  Unknown: {cmd}")
            except KeyboardInterrupt:
                print()
                return 130
            except EOFError:
                return 0 if self._attached() else 1
            except LoaderError as error:
                print(f"  [!] {error}")
                if not self._attached():
                    return 1
            except Exception as e:
                print(f"  [!] {e}")

    def _stop_owned_game(self):
        if not self.spawn_owned or self.pid is None:
            return
        if not self._owned_game_alive():
            return
        result = adb_cmd(
            self.adb, self.device_id, "shell", f"am force-stop {PACKAGE_NAME}"
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise LoaderError(
                f"could not stop owned game process: {detail or 'adb shell failed'}"
            )

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not self._owned_game_alive():
                return
            time.sleep(0.05)

        if self._owned_game_alive():
            su_command(
                self.adb, self.device_id, f"kill -9 {int(self.pid)}", check=False
            )
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if not self._owned_game_alive():
                return
            time.sleep(0.05)
        raise LoaderError(f"owned game PID {self.pid} did not terminate")

    def _control_result(self, line):
        """Parse ONE control-protocol request line and return the reply line
        (no trailing newline): 'OK ...' on success, 'ERR ...' on failure. Calls
        the native primitives directly, serialized under self._cmd_lock so they
        never interleave with the CLI or the farm thread."""
        line = (line or "").strip()
        if not line:
            return "ERR empty request"
        try:
            parts = shlex.split(line)
        except ValueError as e:
            return f"ERR parse error: {e}"
        if not parts:
            return "ERR empty request"
        cmd, args = parts[0].lower(), parts[1:]

        if cmd == "ping":
            return "OK pong"
        if cmd == "farm":               # manages a thread; must not hold the lock across join()
            return self._control_farm(args)
        if cmd == "status":             # cached; no native RPC
            return self._control_status()
        if cmd == "adb":                # probe the ADB device (GUI 'Test ADB' button)
            return self._control_adb()

        if not self._attached():
            reason = self.detached_reason or self.script_error or "session not attached"
            return f"ERR {reason}"

        with self._cmd_lock:
            try:
                if cmd == "fields":
                    ids = self._field_ids(verbose=False)
                    return f"OK {len(ids)} [{','.join(str(i) for i in ids)}]"
                if cmd == "plant":
                    crop = int(args[0], 0) if args else 400001
                    ids = self._field_ids(verbose=False)
                    if not ids:
                        return "ERR no fields (are you in the farm?)"
                    c = self._native_cmd(4, arg0=crop, ids=ids)
                    return f"OK planted {c}" if c is not None else "ERR native gate not live (open the farm)"
                if cmd == "harvest":
                    ids = self._field_ids(verbose=False)
                    if not ids:
                        return "ERR no fields (are you in the farm?)"
                    c = self._native_cmd(5, ids=ids)
                    return f"OK harvested {c}" if c is not None else "ERR native gate not live (open the farm)"
                if cmd == "sell":
                    if not args:
                        return "ERR usage: sell <slot> [count=10] [price=1] [ad=0] [item=400001]"
                    slot = int(args[0], 0)
                    count = int(args[1], 0) if len(args) > 1 else 10
                    price = int(args[2], 0) if len(args) > 2 else 1
                    ad = 1 if len(args) > 3 and args[3].lower() not in ("0", "no", "false", "n") else 0
                    item = int(args[4], 0) if len(args) > 4 else self.WHEAT_ITEM
                    c = self._native_cmd(6, ids=[slot, item, count, price, ad])
                    if c is None:
                        return "ERR native gate not live (open the roadside shop)"
                    return f"OK sold item {item} x{count} @ {price} coin, slot {slot}, ad={ad}"
                return f"ERR unknown command: {cmd}"
            except LoaderError as e:
                return f"ERR {e}"
            except Exception as e:
                return f"ERR {e}"

    def _control_farm(self, args):
        """Non-blocking farm start/stop over the socket. Never holds _cmd_lock
        itself (the worker takes it per cycle), so 'farm stop' can join() safely."""
        if not args:
            return "ERR usage: farm start [wait=130] [crop=400001] | farm stop"
        sub = args[0].lower()
        if sub == "start":
            if self._farm_thread and self._farm_thread.is_alive():
                return "ERR farm already running"
            if not self._attached():
                reason = self.detached_reason or self.script_error or "session not attached"
                return f"ERR {reason}"
            wait = int(args[1], 0) if len(args) > 1 and args[1].isdigit() else 130
            crop = int(args[2], 0) if len(args) > 2 else 400001
            self._farm_stop.clear()
            self._farm_thread = threading.Thread(
                target=self._farm_worker, args=(wait, crop), daemon=True, name="nxrth-farm")
            self._farm_thread.start()
            return "OK farm started"
        if sub == "stop":
            if not (self._farm_thread and self._farm_thread.is_alive()):
                return "ERR farm not running"
            self._farm_stop.set()
            self._farm_thread.join(timeout=10.0)    # NOT holding _cmd_lock here
            if self._farm_thread.is_alive():
                return "OK farm stopping (winding down mid-cycle)"
            return "OK farm stopped"
        return f"ERR unknown farm subcommand: {sub}"

    def _farm_worker(self, wait, crop):
        """Background auto-farm: harvest -> plant -> jittered wait, until the stop
        Event is set. Native ops run under _cmd_lock; the long growth wait is an
        interruptible Event.wait() OUTSIDE the lock."""
        cycle = 0
        while not self._farm_stop.is_set():
            cycle += 1
            try:
                with self._cmd_lock:
                    ids = self._field_ids(verbose=False)
                    if ids:
                        self._native_cmd(5, ids=ids)                 # harvest
                        time.sleep(random.uniform(0.8, 2.2))
                        ids = self._field_ids(verbose=False) or ids
                        self._native_cmd(4, arg0=crop, ids=ids)      # plant
            except LoaderError:
                break
            except Exception:
                pass
            delay = wait * random.uniform(1.02, 1.18)
            if cycle % random.randint(4, 7) == 0:
                delay += random.uniform(20, 90)
            if self._farm_stop.wait(timeout=delay):
                break

    def _control_adb(self):
        """Probe the ADB device connection (GUI 'Test ADB'). Returns the device
        state so the button reflects the real link, not just loader reachability."""
        try:
            r = adb_cmd(self.adb, self.device_id, "get-state", timeout=5)
            st = (r.stdout or "").strip() or "unknown"
            if "device" in st:
                return f"OK adb {self.device_id}: {st}"
            return f"ERR adb {self.device_id}: {st or 'offline'}"
        except Exception as e:
            return f"ERR adb: {e}"

    def _control_status(self):
        running = bool(self._farm_thread and self._farm_thread.is_alive())
        fields = getattr(self, "_last_field_count", 0)
        gate = bool(getattr(self, "nat_cave", None))
        return (f"OK farm={'running' if running else 'stopped'} fields={fields} "
                f"attached={'yes' if self._attached() else 'no'} "
                f"gate={'ready' if gate else 'down'}")

    def start_control_server(self, host="127.0.0.1", port=31350):
        """Localhost line protocol so an external GUI can drive the bot. One
        request line in ('<cmd> [args]\\n'), one reply line out ('OK ...'/'ERR ...').
        Persistent and one-shot clients both work. Bind failure is non-fatal."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(5)
        except OSError as e:
            print(f"[!] Control server NOT started on {host}:{port}: {e}")
            return
        self._control_srv = srv
        print(f"[+] Control server listening on {host}:{port}")
        threading.Thread(target=self._control_accept_loop, args=(srv,),
                         daemon=True, name="nxrth-control").start()

    def _control_accept_loop(self, srv):
        while not self.closing:
            try:
                conn, _addr = srv.accept()
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self._control_client, args=(conn,),
                             daemon=True, name="nxrth-control-conn").start()

    def _control_client(self, conn):
        rf = conn.makefile("rb")
        try:
            for raw in rf:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    reply = self._control_result(line)
                except Exception as e:
                    reply = f"ERR {e}"
                try:
                    conn.sendall((reply + "\n").encode("utf-8"))
                except OSError:
                    break
        except OSError:
            pass
        finally:
            try:
                rf.close()
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def cleanup(self, stop_game):
        self.closing = True
        self._farm_stop.set()
        if self._control_srv is not None:
            try:
                self._control_srv.close()   # unblocks the accept loop
            except OSError:
                pass
            self._control_srv = None
        print("[*] Cleaning up...")
        if self.adb and self.device_id and stop_game:
            try:
                self._stop_owned_game()
            except Exception as error:
                print(f"[!] Could not stop owned game before injector cleanup: {error}")

        if self.probe_script is not None:
            try:
                if not self.probe_script.is_destroyed:
                    self.probe_script.unload()
            except Exception:
                pass
            self.probe_script = None
        if self.guard_script is not None:
            try:
                if not self.guard_script.is_destroyed:
                    self.guard_script.unload()
            except Exception:
                pass
            self.guard_script = None
        if self.script is not None:
            try:
                if not self.script.is_destroyed:
                    self.script.unload()
            except Exception:
                pass
        if self.session is not None:
            try:
                if not self.session.is_detached:
                    self.session.detach()
            except Exception:
                pass
        self.script = None
        self.session = None

        if self.manager is not None:
            try:
                self.manager.remove_remote_device(f"127.0.0.1:{GADGET_PORT}")
            except Exception:
                pass
        self.gadget_device = None

        if self.adb and self.device_id:
            try:
                self._release_injector()
            except Exception:
                pass
            self._remove_forward(GADGET_PORT)
        print("[*] Done.")

    def run(self):
        exit_code = 1
        try:
            self.setup_adb()
            self.prepare_assets()
            self.ensure_server_dead()
            self.start_and_connect()
            self.spawn_inject()
            self.startup_complete = True
            self.start_control_server()          # TCP seam for the GUI (before the CLI)
            exit_code = self.console_loop()
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            exit_code = 130
        except LoaderError as error:
            print(f"[!] {error}")
            exit_code = 1
        except Exception as error:
            print(f"[!] Unexpected loader failure: {error}")
            exit_code = 1
        finally:
            self.cleanup(stop_game=not self.startup_complete)
        return exit_code


def main():
    attempt = 0
    while True:
        attempt += 1
        if attempt > 1:
            print(f"\n[*] ===== Auto-retry attempt {attempt} (Ctrl+C to stop) =====")
        try:
            code = NXRTHConsole().run()
        except KeyboardInterrupt:
            return 130
        # 0 = user quit cleanly, 130 = Ctrl+C -> stop. Anything else (startup
        # failure or a mid-session detach/crash) -> auto-restart.
        if code in (0, 130):
            return code
        print(f"[*] Session ended (code {code}). Auto-restarting in 3s...  (Ctrl+C to stop)")
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            return 130


if __name__ == "__main__":
    raise SystemExit(main())
