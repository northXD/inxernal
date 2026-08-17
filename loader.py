import frida
import json
import queue
import re
import time
import shlex
import struct
import subprocess
import threading
from pathlib import Path

PACKAGE_NAME = "com.supercell.hayday"
PROJECT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = PROJECT_DIR / "hook.js"
GADGET_CONFIG_PATH = PROJECT_DIR / "gadget.config.json"
ASSET_VAULT = "/data/adb/nxrth-assets"
FRIDA_BIN = f"{ASSET_VAULT}/.service"
GADGET_VAULT = f"{ASSET_VAULT}/libmetrics.so"
APP_DATA_DIR = f"/data/user/0/{PACKAGE_NAME}"
RUNTIME_GADGET_DIR = f"{APP_DATA_DIR}/files/metrics"
GADGET_BIN = f"{RUNTIME_GADGET_DIR}/libmetrics.so"
CONFIG_STAGE_PATH = "/data/local/tmp/.nxrth-libmetrics.config.so"
INJECTOR_OAT_DIR = "/data/local/tmp/oat"
SERVER_LOG = "/data/local/tmp/.nxrth-server.log"
FRIDA_SHA256 = "b13013c5fb19b01dc81fed1cd9b517b10681240c63d8111167e9df50fb0a0d18"
GADGET_SHA256 = "cfd21e76394bcf86481707754720c3d279016066e71aadeeef26d6ecdff4f981"
FRIDA_PORT = 31337
GADGET_PORT = 31338
CONNECT_TIMEOUT = 12.0
RESUME_TIMEOUT = 5.0
ENGINE_TIMEOUT = 35.0
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

    def on_message(self, message, data):
        message_type = message.get("type")
        if message_type == "send":
            print(f"  {message.get('payload')}")
        elif message_type == "error":
            self.script_error = message.get("stack") or message.get("description") or str(message)
            self.script_failed.set()
            print(f"  [ERROR] {self.script_error}")

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
        CTOR = base + 0x00bf2d6c
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
        emit(0xB9400000 | (2 << 10) | (9 << 5) | 1)               # ldr w1,[x9,#8] start
        emit(0xB9400000 | ((0x5c // 4) << 10) | (31 << 5) | 13)   # ldr w13,[sp,#0x5c] i
        emit(0x0B000000 | (13 << 16) | (1 << 5) | 1)              # add w1,w1,w13
        emit(0xB9400000 | (4 << 10) | (9 << 5) | 2)               # ldr w2,[x9,#0x10] crop
        mvz(3, 0)                                                 # mov w3,#0
        li(11, CTOR)
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

    @staticmethod
    def _le_words(byte_seq):
        return [int.from_bytes(byte_seq[i:i + 4], "little") for i in range(0, len(byte_seq), 4)]

    def _install_plant_gate(self):
        # Hook the main game tick (calls update every frame). At entry x0 =
        # GameMode and we are before the command-drain loop -> a safe, per-frame
        # context. Fires instantly without needing a natural command.
        F = 0x00ae2430
        info = self._rpc("info")
        base = int(str(info["base"]), 0)
        self.engine_base = base
        fabs = base + F
        mbox = self._rpc("alloccave", 64)
        self._rpc("writeabs", mbox, [0] * 32)
        stolen = bytes(self._rpc("readbytes", str(F), "16"))
        if len(stolen) != 16:
            raise LoaderError("could not read stolen bytes")
        cave = self._rpc("alloccave", 384)
        sc = self._build_plant_cave(int(mbox, 0), stolen, base, fabs)
        self._rpc("writeabs", cave, list(sc))
        self._rpc("farjump", str(F), cave)
        self._flush_line_once(base, fabs)
        self.plant_mbox = mbox
        print(f"  Plant gate on main game tick (every frame); mbox {mbox}")

    def cmd_plant(self, args):
        if len(args) < 1:
            print("  Usage: plant <fieldId> [cropId]   |   plant all [count]")
            print("         wheat cropId=400001; fields start at 400000")
            return
        if args[0].lower() == "all":
            start = 400000
            count = int(args[1], 0) if len(args) > 1 else 18
            crop_id = 400001
        else:
            start = int(args[0], 0)
            count = 1
            crop_id = int(args[1], 0) if len(args) > 1 else 400001
        if not self.plant_mbox:
            self._install_plant_gate()
        m = int(self.plant_mbox, 0)
        self._rpc("writeabs", f"0x{m + 8:x}", list(struct.pack("<I", start)))
        self._rpc("writeabs", f"0x{m + 16:x}", list(struct.pack("<I", crop_id)))
        self._rpc("writeabs", f"0x{m + 0x1c:x}", list(struct.pack("<I", count)))
        self._rpc("writeabs", self.plant_mbox, list(struct.pack("<I", 1)))
        print(f"  Requested: crop {crop_id} on {count} field(s) from {start}")
        for i in range(30):
            time.sleep(0.1)
            v = self._rpc("readabs", self.plant_mbox, 4)
            if int.from_bytes(bytes(v), "little") == 0:
                print(f"  >>> DONE after {(i + 1) * 0.1:.2f}s ({count} field(s))")
                return
        print("  Flag still set after 3s (tick hook may not be firing) - tell me.")

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
            "arghook": self.cmd_arghook, "arglog": self.cmd_arglog,
            "plant": self.cmd_plant,
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
        print("|  plant  <fieldId> | plant all [n]    |")
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

    def cleanup(self, stop_game):
        self.closing = True
        print("[*] Cleaning up...")
        if self.adb and self.device_id and stop_game:
            try:
                self._stop_owned_game()
            except Exception as error:
                print(f"[!] Could not stop owned game before injector cleanup: {error}")

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


if __name__ == "__main__":
    raise SystemExit(NXRTHConsole().run())
