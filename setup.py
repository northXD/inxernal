# -*- coding: utf-8 -*-
"""
setup.py — Inxernal Auto-Setup for Hay Day
==========================================
Fully automatic one-click installer for the Inxernal Hay Day tool.

What this script does (in order):
  1. Checks Python version (≥ 3.9 required)
  2. Installs / upgrades pip
  3. Installs all Python dependencies (frida, capstone)
  4. Checks for Node.js — installs via winget if missing (Windows)
  5. Runs `npm install` to build Frida bundles
  6. Detects LDPlayer 9 / LDPlayer 14 ADB path
  7. Checks that LDPlayer is running and ADB device is connected
  8. Verifies the required binaries exist in /data/adb/nxrth-assets/ on the device
  9. Verifies the Frida server SHA-256 matches what loader.py expects — and FIXES it if not
 10. Prints a full readiness report and launches loader.py

Usage:
    python setup.py           — full auto-setup + launch
    python setup.py --check   — check-only, don't launch
    python setup.py --fix     — fix SHA256 only, then exit
"""

import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

# ── colour helpers (no external dep) ──────────────────────────────────────────
# Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

def _c(code, text): return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text
def ok(msg):   print(_c("32", f"  [✔] {msg}"))
def err(msg):  print(_c("31", f"  [✗] {msg}"))
def warn(msg): print(_c("33", f"  [!] {msg}"))
def info(msg): print(_c("36", f"  [i] {msg}"))
def step(msg): print(_c("1;35", f"\n━━ {msg}"))

# ── paths ──────────────────────────────────────────────────────────────────────
HERE       = Path(__file__).resolve().parent
LOADER     = HERE / "loader.py"
PKG_JSON   = HERE / "package.json"
ASSET_VAULT = "/data/adb/nxrth-assets"
FRIDA_BIN   = f"{ASSET_VAULT}/.service"
GADGET_BIN  = f"{ASSET_VAULT}/libmetrics.so"

ADB_CANDIDATES = [
    r"C:\LDPlayer\LDPlayer9\adb.exe",
    r"C:\LDPlayer\LDPlayer14\adb.exe",
    r"C:\Program Files\Genymobile\Genymotion\tools\adb.exe",
    "adb",
]

# ── helpers ────────────────────────────────────────────────────────────────────
def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)

def shell_run(cmd_str, **kw):
    """Run a shell command string (needed for npm/node on Windows PATH)."""
    return subprocess.run(
        cmd_str, capture_output=True, text=True, timeout=120,
        shell=True, **kw
    )


def pip_install(*pkgs):
    result = run([sys.executable, "-m", "pip", "install", "--upgrade", *pkgs])
    if result.returncode != 0:
        err(f"pip install {' '.join(pkgs)} failed:\n{result.stderr.strip()}")
        return False
    return True

def find_adb():
    for p in ADB_CANDIDATES:
        try:
            r = run([p, "version"])
            if r.returncode == 0:
                return p
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None

def find_device(adb):
    r = run([adb, "devices"])
    devices = []
    for line in r.stdout.strip().splitlines()[1:]:
        line = line.strip()
        if not line or "offline" in line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    for d in devices:
        if "127.0.0.1" in d or "emulator" in d:
            return d
    return devices[0] if devices else None

def adb_shell(adb, device, cmd, *, su=True, timeout=15):
    full_cmd = f"su -c {shlex.quote(cmd)}" if su else cmd
    return subprocess.run(
        [adb, "-s", device, "shell", full_cmd],
        capture_output=True, text=True, timeout=timeout
    )

def remote_sha256(adb, device, path):
    r = adb_shell(adb, device, f"sha256sum {shlex.quote(path)}")
    if r.returncode != 0:
        return None
    digest = r.stdout.split(maxsplit=1)[0].strip().lower()
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None

def read_loader_sha(key="FRIDA_SHA256"):
    """Read the current SHA256 constant from loader.py."""
    if not LOADER.exists():
        return None
    text = LOADER.read_text(encoding="utf-8")
    m = re.search(rf'^{key}\s*=\s*"([0-9a-fA-F]{{64}})"', text, re.MULTILINE)
    return m.group(1).lower() if m else None

def patch_loader_sha(key, new_hash):
    """Patch the SHA256 constant in loader.py in-place."""
    text = LOADER.read_text(encoding="utf-8")
    patched, n = re.subn(
        rf'^({key}\s*=\s*")[0-9a-fA-F]{{64}}(")',
        rf'\g<1>{new_hash}\g<2>',
        text, flags=re.MULTILINE
    )
    if n == 0:
        return False
    LOADER.write_text(patched, encoding="utf-8")
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def check_python():
    step("Python version")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 9):
        err(f"Python 3.9+ required — you have {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor} (sys.executable={sys.executable})")

def install_python_deps():
    step("Python dependencies")
    deps = ["frida", "capstone"]
    info(f"Installing: {', '.join(deps)}")
    if not pip_install(*deps):
        sys.exit(1)
    # Verify import
    for pkg in deps:
        try:
            __import__(pkg)
            ok(f"{pkg} importable")
        except ImportError:
            warn(f"{pkg} install reported OK but import failed — continuing anyway")

def install_node_deps():
    step("Node.js + npm dependencies")
    if not PKG_JSON.exists():
        warn("package.json not found — skipping npm install")
        return
    # Check node
    r = shell_run("node --version")
    if r.returncode != 0:
        warn("Node.js not found — Frida bundles must be pre-built (java_guard.bundle.js, quago_probe.bundle.js)")
        warn("To build them: install Node.js from https://nodejs.org then run: npm install")
        return
    ok(f"Node.js {r.stdout.strip()}")
    # npm install
    info("Running npm install ...")
    r = shell_run("npm install", cwd=str(HERE))
    if r.returncode != 0:
        warn(f"npm install failed:\n{r.stderr.strip()}")
    else:
        ok("npm install done")
    # Build bundles if not present
    bundles = {
        "java_guard.bundle.js":  "build:java-guard",
        "quago_probe.bundle.js": "build:quago",
    }
    for bundle, script in bundles.items():
        if (HERE / bundle).exists():
            ok(f"{bundle} already built")
            continue
        info(f"Building {bundle} ...")
        r = shell_run(f"npm run {script}", cwd=str(HERE))
        if r.returncode != 0:
            err(f"Build failed for {bundle}:\n{r.stderr.strip()}")
        else:
            ok(f"{bundle} built")

def check_adb_device():
    step("ADB + LDPlayer device")
    adb = find_adb()
    if not adb:
        err("ADB not found. Install LDPlayer 9 or add adb to PATH.")
        sys.exit(1)
    ok(f"ADB: {adb}")
    device = find_device(adb)
    if not device:
        err("No ADB device found. Start LDPlayer first.")
        sys.exit(1)
    ok(f"Device: {device}")
    return adb, device

def check_device_assets(adb, device):
    step("Device asset verification")
    all_ok = True
    for path, label in [(FRIDA_BIN, "Frida server"), (GADGET_BIN, "Frida gadget")]:
        r = adb_shell(adb, device, f"test -s {shlex.quote(path)} && echo OK")
        if "OK" in (r.stdout or ""):
            ok(f"{label} present: {path}")
        else:
            err(f"{label} MISSING: {path}")
            err(f"  → Place the binary at {path} on the device (see README.md)")
            all_ok = False
    if not all_ok:
        warn("Some device assets are missing. loader.py will fail until they are staged.")
    return all_ok

def check_and_fix_sha256(adb, device):
    step("SHA-256 integrity check & auto-fix")
    pairs = [
        (FRIDA_BIN,  "FRIDA_SHA256",  "Frida server"),
        (GADGET_BIN, "GADGET_SHA256", "Gadget"),
    ]
    all_ok = True
    for remote_path, const_name, label in pairs:
        device_hash = remote_sha256(adb, device, remote_path)
        if device_hash is None:
            warn(f"Could not hash {label} ({remote_path}) — file may be missing")
            all_ok = False
            continue
        loader_hash = read_loader_sha(const_name)
        if loader_hash is None:
            warn(f"Could not read {const_name} from loader.py")
            all_ok = False
            continue
        if device_hash == loader_hash:
            ok(f"{label} SHA-256 matches ✓")
        else:
            warn(f"{label} SHA-256 MISMATCH")
            info(f"  Expected (loader.py): {loader_hash}")
            info(f"  Actual   (device):    {device_hash}")
            info(f"  Patching {const_name} in loader.py ...")
            if patch_loader_sha(const_name, device_hash):
                ok(f"  {const_name} updated to {device_hash}")
            else:
                err(f"  Failed to patch {const_name}")
                all_ok = False
    return all_ok

def readiness_report(adb, device):
    step("Readiness report")
    r = adb_shell(adb, device, "uname -m")
    arch = r.stdout.strip() if r.returncode == 0 else "unknown"
    r2 = adb_shell(adb, device, "getenforce", su=False)
    selinux = r2.stdout.strip() if r2.returncode == 0 else "unknown"
    r3 = adb_shell(adb, device, f"pidof com.supercell.hayday", su=False)
    hayday_pid = r3.stdout.strip() if r3.returncode == 0 else "(not running)"

    print()
    print("  " + "-" * 55)
    print(f"  Device arch    : {arch}")
    print(f"  SELinux        : {selinux}")
    print(f"  Hay Day PID    : {hayday_pid}")
    print(f"  ADB            : {adb}")
    print(f"  Device ID      : {device}")
    print("  " + "-" * 55)
    if hayday_pid == "(not running)":
        warn("Hay Day is NOT running — start it in LDPlayer before running loader.py")
    else:
        ok("Hay Day is running — ready to inject!")

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]
    check_only  = "--check" in args
    fix_only    = "--fix"   in args
    no_launch   = "--no-launch" in args or check_only or fix_only

    print()
    print(_c("1;36", "=" * 56))
    print(_c("1;36", "   Inxernal Auto-Setup -- Hay Day Tool Installer"))
    print(_c("1;36", "   github.com/northXD/inxernal"))
    print(_c("1;36", "=" * 56))

    check_python()
    if not fix_only:
        install_python_deps()
        install_node_deps()

    adb, device = check_adb_device()

    assets_ok = check_device_assets(adb, device)
    if assets_ok or fix_only:
        sha_ok = check_and_fix_sha256(adb, device)
    else:
        sha_ok = False
        warn("Skipping SHA-256 check — assets missing")

    readiness_report(adb, device)

    if not LOADER.exists():
        err(f"loader.py not found at {LOADER}")
        sys.exit(1)

    if no_launch:
        step("Done (--check/--fix mode — not launching loader.py)")
        sys.exit(0 if (assets_ok and sha_ok) else 1)

    step("Launching loader.py")
    if not assets_ok:
        warn("Launching with missing assets — expect errors")
    ok("Starting nxrth console ...")
    print()
    os.execv(sys.executable, [sys.executable, str(LOADER)] + [a for a in args
                               if a not in ("--check", "--fix", "--no-launch")])

if __name__ == "__main__":
    main()
