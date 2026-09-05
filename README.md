# inxernal discord.gg/nxrth

An **internal tool for Hay Day** (`com.supercell.hayday`) running on **LDPlayer 9** (Android 9,
x86_64). It injects into the game, survives the **Promon SHIELD** anti‑tamper, calls the game's
**own** functions (plant / harvest / sell) directly, blocks the **Quago** behavioural anti‑cheat,
and can spoof the device fingerprint. You drive it from a small `nxrth>` console (or an optional
Windows GUI).

---

## What you need to run it

**On your PC**
- **Python 3.9+** with Frida:
  ```
  pip install frida
  ```
  (Optional, only for the reverse‑engineering scripts in `tests/`: `pip install capstone`.)
- **LDPlayer 9** installed, with its `adb.exe` (the path is auto‑detected).

**In LDPlayer**
- An **Android 9 (x86_64)** instance, **rooted**, with **ADB enabled**.
- **Hay Day installed and launched at least once.**

**Binaries staged on the device** (you supply your own — the loader stages the gadget from
`/data/adb/nxrth-assets/`):

| File | Path on device |
|------|----------------|
| Frida server  | `/data/adb/nxrth-assets/.service` |
| Frida gadget  | `/data/adb/nxrth-assets/libmetrics.so` |

The native engine (`native/build/libnxrth.so`) ships pre‑built in the repo; the loader pushes it
into the game for you. You only need to rebuild it if you change the C++ (see **Building**).

Keep these files next to `loader.py` (they already are): `hook.js`, `gadget.config.json`,
`java_guard.bundle.js`, `quago_probe.bundle.js`, and the `native/` folder.

---

## Running it

1. Start your LDPlayer Android‑9 instance.
2. From the project folder:
   ```
   python loader.py
   ```
3. **Wait for the game to load.** If it crashes, type `quit`, run `python loader.py` again, and
   repeat until the game reaches the farm and the `nxrth>` console appears.
4. Load the native engine, then use the commands:
   ```
   nxrth> loadnative        (load the in‑game engine — do this once per session)
   nxrth> nfields           (list your field ids — you must be on the farm screen)
   nxrth> nharvest          (harvest every field)
   nxrth> nplant            (plant wheat on every field)
   nxrth> nfarm             (auto loop: harvest → plant → wait → repeat, Ctrl+C to stop)
   ```

Type `quit` to exit.

### Main commands (native engine — use these)

| Command | What it does |
|---|---|
| `loadnative` | Load the native engine module into the game (once per session) |
| `nfields` | List the current field ids (they grow each cycle — always read live) |
| `nplant [crop]` | Plant a crop on every field (default wheat `400001`) |
| `nharvest` | Harvest every ready field |
| `nsell <slot> [count] [price] [ad]` | List an item in a roadside‑shop crate (open the shop first) |
| `nfarm [wait] [crop]` | Auto‑farm loop with human‑like jitter (Ctrl+C to stop) |
| `nfdiag` | Diagnostic: confirm the field enumeration finds all fields |

> You must be **on the farm** for field commands, and **at the roadside shop** for `nsell`.

### Anti‑ban

**Quago (behavioural anti‑cheat) — block its uploads.** Set an environment variable *before*
starting the loader, then it's automatic:
```
PowerShell:   $env:NX_QUAGO = "1"; python loader.py
```
| Command | What it does |
|---|---|
| `nquago status` | Show block state + how many uploads were blocked |
| `nquago block on\|off` | Toggle blocking Quago's `api.quago.io` upload |
| `nstate` | Live game state Quago exposes: current screen, player, farm level, roadside‑shop slots |

**Device fingerprint (optional) — present a Galaxy S24 Ultra.** Opt‑in, off until you turn it on:
| Command | What it does |
|---|---|
| `nspoof scan` | Verify the hook can find the `open` import (no changes made) |
| `nspoof on` / `nspoof off` | Redirect `/proc/cpuinfo` to a Snapdragon profile and hide root markers |
| `nspoof` | Show what the hook has intercepted |

Edit the impersonated device in `native/src/device_profile.h` (keep every field consistent).

### Low‑level / reverse‑engineering (advanced)

`info`, `read`/`write`/`dump`/`scan`, the value scanner (`vscan`/`vnarrow`/`vlist`/`vwrite`),
ARM64 caves (`cave`/`farjump`/`branch`/`wabs`/`rabs`), and dumping (`dumpso`) are all available —
type them at the `nxrth>` prompt. The `plant`/`harvest`/`farm`/`sell`/`fields` commands are the
**legacy** Frida‑cave versions; prefer the `n`‑prefixed native ones above.

---

## The GUI (optional)

A Windows ImGui app that drives the loader over a local socket.

1. Build `inxernal.vcxproj` in **Visual Studio** (uses vcpkg for ImGui). This produces the exe.
2. Run **`python loader.py`** first — it starts a control server on `127.0.0.1:31350`.
3. Launch the GUI exe. Its buttons (Plant / Harvest / Farm / Sell / Test ADB) send commands to the
   loader over the socket; a plain console window shows the log.

---

## Building from source

You only need these if you change the corresponding source.

| Part | Command / tool |
|---|---|
| Native engine (`native/src/*`) | `powershell native/build.ps1` (needs **Android NDK r27c**) → `native/build/libnxrth.so` |
| Frida bundles (`java_guard.ts`, `quago_probe.ts`) | `npm install` then `npm run build:java-guard` / `npm run build:quago` (needs **Node.js**) |
| GUI (`ui.cpp`, `engine.cpp`) | **Visual Studio** + vcpkg (build `inxernal.vcxproj`) |

---

## Project layout

```
loader.py                 the tool you run (console + control server)
hook.js                   Frida agent (injection / RPC)
java_guard.bundle.js      Promon SHIELD suppression (compiled from java_guard.ts)
quago_probe.bundle.js     Quago block + game‑state feed (compiled from quago_probe.ts)
gadget*.config.json       Frida gadget configs
native/                   the in‑game ARM64 engine (src/ + build.ps1 + build/libnxrth.so)
engine.cpp / engine.h / ui.cpp / inxernal.*   the optional Windows GUI
tests/                    reverse‑engineering scripts, memory dumps, and experiments (not needed to run)
```

---

## Notes

- Field ids change every cycle (the game grows object ids) — always read them live with `nfields`.
- A fresh native build needs a game restart before `loadnative` (a loaded `.so` can't be re‑staged).
- For educational and reverse‑engineering purposes.
