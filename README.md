# inxernal

An **internal tool for Hay Day** (`com.supercell.hayday`) running on **LDPlayer 9** (Android 9, x86_64).

It injects into the game, survives the Promon SHIELD anti‑tamper protection, and gives you a small
console from which you can call the game's **own** functions — for example, planting wheat on every
field with a single command.

## How it works (short version)

The game engine `libg.so` is **ARM64** code, but LDPlayer is x86 and runs it through **Houdini**
(an ARM→x86 translator). Because of that, normal Frida hooking of the game code doesn't work.
Instead, inxernal writes its own small pieces of **ARM64 code ("caves")** into the game process and
redirects the game into them. That lets it call real game functions (like the "plant crop" command)
exactly the way the game does — so the server accepts the actions.

## Requirements

- **LDPlayer 9** with an **Android 9 (x86_64)** instance, **root + ADB enabled**
- Hay Day installed and launched at least once
- **Python 3** with `frida` and `capstone`:
  ```
  pip install frida capstone
  ```
- A Frida **server** and Frida **gadget** placed on the device (see Setup)

## Setup

Put your own binaries on the device (their SHA‑256 hashes are checked in `loader.py`, change them to match yours):

| File | Path on device |
|------|----------------|
| Frida server | `/data/adb/nxrth-assets/.service` |
| Frida gadget | `/data/adb/nxrth-assets/libmetrics.so` |

Keep `hook.js` and `gadget.config.json` in the same folder as `loader.py`.

## How to use

1. Start your LDPlayer Android 9 instance.
2. In the project folder, run:
   ```
   python loader.py
   ```
3. **WAIT FOR THE GAME TO LOAD.** If the game crashes, type `quit`, run `python loader.py` again,
   and repeat until the game gets past the loading screen and the `nxrth>` console appears.
4. Use the commands below.

## Commands

Once the `nxrth>` console is up:

### Farming
| Command | What it does |
|---------|--------------|
| `plant all` | Plant wheat on all fields at once (instant) |
| `plant all 9` | Plant wheat on the first 9 fields |
| `plant <fieldId>` | Plant on one field (field IDs are `400000`, `400001`, …) |

### Memory
| Command | What it does |
|---------|--------------|
| `info` | Show libg.so base, size and arch |
| `read <type> <off> [len]` | Read a value at a libg.so offset |
| `write <type> <off> <val>` | Write a value |
| `dump <off> <len>` | Hex dump |
| `scan "<pattern>"` | Byte‑pattern search |

Types: `int` `float` `double` `long` `ptr` `str` `bytes`.

### Value scanner (like Game Guardian, for heap values)
| Command | What it does |
|---------|--------------|
| `vscan <type> <value>` | First scan |
| `vnarrow <type> <value>` | Narrow results after the value changes |
| `vlist` / `vwrite <value>` / `vreset` | List / write / clear results |

### Reverse engineering & low level
| Command | What it does |
|---------|--------------|
| `dumpso <file>` | Dump the unpacked libg.so from memory to a file |
| `arghook <off>` / `arglog` | Log a function's arguments |
| `cave` / `farjump` / `wabs` / `rabs` | ARM64 code caves & patching |

Type `quit` to exit.

## Extra tools

- `rev.py` — call‑graph / cross‑reference navigator over a `libg.so` memory dump
- `analyze_libg.py` — string + cross‑reference scanner over the dump

## Note

For educational and reverse‑engineering purposes.
