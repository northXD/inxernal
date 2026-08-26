// =============================================================================
//  INXERNAL native engine - command mailbox (shared with the Python loader)
// -----------------------------------------------------------------------------
//  The loader can't call our aarch64 functions across the Houdini boundary, so
//  it drives the engine by writing this struct (found at module_base + the RVA
//  of `nx_mailbox`) via Frida read/write, and the engine acts on it from the
//  game thread inside on_tick. Fixed layout: keep in sync with loader.py.
// =============================================================================
#pragma once
#include <cstdint>

namespace nx {

constexpr uint32_t MB_MAGIC = 0x4e585254;  // 'NXRT'

// commands (loader -> engine)
enum : uint32_t {
    CMD_IDLE     = 0,
    CMD_PING     = 1,   // liveness: engine writes count = 0xABCD
    CMD_DIAG     = 2,   // dump gameMode/manager layout to logcat
    CMD_FIELDS   = 3,   // enumerate fields -> ids[0..count)
    CMD_PLANT    = 4,   // plant crop arg0 on every field
    CMD_HARVEST  = 5,   // harvest every field
    CMD_SELL     = 6,   // roadside-shop sale; params in ids[0..4]
    CMD_FIELDS_DIAG = 7,// probe each field-container candidate; counts -> scan_* + logcat
    CMD_SPOOF_SCAN = 8, // anti-ban: report libg's hookable libc import slots (no patch)
    CMD_SPOOF_ON   = 9, // anti-ban: install device-spoof hooks (GOT data-hooks)
    CMD_SPOOF_OFF  = 10,// anti-ban: restore original import slots
};

// status (engine -> loader)
enum : uint32_t {
    ST_IDLE = 0,
    ST_DONE = 1,
    ST_ERR  = 2,
};

struct Mailbox {
    uint32_t magic;        // +0x00  MB_MAGIC once initialized
    uint32_t cmd;          // +0x04  loader writes; engine clears to 0 when done
    uint32_t arg0;         // +0x08
    uint32_t arg1;         // +0x0c
    uint32_t status;       // +0x10
    uint32_t count;        // +0x14  result count
    uint32_t heartbeat;    // +0x18  bumped every on_tick (re-arm polls this)
    uint32_t err;          // +0x1c  error code / detail
    uint64_t gameMode;     // +0x20  last GameMode seen by on_tick
    uint32_t ids[128];     // +0x28  result field ids
    // ---- background field scan (maintained off the game thread) -------------
    uint32_t scan_count;   // +0x228 live field count from the heap scan
    uint32_t scan_gen;     // +0x22c increments each scan pass (freshness)
    uint32_t scan_ms;      // +0x230 last scan duration (ms), for tuning
    uint32_t scan_seen;    // +0x234 total field-vtable objects seen (incl stale)
    uint32_t scan_ids[192];// +0x238 live field ids
    uint32_t tick_stolen[4];// +0x538 clean 16-byte tick prologue captured at load
    uint32_t scan_req;     // +0x548 loader bumps this to request ONE scan pass
};

} // namespace nx
