// =============================================================================
//  INXERNAL native engine - reversed offset table (base-relative into libg.so)
// -----------------------------------------------------------------------------
//  Every value is an offset from the runtime base of libg.so (the aarch64 game
//  image). The module resolves the base in-process (dl_iterate_phdr) and adds
//  these. Sourced from the RE captured in loader.py + memory/inxernal-bot-state.
//  Verified against Hay Day 1.72.2. If the game updates, only this file changes.
// =============================================================================
#pragma once
#include <cstdint>

namespace nx::off {

// --- core engine entry points -------------------------------------------------
constexpr uintptr_t TICK               = 0x00ae2430; // per-frame; x0 = GameMode
constexpr uintptr_t TRY_EXECUTE_CMD    = 0x00ae3bc4; // tryToExecuteCommand(gm, cmd, flag)
constexpr uintptr_t OPERATOR_NEW       = 0x0141c480; // operator new(size)

// --- GameMode member offsets --------------------------------------------------
constexpr uintptr_t GM_LEVEL           = 0x10;       // [gm+0x10]  = level
constexpr uintptr_t GM_CMDQ_BEGIN      = 0x1c0;      // command-queue vector begin
constexpr uintptr_t GM_CMDQ_END        = 0x1c8;
constexpr uintptr_t GM_CMDQ_CAP        = 0x1d0;
constexpr uintptr_t GM_OBJ_MANAGER     = 0x1f8;      // a game-object manager

// --- commands (recipe: new(size) -> ctor(...) -> tryToExecuteCommand) ---------
constexpr uintptr_t PLANT_CTOR         = 0x00bf2d6c; // (cmd, fieldId, cropId, 0)
constexpr uintptr_t PLANT_VTABLE       = 0x014a9358;
constexpr uintptr_t HARVEST_CTOR       = 0x00be8b40; // (cmd, fieldId)  [ignores crop]
constexpr uintptr_t HARVEST_VTABLE     = 0x014a82c8;
constexpr uintptr_t SELL_CTOR          = 0x00bf4394; // (cmd, slot, item, count, price, ad, flag6)
constexpr uintptr_t SELL_VTABLE        = 0x014a9598;
constexpr uintptr_t SELL_SIZE          = 0x38;       // operator new size for SellCommand
constexpr uintptr_t CMD_SIZE           = 0x30;       // plant/harvest command size

// --- crop ids -----------------------------------------------------------------
constexpr uint32_t  CROP_WHEAT         = 400001;

// --- Field object -------------------------------------------------------------
constexpr uintptr_t FIELD_VTABLE       = 0x014cfea0;
constexpr uintptr_t FIELD_ID           = 0x10;       // global id (u32)
constexpr uintptr_t FIELD_STRIDE       = 0x80;
constexpr uintptr_t FIELD_SLOT         = 0x48;       // live-slot back-ref ([slot+8]==field)
constexpr uintptr_t FIELD_OWNER_A      = 0x38;       // shared owner/manager
constexpr uintptr_t FIELD_OWNER_B      = 0x30;

// --- Field / GameObject manager -----------------------------------------------
constexpr uintptr_t MGR_VTABLE         = 0x014ba5b0;
constexpr uintptr_t MGR_CTOR           = 0x00c8de28;
constexpr uintptr_t MGR_OBJVEC_BEGIN   = 0xc0;       // object vector begin/end/cap
constexpr uintptr_t MGR_OBJVEC_END     = 0xc8;
constexpr uintptr_t MGR_OBJVEC_CAP     = 0xd0;
constexpr uintptr_t LEVEL_FIELD_MGR    = 0x138;      // [gm+0x10]+0x138 = level field manager
constexpr uintptr_t GAMEOBJ_FACTORY    = 0x00da248c;
constexpr uintptr_t FIELD_CTOR         = 0x00d95e24;

// --- global-id object model (reversed from getGameObjectByGlobalId @0xc6d58c) -
// manager = *(gm-or-level + 0x220); it holds a per-TYPE array of sub-managers at
// mgr+0x15c8 (type count at mgr+0x15d4). An object's TYPE = globalId / 100000, so
// fields (ids 400000+) are type 4. The field sub-manager = (*(mgr+0x15c8))[4]
// owns every field. resolve(mgr,id,expType,flag) = subMgr->vtable[0x50](subMgr,id).
constexpr uintptr_t ROOT_MANAGER       = 0x220;      // *(gm/level+0x220) = LogicGameObjectManager
constexpr uintptr_t MGR_TYPE_ARRAY     = 0x15c8;     // -> array[type] of sub-managers
constexpr uintptr_t MGR_TYPE_COUNT     = 0x15d4;     // number of object types
constexpr uint32_t  ID_TYPE_DIV        = 100000;     // type = globalId / 100000
constexpr uint32_t  FIELD_TYPE         = 4;          // field ids are 400000+
constexpr uintptr_t RESOLVE_BY_GID     = 0x00c6d58c; // getGameObjectByGlobalId(mgr,id,expType,flag)

// --- anti-ban / device telemetry (future workstream) --------------------------
constexpr uintptr_t IS_EMULATOR_BRIDGE = 0x0117afbc;
constexpr uintptr_t DEVINFO_COLLECT_A  = 0x00b455e0;
constexpr uintptr_t DEVINFO_COLLECT_B  = 0x00f576c4;
constexpr uintptr_t GETPROP_A          = 0x01119868;
constexpr uintptr_t GETPROP_B          = 0x0111a4e4;
constexpr uintptr_t SAFETYNET_PATH     = 0x0111aa18;

} // namespace nx::off
