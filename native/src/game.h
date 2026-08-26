// =============================================================================
//  INXERNAL native engine - typed access to libg (the aarch64 game image)
// -----------------------------------------------------------------------------
//  Function pointers and reads computed from the resolved libg base + offsets.h.
//  Being aarch64 in-process, calling these is an ordinary C++ call and reading
//  game structures is an ordinary dereference - no cave, no RPC, no scraping.
// =============================================================================
#pragma once
#include <cstdint>
#include "offsets.h"

namespace nx {

extern uintptr_t g_libg_base;   // set by nx_init (main.cpp)

inline uintptr_t A(uintptr_t off) { return g_libg_base + off; }

inline bool is_heap(uint64_t p) { return p >= 0x700000000000ull && p < 0x800000000000ull; }
inline bool is_lib (uint64_t p) { return p >= g_libg_base && p < g_libg_base + 0x1660000ull; }

template <class T> inline T rd(uint64_t addr) { return *reinterpret_cast<T*>(addr); }
inline uint64_t rd64(uint64_t a) { return rd<uint64_t>(a); }
inline uint32_t rd32(uint64_t a) { return rd<uint32_t>(a); }
inline uint64_t deref(uint64_t base, uintptr_t off) { return rd64(base + off); }

// ---- crash-safe reads -------------------------------------------------------
// Exploration follows pointers that may be stale/unmapped; a bad load SIGSEGVs
// and takes the app down (that is what froze the game). We snapshot the process
// readable ranges from /proc/self/maps and gate every exploratory read on them,
// so a bad pointer just reads as 0 instead of faulting.
struct Range { uint64_t start, end; uint8_t w, anon; };  // writable / anonymous
// Double-buffered readable-range snapshot. A background thread refreshes the
// inactive buffer from /proc/self/maps and flips g_active_ranges, so on_tick
// (game thread) NEVER does file I/O - that is what froze the game.
extern Range g_ranges_buf[2][16384];   // must exceed the process's mapping count
extern int   g_nranges_buf[2];         // (the guest heap sits at high addresses)
extern volatile int g_active_ranges;
void start_range_refresher();   // spawn the off-thread updater (call once at init)
bool is_readable(uint64_t p);   // p..p+8 inside a readable mapping

inline uint64_t srd64(uint64_t a) { return is_readable(a) ? *reinterpret_cast<uint64_t*>(a) : 0; }
inline uint32_t srd32(uint64_t a) { return is_readable(a) ? *reinterpret_cast<uint32_t*>(a) : 0; }
inline uint64_t sderef(uint64_t base, uintptr_t off) { return srd64(base + off); }

// ---- game function pointers -------------------------------------------------
using try_exec_t     = int   (*)(void* gameMode, void* cmd, int flag);
using op_new_t       = void* (*)(uint64_t size);
using plant_ctor_t   = void  (*)(void* cmd, uint32_t fieldId, uint32_t cropId, uint32_t z);
using harvest_ctor_t = void  (*)(void* cmd, uint32_t fieldId);
using sell_ctor_t    = void  (*)(void* cmd, uint32_t slot, uint32_t item,
                                 uint32_t count, uint32_t price, uint32_t ad, uint32_t f6);

inline try_exec_t     fn_try_exec()     { return reinterpret_cast<try_exec_t>(A(off::TRY_EXECUTE_CMD)); }
inline op_new_t       fn_op_new()       { return reinterpret_cast<op_new_t>(A(off::OPERATOR_NEW)); }
inline plant_ctor_t   fn_plant_ctor()   { return reinterpret_cast<plant_ctor_t>(A(off::PLANT_CTOR)); }
inline harvest_ctor_t fn_harvest_ctor() { return reinterpret_cast<harvest_ctor_t>(A(off::HARVEST_CTOR)); }
inline sell_ctor_t    fn_sell_ctor()    { return reinterpret_cast<sell_ctor_t>(A(off::SELL_CTOR)); }

inline uint64_t field_vtable() { return A(off::FIELD_VTABLE); }

// ---- command execution (recipe: new -> ctor -> tryToExecuteCommand) ---------
inline void plant_field(void* gm, uint32_t fieldId, uint32_t cropId) {
    void* cmd = fn_op_new()(off::CMD_SIZE);
    fn_plant_ctor()(cmd, fieldId, cropId, 0);
    fn_try_exec()(gm, cmd, 0);
}
inline void harvest_field(void* gm, uint32_t fieldId) {
    void* cmd = fn_op_new()(off::CMD_SIZE);
    fn_harvest_ctor()(cmd, fieldId);
    fn_try_exec()(gm, cmd, 0);
}
// Put an item up for sale in a roadside-shop crate. The trailing flag is always
// 1 in captured traffic; `ad` toggles the (free, cooldowned) advertisement.
inline void sell_item(void* gm, uint32_t slot, uint32_t item,
                      uint32_t count, uint32_t price, uint32_t ad) {
    void* cmd = fn_op_new()(off::SELL_SIZE);
    fn_sell_ctor()(cmd, slot, item, count, price, ad ? 1 : 0, 1);
    fn_try_exec()(gm, cmd, 0);
}

// ---- Field object helpers ---------------------------------------------------
inline bool is_field(uint64_t obj) {
    return is_heap(obj) && is_readable(obj) && srd64(obj) == field_vtable();
}
inline uint32_t field_id(uint64_t obj) { return srd32(obj + off::FIELD_ID); }

} // namespace nx
