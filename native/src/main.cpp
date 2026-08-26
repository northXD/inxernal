// =============================================================================
//  INXERNAL native engine - module entry + game-thread callback
// -----------------------------------------------------------------------------
//  aarch64 module loaded into the Hay Day process (Houdini). It resolves libg,
//  exposes a mailbox the loader pokes, and runs on_tick every frame (reached by
//  a tiny cave the loader installs on the game tick). All game work happens in
//  on_tick on the game thread: enumerate fields, build+execute commands - all as
//  direct in-process calls/reads. No RPC, no memory scraping.
// =============================================================================
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <cerrno>
#include <cstdarg>
#include <ctime>
#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include "offsets.h"
#include "mailbox.h"
#include "game.h"
#include "device_profile.h"

#define NX_TAG "NXRTH"
#define NXLOG(...) __android_log_print(ANDROID_LOG_INFO, NX_TAG, __VA_ARGS__)
#define NXERR(...) __android_log_print(ANDROID_LOG_ERROR, NX_TAG, __VA_ARGS__)

namespace nx {

uintptr_t g_libg_base = 0;

// The command mailbox: loader writes at module_base + RVA(nx_mailbox), engine
// acts on it from on_tick. Exported (C name) so the loader can find its RVA.
extern "C" __attribute__((visibility("default"))) Mailbox nx_mailbox = {};

// ---- fault guard for the scanner --------------------------------------------
// The scan follows the heap while the game frees mappings; a read can fault. We
// install a SIGSEGV/SIGBUS handler that, ONLY on the scan thread while scanning
// (thread-local guard), skips the faulting range instead of crashing. Faults on
// any other thread (the game) are chained to the previous handler untouched.
static __thread sigjmp_buf g_scan_jmp;
static __thread volatile int g_scan_guard = 0;
static struct sigaction g_prev_segv, g_prev_bus;

static void nx_fault(int sig, siginfo_t* si, void* uc) {
    if (g_scan_guard) siglongjmp(g_scan_jmp, 1);
    struct sigaction* prev = (sig == SIGBUS) ? &g_prev_bus : &g_prev_segv;
    if (prev->sa_flags & SA_SIGINFO) {
        if (prev->sa_sigaction) prev->sa_sigaction(sig, si, uc);
        return;
    }
    if (prev->sa_handler == SIG_IGN) return;
    if (prev->sa_handler && prev->sa_handler != SIG_DFL) { prev->sa_handler(sig); return; }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_scan_guard() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = nx_fault;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_prev_segv);
    sigaction(SIGBUS, &sa, &g_prev_bus);
}

// ---- crash-safe read support (off-thread /proc/self/maps snapshot) -----------
Range g_ranges_buf[2][16384];
int   g_nranges_buf[2] = {0, 0};
volatile int g_active_ranges = 0;

void scan_fields();   // forward decl (defined after is_readable)

static void refresh_into(int b) {
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) { g_nranges_buf[b] = 0; return; }
    char line[512];
    int n = 0;
    while (std::fgets(line, sizeof(line), f) && n < 16384) {
        unsigned long long s = 0, e = 0;
        char perms[8] = {0};
        if (std::sscanf(line, "%llx-%llx %7s", &s, &e, perms) == 3 && perms[0] == 'r') {
            g_ranges_buf[b][n].start = s;
            g_ranges_buf[b][n].end = e;
            g_ranges_buf[b][n].w = (perms[1] == 'w') ? 1 : 0;
            // Anonymous == no '/' in the line: addresses, perms, offset, dev and
            // inode never contain one, so a '/' means a file-backed mapping
            // (libs, assets, /dev/*). The malloc heap - where Field objects live
            // - is anonymous ("[anon:libc_malloc]" or blank), so scanning only
            // anonymous ranges is both safer and much faster.
            g_ranges_buf[b][n].anon = (std::strchr(line, '/') == nullptr) ? 1 : 0;
            n++;
        }
    }
    std::fclose(f);
    g_nranges_buf[b] = n;
}

// ON DEMAND, never continuous: refresh the readable-range snapshot OFF the game
// thread so is_readable() is current for the in-process container read (the game
// frees/maps heap constantly). We do NOT scan memory here - broad scanning trips
// Promon; reading /proc/self/maps off-thread does not. The loader bumps
// mailbox.scan_req before enumerating; this thread notices, refreshes once, bumps
// scan_gen as the 'done' handshake, and idles again.
static void* range_thread(void*) {
    uint32_t served = 0;
    for (;;) {
        if (nx_mailbox.scan_req != served) {
            served = nx_mailbox.scan_req;
            int b = 1 - g_active_ranges;
            refresh_into(b);
            g_active_ranges = b;         // atomic-ish flip (aligned int)
            nx_mailbox.scan_gen++;       // refresh-done handshake for the loader
        }
        struct timespec ts { 0, 150 * 1000 * 1000 };
        nanosleep(&ts, nullptr);
    }
    return nullptr;
}

void start_range_refresher() {
    refresh_into(0);                     // seed synchronously (module thread)
    g_active_ranges = 0;
    NXLOG("ranges: %d readable regions", g_nranges_buf[0]);
    pthread_t t;
    pthread_create(&t, nullptr, range_thread, nullptr);
}

bool is_readable(uint64_t p) {
    int a = g_active_ranges;
    const Range* r = g_ranges_buf[a];
    int lo = 0, hi = g_nranges_buf[a] - 1;
    while (lo <= hi) {
        int m = (lo + hi) >> 1;
        if (p < r[m].start) hi = m - 1;
        else if (p >= r[m].end) lo = m + 1;
        else return p + 8 <= r[m].end;
    }
    return false;
}

// Background heap scan: find live Field objects by vtable across writable guest-
// heap ranges, drop stale ones via the slot back-ref (Field+0x48 -> slot,
// slot+8 == Field), and publish the live ids to the mailbox. Runs off the game
// thread (no renderer stall) with plain loads (indistinguishable from the game's
// own reads, so it does not trip Promon like an external scanner).
static uint32_t g_live[192], g_all[192];
static uint32_t g_lc, g_ac, g_seen;
static uint64_t g_arena_s[8], g_arena_e[8];   // ranges known to hold Fields
static int      g_narena = 0;

static uint64_t now_ms() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}

// Scan one range for Field objects; returns how many were found. Fault-guarded,
// so a page freed mid-scan just aborts this range instead of crashing.
static uint32_t scan_one_range(uint64_t s, uint64_t e, uint64_t fvt) {
    uint32_t found = 0;
    g_scan_guard = 1;
    if (sigsetjmp(g_scan_jmp, 1) == 0) {
        for (uint64_t p = s; p + 0x50 <= e && g_ac < 192; p += 8) {
            if (*reinterpret_cast<uint64_t*>(p) != fvt) continue;
            g_seen++; found++;
            uint32_t id = *reinterpret_cast<uint32_t*>(p + off::FIELD_ID);
            if (id < 100000 || id > 5000000) continue;
            bool dupa = false;
            for (uint32_t k = 0; k < g_ac; k++) if (g_all[k] == id) { dupa = true; break; }
            if (!dupa) g_all[g_ac++] = id;
            // liveness: the field's slot points back to it (drops freed fields)
            uint64_t slot = *reinterpret_cast<uint64_t*>(p + off::FIELD_SLOT);
            uint64_t back = is_readable(slot + 8) ? *reinterpret_cast<uint64_t*>(slot + 8) : 0;
            if (back == p) {
                bool dupl = false;
                for (uint32_t k = 0; k < g_lc; k++) if (g_live[k] == id) { dupl = true; break; }
                if (!dupl && g_lc < 192) g_live[g_lc++] = id;
            }
        }
    }
    g_scan_guard = 0;
    return found;
}

void scan_fields() {
    if (!g_libg_base) return;
    uint64_t t0 = now_ms();
    uint64_t fvt = g_libg_base + off::FIELD_VTABLE;
    int a = g_active_ranges;
    const Range* rs = g_ranges_buf[a];
    int nr = g_nranges_buf[a];
    g_lc = g_ac = g_seen = 0;

    // Fast path: re-scan only the arenas we already know hold Fields. After a
    // harvest the objects are freed and reallocated, but from the same size-class
    // arena, so this keeps working across cycles.
    for (int i = 0; i < g_narena; i++)
        scan_one_range(g_arena_s[i], g_arena_e[i], fvt);

    // Full sweep when the fast path comes up short (first run, or the arena set
    // changed). Anonymous writable guest-heap ranges only; time-bounded so it
    // can never spin. Records every range that contained Fields.
    if (g_ac < 2) {
        g_narena = 0;
        for (int r = 0; r < nr && g_ac < 192; r++) {
            if (!rs[r].w || !rs[r].anon || rs[r].start < 0x700000000000ull) continue;
            uint64_t s = rs[r].start, e = rs[r].end;
            if (e - s < 0x1000 || e - s > 192ull * 1024 * 1024) continue;
            if (scan_one_range(s, e, fvt) > 0 && g_narena < 8) {
                g_arena_s[g_narena] = s;
                g_arena_e[g_narena] = e;
                g_narena++;
            }
            if (now_ms() - t0 > 4000) break;      // hard time bound
        }
        if (g_narena)
            NXLOG("scan: %d arena(s), %u field(s), %u seen, %lums",
                  g_narena, g_ac, g_seen, (unsigned long)(now_ms() - t0));
    }

    // Prefer the slot-filtered live set; if the filter rejected everything (its
    // assumption doesn't hold in this state) fall back to all seen fields -
    // planting/harvesting a stale id is a harmless no-op.
    uint32_t* pub = (g_lc > 0) ? g_live : g_all;
    uint32_t pubn = (g_lc > 0) ? g_lc : g_ac;
    for (uint32_t k = 0; k < pubn; k++) nx_mailbox.scan_ids[k] = pub[k];  // ids before count
    nx_mailbox.scan_seen = g_seen;
    nx_mailbox.scan_ms = static_cast<uint32_t>(now_ms() - t0);
    nx_mailbox.scan_count = pubn;
    nx_mailbox.scan_gen++;
}

namespace {

struct FindData { const char* needle; uintptr_t base; const char* full; };

int phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* fd = static_cast<FindData*>(data);
    if (info->dlpi_name && std::strstr(info->dlpi_name, fd->needle)) {
        fd->base = static_cast<uintptr_t>(info->dlpi_addr);
        fd->full = info->dlpi_name;
        return 1;
    }
    return 0;
}

uintptr_t resolve_lib_base_maps(const char* needle) {
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, needle)) {
            base = static_cast<uintptr_t>(std::strtoull(line, nullptr, 16));
            break;
        }
    }
    std::fclose(f);
    return base;
}

uintptr_t resolve_lib_base(const char* needle) {
    uintptr_t base = resolve_lib_base_maps(needle);
    if (base) return base;
    FindData fd{needle, 0, nullptr};
    dl_iterate_phdr(phdr_cb, &fd);
    return fd.base;
}

// A vector of Field objects inside `obj`: either a {begin,end} of Field* (the
// game-object manager's mixed list) or an inline Field array (0x80 stride).
uint32_t try_field_vector(uint64_t obj, uint32_t* out, uint32_t cap) {
    for (uintptr_t o = 0; o + 16 <= 0x1a0; o += 8) {
        uint64_t b = srd64(obj + o), e = srd64(obj + o + 8);
        if (!(is_heap(b) && is_heap(e) && b < e)) continue;
        uint64_t span = e - b;
        if ((span % 8) == 0) {                     // vector<Field*> (maybe mixed)
            uint64_t cnt = span / 8;
            if (cnt >= 2 && cnt <= 8000) {
                uint32_t fc = 0, chk = 0;
                for (uint64_t k = 0; k < cnt && chk < 96; k++, chk++)
                    if (is_field(srd64(b + k * 8))) fc++;
                if (fc >= 3) {
                    uint32_t n = 0;
                    for (uint64_t k = 0; k < cnt && n < cap; k++) {
                        uint64_t f = srd64(b + k * 8);
                        if (is_field(f)) out[n++] = field_id(f);
                    }
                    if (n >= 3) return n;
                }
            }
        }
        if ((span % 0x80) == 0 && is_field(b) && is_field(b + 0x80)) {  // inline
            uint64_t cnt = span / 0x80;
            if (cnt >= 2 && cnt <= 200) {
                uint32_t n = 0;
                for (uint64_t k = 0; k < cnt && n < cap; k++) {
                    uint64_t f = b + k * 0x80;
                    if (is_field(f)) out[n++] = field_id(f);
                }
                if (n >= 2) return n;
            }
        }
    }
    return 0;
}

// Bounded BFS from gameMode+level. Tight limits so it can NEVER stall the game
// thread: hash is 2x the object cap (never fills), probe window is short, and
// only the game-object-MANAGER class is inspected for a field vector (one vtable
// read rules every other object out). Returns the largest Field vector found.
uint64_t g_seen[32768];
uint64_t g_queue[6000];
uint32_t g_tmp[256];

uint32_t enumerate_fields(void* gmv, uint32_t* out, uint32_t cap) {
    uint64_t gm = reinterpret_cast<uint64_t>(gmv);
    uint64_t level = sderef(gm, off::GM_LEVEL);
    for (int i = 0; i < 32768; i++) g_seen[i] = 0;
    uint32_t qn = 0;
    auto add = [&](uint64_t p) {
        if (!is_heap(p) || !is_readable(p) || qn >= 6000) return;
        uint64_t h = (p >> 4) & 32767;
        for (int i = 0; i < 16; i++) {                 // short probe, never O(n)
            uint64_t idx = (h + i) & 32767;
            if (g_seen[idx] == 0) { g_seen[idx] = p; g_queue[qn++] = p; return; }
            if (g_seen[idx] == p) return;
        }
    };
    add(gm);
    add(level);
    uint32_t best = 0;
    for (uint32_t i = 0; i < qn; i++) {
        uint64_t obj = g_queue[i];
        uint32_t n = try_field_vector(obj, g_tmp, 256);   // inspect every object
        if (n > best) {
            best = n;
            for (uint32_t k = 0; k < n && k < cap; k++) out[k] = g_tmp[k];
        }
        for (uintptr_t o = 0; o < 0x100; o += 8) add(srd64(obj + o));
    }
    return best > cap ? cap : best;
}

// 2-level search: report objects up to 2 hops from gm/level that hold a Field
// vector OR are the game-object manager, with their path. Record (4 u32):
//   ids[4k]   = (source<<28) | o1
//   ids[4k+1] = o2   (0xffffffff means the level-1 object itself)
//   ids[4k+2] = vtable RVA
//   ids[4k+3] = field count held by that object
uint32_t diag_dump(uint64_t gm, uint64_t level) {
    uint64_t roots[2] = { gm, level };
    uint64_t mgr_vt = A(off::MGR_VTABLE);
    uint32_t rec = 0;
    auto emit = [&](uint32_t s, uint32_t o1, uint32_t o2, uint64_t vt, uint32_t fc) {
        if (rec >= 30) return;
        nx_mailbox.ids[rec * 4]     = (s << 28) | o1;
        nx_mailbox.ids[rec * 4 + 1] = o2;
        nx_mailbox.ids[rec * 4 + 2] = static_cast<uint32_t>(vt - g_libg_base);
        nx_mailbox.ids[rec * 4 + 3] = fc;
        rec++;
    };
    for (int s = 0; s < 2 && rec < 30; s++) {
        uint64_t root = roots[s];
        if (!is_heap(root) || !is_readable(root)) continue;
        for (uintptr_t o1 = 0; o1 < 0x400 && rec < 30; o1 += 8) {
            uint64_t m1 = srd64(root + o1);
            if (!is_heap(m1) || !is_readable(m1)) continue;
            uint64_t vt1 = srd64(m1);
            if (!is_lib(vt1)) continue;
            uint32_t fc1 = try_field_vector(m1, g_tmp, 256);
            if (fc1 > 0 || vt1 == mgr_vt)
                emit(static_cast<uint32_t>(s), static_cast<uint32_t>(o1), 0xffffffffu, vt1, fc1);
            for (uintptr_t o2 = 0; o2 < 0x400 && rec < 30; o2 += 8) {
                uint64_t m2 = srd64(m1 + o2);
                if (!is_heap(m2) || !is_readable(m2)) continue;
                uint64_t vt2 = srd64(m2);
                if (!is_lib(vt2)) continue;
                uint32_t fc2 = try_field_vector(m2, g_tmp, 256);
                if (fc2 > 0 || vt2 == mgr_vt)
                    emit(static_cast<uint32_t>(s), static_cast<uint32_t>(o1),
                         static_cast<uint32_t>(o2), vt2, fc2);
            }
        }
    }
    return rec;
}

// ============================================================================
//  Reliable enumeration: read the game's OWN object list in-process.
//  A vector<Field*> holds POINTERS, so fields scattered across separate heap
//  blocks are all reached - the thing the address-walking scrape could not do.
//  We read the game's live container, never raw heap, so there is no stale
//  generation to filter and nothing Promon reacts to (it is the same structured
//  access the game itself performs every frame).
// ============================================================================

// A live Field's pool slot points back at it: *(field+FIELD_SLOT) -> slot and
// *(slot+8) == field. Same cheap check the loader used; drops any stale entry a
// container might still reference.
inline bool field_is_live(uint64_t f) {
    uint64_t slot = srd64(f + off::FIELD_SLOT);
    return is_heap(slot) && srd64(slot + 8) == f;
}

// Collect field ids from a std::vector<GameObject*> given by {begin,end}. Prefers
// live fields; if NONE pass the liveness check (its assumption doesn't hold in
// this state) it returns every Field-vtable entry, so a valid container can never
// under-count. `raw` (optional) receives the pre-liveness Field count.
uint32_t collect_fields_from_ptrvec(uint64_t begin, uint64_t end,
                                    uint32_t* out, uint32_t cap, uint32_t* raw) {
    if (raw) *raw = 0;
    if (!is_heap(begin) || !is_heap(end) || end <= begin) return 0;
    uint64_t span = end - begin;
    if ((span % 8) != 0) return 0;
    uint64_t cnt = span / 8;
    if (cnt > 16000) return 0;                       // implausible -> bad offset guard
    uint32_t n = 0, rc = 0;
    for (uint64_t k = 0; k < cnt; k++) {
        uint64_t f = srd64(begin + k * 8);
        if (!is_field(f)) continue;
        rc++;
        if (field_is_live(f) && n < cap) out[n++] = field_id(f);
    }
    if (raw) *raw = rc;
    if (n) return n;
    for (uint64_t k = 0; k < cnt && n < cap; k++) {  // no liveness agreement: keep all
        uint64_t f = srd64(begin + k * 8);
        if (is_field(f)) out[n++] = field_id(f);
    }
    return n;
}

// Resolve the type-4 (field) sub-manager from a GameMode/Level root using the
// object model reversed from getGameObjectByGlobalId (0xc6d58c):
//   mgr = *(root+0x220);  subMgr = (*(mgr+0x15c8))[FIELD_TYPE]
// Tries root=gm then root=level(*(gm+0x10)) and validates the manager shape (a
// sane type-count + a heap type-array). Cheap, bounded, structured reads only.
uint64_t field_submgr(uint64_t gm) {
    uint64_t level = sderef(gm, off::GM_LEVEL);
    uint64_t roots[2] = { gm, level };
    for (int i = 0; i < 2; i++) {
        uint64_t root = roots[i];
        if (!is_heap(root) || !is_readable(root)) continue;
        uint64_t mgr = sderef(root, off::ROOT_MANAGER);
        if (!is_heap(mgr) || !is_readable(mgr)) continue;
        uint32_t tc = srd32(mgr + off::MGR_TYPE_COUNT);
        uint64_t ta = sderef(mgr, off::MGR_TYPE_ARRAY);
        if (tc <= off::FIELD_TYPE || tc > 0x10000 || !is_heap(ta)) continue;
        uint64_t sub = srd64(ta + off::FIELD_TYPE * 8);
        if (is_heap(sub) && is_readable(sub)) return sub;
    }
    return 0;
}

// Collect field ids from the field sub-manager's object container. Scans the
// sub-manager's first 0x200 bytes (cheap + bounded) for either a std::vector
// {begin,end} of Field* OR a LogicArrayList {T* items, int32 size} of Field*,
// then filters by Field vtable + slot-back-ref liveness. Reading a POINTER
// container means fields scattered across separate heap blocks are all reached.
uint32_t collect_submgr_fields(uint64_t sub, uint32_t* out, uint32_t cap) {
    // (a) {begin,end} pointer vector
    for (uintptr_t o = 0; o + 16 <= 0x200; o += 8) {
        uint64_t b = srd64(sub + o), e = srd64(sub + o + 8);
        if (is_heap(b) && is_heap(e) && b < e && ((e - b) % 8) == 0 && (e - b) / 8 <= 8192) {
            uint32_t n = collect_fields_from_ptrvec(b, e, out, cap, nullptr);
            if (n) return n;
        }
    }
    // (b) {T* items, int32 size} array-list
    for (uintptr_t o = 0; o + 12 <= 0x200; o += 8) {
        uint64_t b = srd64(sub + o);
        uint32_t sz = srd32(sub + o + 8);
        if (is_heap(b) && sz >= 1 && sz <= 8192) {
            uint32_t n = collect_fields_from_ptrvec(b, b + (uint64_t)sz * 8, out, cap, nullptr);
            if (n) return n;
        }
    }
    return 0;
}

// Scan a candidate holder object AND its immediate child objects (one hop) for a
// Field* container. Bounded (~holder 0x200 + up to ~64 children x 0x200) so it
// stays cheap and never becomes the broad-graph traversal that froze the game.
uint32_t scan_holder_1hop(uint64_t obj, uint32_t* out, uint32_t cap) {
    if (!is_heap(obj) || !is_readable(obj)) return 0;
    uint32_t n = collect_submgr_fields(obj, out, cap);
    if (n) return n;
    for (uintptr_t o = 0; o + 8 <= 0x200; o += 8) {
        uint64_t c = srd64(obj + o);
        if (!is_heap(c) || !is_readable(c)) continue;
        n = collect_submgr_fields(c, out, cap);
        if (n) return n;
    }
    return 0;
}

// Enumerate live field ids from the game's own game-object manager. The manager
// that holds live Field instances (vtable 0x14cfea0) is NOT the +0x220 data-table
// manager; try the known instance-holder roots, one hop deep, cheapest first.
uint32_t read_field_container(void* gmv, uint32_t* out, uint32_t cap) {
    uint64_t gm = reinterpret_cast<uint64_t>(gmv);
    uint64_t level = sderef(gm, off::GM_LEVEL);
    uint64_t cands[3] = { sderef(level, 0x138), sderef(level, 0x1e8), field_submgr(gm) };
    for (int i = 0; i < 3; i++) {
        uint32_t n = scan_holder_1hop(cands[i], out, cap);
        if (n) return n;
    }
    return 0;
}

// Dump the gm->manager->type-array->type-4 chain and the field sub-manager's raw
// layout to logcat, so one live run confirms the manager root (gm vs level) and
// the field container. Read-only + bounded. Returns the type-4 field count.
uint32_t fields_diag(void* gmv) {
    static uint32_t tmp[256];
    uint64_t gm = reinterpret_cast<uint64_t>(gmv);
    uint64_t level = sderef(gm, off::GM_LEVEL);
    NXLOG("fdiag gm=0x%lx level=0x%lx", (unsigned long)gm, (unsigned long)level);
    uint64_t roots[2] = { gm, level };
    const char* rn[2] = { "gm", "level" };
    uint32_t best = 0;
    for (int i = 0; i < 2; i++) {
        uint64_t root = roots[i];
        if (!is_heap(root) || !is_readable(root)) continue;
        uint64_t mgr = sderef(root, off::ROOT_MANAGER);
        uint32_t tc = is_heap(mgr) ? srd32(mgr + off::MGR_TYPE_COUNT) : 0;
        uint64_t ta = is_heap(mgr) ? sderef(mgr, off::MGR_TYPE_ARRAY) : 0;
        NXLOG("fdiag %s+0x220 mgr=0x%lx typecount=%u typearray=0x%lx",
              rn[i], (unsigned long)mgr, tc, (unsigned long)ta);
        if (tc <= off::FIELD_TYPE || tc > 0x10000 || !is_heap(ta)) continue;
        for (uint32_t t = 0; t < tc && t < 12; t++) {
            uint64_t s  = srd64(ta + t * 8);
            uint64_t vt = is_heap(s) ? srd64(s) : 0;
            NXLOG("fdiag   type[%u] sub=0x%lx vt+0x%lx", t, (unsigned long)s,
                  vt ? (unsigned long)(vt - g_libg_base) : 0);
        }
        if (off::FIELD_TYPE >= tc) continue;
        uint64_t sub = srd64(ta + off::FIELD_TYPE * 8);
        if (!is_heap(sub)) continue;
        for (int o = 0; o < 0x50; o += 8)                  // raw layout, to eyeball the container
            NXLOG("fdiag   sub+0x%02x = 0x%lx", o, (unsigned long)srd64(sub + o));
        // For each heap-pointer field in the sub-manager, dump the first entries
        // of the array it points at + each entry's vtable, so we can see whether
        // any array holds Field instances (vtable 0x14cfea0) vs pure data.
        const uintptr_t arr_offs[4] = { 0x18, 0x28, 0x38, 0x40 };
        for (int a = 0; a < 4; a++) {
            uint64_t arr = srd64(sub + arr_offs[a]);
            if (!is_heap(arr) || !is_readable(arr)) continue;
            for (int e = 0; e < 6; e++) {
                uint64_t el = srd64(arr + e * 8);
                uint64_t vt = is_heap(el) ? srd64(el) : 0;
                uint32_t eid = is_heap(el) ? srd32(el + off::FIELD_ID) : 0;
                NXLOG("fdiag   arr[sub+0x%02lx][%d]=0x%lx vt+0x%lx id=%u%s",
                      (unsigned long)arr_offs[a], e, (unsigned long)el,
                      vt ? (unsigned long)(vt - g_libg_base) : 0, eid,
                      (vt == A(off::FIELD_VTABLE)) ? "  <== FIELD" : "");
            }
        }
        uint32_t n = collect_submgr_fields(sub, tmp, 256);
        NXLOG("fdiag   type4 sub=0x%lx -> %u field(s)", (unsigned long)sub, n);
        for (uint32_t k = 0; k < n && k < 8; k++) NXLOG("fdiag     id[%u]=%u", k, tmp[k]);
        if (n > best) {
            best = n;
            for (uint32_t k = 0; k < n && k < 128; k++) nx_mailbox.ids[k] = tmp[k];
        }
    }
    // Candidate instance-holders (where live Field objects actually live): scan
    // each one hop deep for a vtable-0x14cfea0 field vector.
    uint64_t cands[3] = { sderef(level, 0x138), sderef(level, 0x1e8), field_submgr(gm) };
    const char* cn[3] = { "level+0x138", "level+0x1e8", "datamgr.type4" };
    for (int i = 0; i < 3; i++) {
        uint64_t o = cands[i];
        uint32_t n = scan_holder_1hop(o, tmp, 256);
        uint64_t vt = (is_heap(o) && is_readable(o)) ? srd64(o) : 0;
        NXLOG("fdiag CAND %s=0x%lx vt+0x%lx -> %u field(s)", cn[i], (unsigned long)o,
              (unsigned long)(vt ? vt - g_libg_base : 0), n);
        for (uint32_t k = 0; k < n && k < 8; k++) NXLOG("fdiag   %s id[%u]=%u", cn[i], k, tmp[k]);
        if (n > best) {
            best = n;
            for (uint32_t k = 0; k < n && k < 128; k++) nx_mailbox.ids[k] = tmp[k];
        }
    }
    nx_mailbox.scan_count = best;
    return best;
}

// ============================================================================
//  Anti-ban: present a coherent real device (device_profile.h) by data-hooking
//  libg's libc imports. Reading the game's DATA SOURCE (open/props) rather than
//  chasing its detection logic. GOT data-hooks are not reverted by Promon and
//  only affect the game's own reads. VERIFY-FIRST: spoof_scan() reports the
//  hookable slots before anything is patched.
// ============================================================================

// Resolve the GOT slot (address of the pointer) for a named PLT import in the
// LIVE libg by walking its in-memory dynamic section (PT_DYNAMIC -> JMPREL).
// d_ptr entries may be link-time vaddrs (add base) or already absolute; `fix`
// handles both. Returns the slot address, or 0 if not imported.
uint64_t find_import_slot(const char* name) {
    uint64_t base = g_libg_base;
    if (!base) return 0;
    auto* eh = reinterpret_cast<Elf64_Ehdr*>(base);
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E') return 0;
    auto fix = [&](uint64_t p) -> uint64_t {
        return (p >= base && p < base + 0x1660000) ? p : base + p;
    };
    auto* ph = reinterpret_cast<Elf64_Phdr*>(base + eh->e_phoff);
    Elf64_Dyn* dyn = nullptr;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) { dyn = reinterpret_cast<Elf64_Dyn*>(base + ph[i].p_vaddr); break; }
    if (!dyn) return 0;
    const char* strtab = nullptr; Elf64_Sym* symtab = nullptr;
    Elf64_Rela* jmprel = nullptr; uint64_t pltrelsz = 0;
    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_STRTAB:   strtab = reinterpret_cast<const char*>(fix(d->d_un.d_ptr)); break;
            case DT_SYMTAB:   symtab = reinterpret_cast<Elf64_Sym*>(fix(d->d_un.d_ptr)); break;
            case DT_JMPREL:   jmprel = reinterpret_cast<Elf64_Rela*>(fix(d->d_un.d_ptr)); break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return 0;
    uint64_t n = pltrelsz / sizeof(Elf64_Rela);
    for (uint64_t i = 0; i < n; i++) {
        uint32_t si = static_cast<uint32_t>(ELF64_R_SYM(jmprel[i].r_info));
        const char* sn = strtab + symtab[si].st_name;
        if (std::strcmp(sn, name) == 0) return base + jmprel[i].r_offset;
    }
    return 0;
}

// Report which libc imports we can data-hook, and their current target. No patch.
void spoof_scan() {
    static const char* names[] = {
        "open", "open64", "openat", "openat64", "__openat", "fopen", "fopen64",
        "access", "faccessat", "stat", "stat64", "lstat", "fstatat", "__statfs",
        "readlink", "readlinkat", "__system_property_get", "__system_property_find",
        "__system_property_read", "__system_property_read_callback",
    };
    NXLOG("spoof scan: libg base=0x%lx", (unsigned long)g_libg_base);
    for (auto nm : names) {
        uint64_t slot = find_import_slot(nm);
        if (slot) {
            uint64_t cur = is_readable(slot) ? *reinterpret_cast<uint64_t*>(slot) : 0;
            NXLOG("spoof import %-30s slot=0x%lx -> fn=0x%lx", nm,
                  (unsigned long)slot, (unsigned long)cur);
        }
    }
}

// ---- device-info spoof: GOT data-hook libg's open() import ------------------
// Redirect /proc/cpuinfo to a file holding the S24 Ultra (Snapdragon) cpuinfo,
// and make root/qemu markers appear absent. A GOT data-hook (not an inline code
// patch) so Promon doesn't revert it, and it only affects the game's own opens.
using open_fn = int (*)(const char*, int, ...);
static open_fn g_orig_open = nullptr;
static uint64_t g_open_slot = 0;
static char g_cpuinfo_path[192] = {0};
static bool g_spoof_on = false;

static bool path_is_hidden(const char* p) {
    if (!p) return false;
    for (int i = 0; i < dev::HIDE_PATHS_N; i++)
        if (std::strcmp(p, dev::HIDE_PATHS[i]) == 0) return true;
    return false;
}

static int g_open_hits = 0;   // log the first few intercepts (proof it fires)

static int nx_open(const char* path, int flags, ...) {
    int mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    if (g_spoof_on && path) {
        if (g_cpuinfo_path[0] && std::strcmp(path, dev::CPUINFO_PATH) == 0) {
            if (g_open_hits < 12) { g_open_hits++; NXLOG("spoof: /proc/cpuinfo -> S24 Ultra"); }
            return g_orig_open(g_cpuinfo_path, flags, mode);   // spoofed cpuinfo
        }
        if (path_is_hidden(path)) {
            if (g_open_hits < 12) { g_open_hits++; NXLOG("spoof: hidden %s -> ENOENT", path); }
            errno = ENOENT; return -1;
        }
    }
    return g_orig_open ? g_orig_open(path, flags, mode) : -1;
}

// Write the spoofed cpuinfo to the app's files dir (where our module lives).
// Called once at nx_init - OFF the game thread (game-thread file I/O froze it).
void write_cpuinfo_file() {
    std::strcpy(g_cpuinfo_path, "/data/user/0/com.supercell.hayday/files/nx_cpuinfo");
    FILE* f = std::fopen(g_cpuinfo_path, "w");
    if (f) { std::fputs(dev::CPUINFO, f); std::fclose(f); }
    else { g_cpuinfo_path[0] = 0; }
}

uint32_t spoof_install() {
    if (g_spoof_on) return 2;
    uint64_t slot = find_import_slot("open");
    if (!slot) { NXERR("spoof: libg 'open' import not found"); return 0; }
    g_open_slot = slot;
    g_orig_open = reinterpret_cast<open_fn>(*reinterpret_cast<uint64_t*>(slot));
    uint64_t page = slot & ~0xFFFULL;                     // RELRO may make the slot RO
    mprotect(reinterpret_cast<void*>(page), 0x1000, PROT_READ | PROT_WRITE);
    *reinterpret_cast<volatile uint64_t*>(slot) = reinterpret_cast<uint64_t>(&nx_open);
    g_spoof_on = true;
    NXLOG("spoof ON: open slot=0x%lx orig=%p nx_open=%p cpuinfo='%s' hide=%d",
          (unsigned long)slot, (void*)g_orig_open, (void*)&nx_open, g_cpuinfo_path,
          dev::HIDE_PATHS_N);
    return 1;
}

uint32_t spoof_uninstall() {
    if (!g_spoof_on || !g_open_slot) return 0;
    *reinterpret_cast<volatile uint64_t*>(g_open_slot) = reinterpret_cast<uint64_t>(g_orig_open);
    g_spoof_on = false;
    NXLOG("spoof OFF: restored open");
    return 1;
}

} // namespace
} // namespace nx

// ------------------------------------------------ game-thread callback --------
// Reached from a cave the loader installs on the tick (x0 = GameMode). Runs on
// the game thread at a safe point, so command execution here is race-free.
extern "C" __attribute__((visibility("default")))
void nx_on_tick(void* gm) {
    nx::nx_mailbox.magic = nx::MB_MAGIC;
    nx::nx_mailbox.gameMode = reinterpret_cast<uint64_t>(gm);
    nx::nx_mailbox.heartbeat++;
    uint32_t cmd = nx::nx_mailbox.cmd;
    if (cmd == nx::CMD_IDLE) return;
    switch (cmd) {
        case nx::CMD_PING:
            nx::nx_mailbox.count = 0xABCD;
            break;
        case nx::CMD_DIAG:
            nx::nx_mailbox.count = nx::diag_dump(
                reinterpret_cast<uint64_t>(gm), nx::sderef(reinterpret_cast<uint64_t>(gm), nx::off::GM_LEVEL));
            break;
        case nx::CMD_FIELDS:
            // Enumerate by reading the game's OWN object list in-process (no heap
            // scrape): manager vector<Field*> first, then fallbacks. Writes the
            // live ids straight into the mailbox the loader reads back.
            nx::nx_mailbox.count = nx::read_field_container(gm, nx::nx_mailbox.ids, 128);
            break;
        case nx::CMD_FIELDS_DIAG:
            // Report each candidate container's field count (to scan_* + logcat)
            // so we can confirm which is canonical before trusting it.
            nx::nx_mailbox.count = nx::fields_diag(gm);
            break;
        case nx::CMD_SPOOF_SCAN:
            // Anti-ban verify step: report libg's hookable libc import slots.
            nx::spoof_scan();
            nx::nx_mailbox.count = 1;
            break;
        case nx::CMD_SPOOF_ON:
            // Install the open() GOT hook (cpuinfo redirect + root hiding).
            nx::nx_mailbox.count = nx::spoof_install();
            break;
        case nx::CMD_SPOOF_OFF:
            nx::nx_mailbox.count = nx::spoof_uninstall();
            break;
        case nx::CMD_PLANT: {
            // ids[0..arg1) are supplied by the loader (reliable RPC enumeration);
            // execute the plant command for each on the game thread.
            uint32_t crop = nx::nx_mailbox.arg0 ? nx::nx_mailbox.arg0 : nx::off::CROP_WHEAT;
            uint32_t k = nx::nx_mailbox.arg1;
            if (k > 128) k = 128;
            for (uint32_t i = 0; i < k; i++)
                nx::plant_field(gm, nx::nx_mailbox.ids[i], crop);
            nx::nx_mailbox.count = k;
            break;
        }
        case nx::CMD_HARVEST: {
            uint32_t k = nx::nx_mailbox.arg1;
            if (k > 128) k = 128;
            for (uint32_t i = 0; i < k; i++)
                nx::harvest_field(gm, nx::nx_mailbox.ids[i]);
            nx::nx_mailbox.count = k;
            break;
        }
        case nx::CMD_SELL: {
            // ids[] = {slot, item, count, price, ad}
            nx::sell_item(gm, nx::nx_mailbox.ids[0], nx::nx_mailbox.ids[1],
                          nx::nx_mailbox.ids[2], nx::nx_mailbox.ids[3],
                          nx::nx_mailbox.ids[4]);
            nx::nx_mailbox.count = 1;
            break;
        }
        default:
            nx::nx_mailbox.err = cmd;
            nx::nx_mailbox.status = nx::ST_ERR;
            nx::nx_mailbox.cmd = nx::CMD_IDLE;
            return;
    }
    nx::nx_mailbox.status = nx::ST_DONE;
    nx::nx_mailbox.cmd = nx::CMD_IDLE;
}

// -------------------------------------------------------------- public init ---
extern "C" __attribute__((visibility("default")))
int nx_init() {
    nx::g_libg_base = nx::resolve_lib_base("libg.so");
    if (!nx::g_libg_base) {
        NXERR("nx_init: libg.so NOT found");
        return -1;
    }
    NXLOG("nx_init: OK  libg @ 0x%lx  mailbox @ %p  on_tick @ %p",
          (unsigned long)nx::g_libg_base, (void*)&nx::nx_mailbox, (void*)&nx_on_tick);
    uint32_t insn = nx::rd32(nx::A(nx::off::TICK));
    NXLOG("validate: [tick] first insn = 0x%08x", insn);
    // Capture the clean 16-byte tick prologue now, before any gate patches it,
    // so the loader's bridge cave never has to read a possibly-hooked tick.
    for (int i = 0; i < 4; i++)
        nx::nx_mailbox.tick_stolen[i] = nx::rd32(nx::A(nx::off::TICK) + i * 4);
    // Start the readable-range refresher: it seeds the /proc/self/maps snapshot
    // NOW (module load thread, not the game thread) and refreshes it OFF the game
    // thread on demand (loader bumps scan_req -> range_thread refreshes -> bumps
    // scan_gen). is_readable() needs this, else EVERY crash-safe read (srd64/
    // sderef) short-circuits to 0 - which is why read_field_container/fields_diag
    // read nothing. It does NOT scan memory (scan_fields is no longer called), and
    // only broad scanning trips Promon - reading the maps file off-thread does not.
    // The broad in-process heap SCANNER and its process-wide SIGSEGV guard stay
    // OFF (Promon freezes on broad scans; a SIGSEGV handler is risky in an ART
    // process - ART/Houdini use SIGSEGV for null checks and GC barriers). Fields
    // are read from the game's OWN container instead (read_field_container).
    nx::start_range_refresher();
    nx::write_cpuinfo_file();   // stage the spoofed cpuinfo now (off the game thread)
    return 0;
}

extern "C" __attribute__((visibility("default")))
uintptr_t nx_ping() { return nx::g_libg_base; }

__attribute__((constructor))
static void nx_ctor() {
    NXLOG("libnxrth loaded (ctor)  build=%s %s", __DATE__, __TIME__);
    nx_init();
}
