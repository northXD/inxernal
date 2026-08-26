// =============================================================================
//  INXERNAL - engine / console / bot logic
// -----------------------------------------------------------------------------
//  Everything below the UI lives here. Two responsibilities:
//    1. The log + console subsystem (the "always on" console from the design
//       note): prints the INXERNAL banner, animates a spinner, and streams
//       every log line. Runs on its own thread so it is independent of the UI.
//    2. Stubs for the bot / developer functions. Each one records the intent in
//       the log and (for dev commands) pushes a loader.py-style command string
//       through Dispatch(). Port loader.py into Dispatch() and it all goes live.
// =============================================================================

#include "engine.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>   // must precede <windows.h> to avoid the winsock v1 clash
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")   // link the sockets library without a build-file edit

// Legacy global (referenced by older prototype code). Mirrors state().running.
bool isRunning = false;

namespace Engine {

// ------------------------------------------------------------------- state ----
State& state() {
    static State s;
    return s;
}

// ------------------------------------------------------------- log internals --
namespace {

std::mutex                g_logMutex;
std::condition_variable   g_logCv;
std::deque<LogLine>       g_history;    // full-ish history for the UI panel
std::deque<LogLine>       g_pending;    // not-yet-printed lines for the console
std::atomic<bool>         g_consoleRun{ false };
std::thread               g_consoleThread;
constexpr size_t          kHistoryCap = 4000;

std::chrono::steady_clock::time_point g_start = std::chrono::steady_clock::now();

double Now() {
    using namespace std::chrono;
    return duration_cast<duration<double>>(steady_clock::now() - g_start).count();
}

// Console text colour (Windows console attributes) - deliberately restrained:
// plain grey for normal lines, red for errors, dim for command/debug echoes.
WORD ColorFor(LogLevel level) {
    switch (level) {
        case LogLevel::Error:   return FOREGROUND_RED | FOREGROUND_INTENSITY;
        case LogLevel::Warning: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case LogLevel::Debug:
        case LogLevel::Command: return FOREGROUND_BLUE | FOREGROUND_GREEN;   // dim
        default:                return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

HANDLE StdOut() {
    static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    return h;
}

void PrintBanner() {
    HANDLE h = StdOut();
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "\n  INXERNAL";
    SetConsoleTextAttribute(h, FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "   internal console\n\n";
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout.flush();
}

void PrintLine(const LogLine& line) {
    HANDLE h = StdOut();
    char stamp[32];
    std::snprintf(stamp, sizeof(stamp), "  %7.1f  ", line.time);

    SetConsoleTextAttribute(h, FOREGROUND_BLUE | FOREGROUND_GREEN);   // dim timestamp
    std::cout << stamp;
    SetConsoleTextAttribute(h, ColorFor(line.level));
    std::cout << line.text << '\n';
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Simple, quiet drain loop - no spinner, no animation. Logs just stream in.
void ConsoleLoop() {
    PrintBanner();
    while (g_consoleRun.load()) {
        std::deque<LogLine> batch;
        {
            std::unique_lock<std::mutex> lock(g_logMutex);
            g_logCv.wait_for(lock, std::chrono::milliseconds(200),
                             [] { return !g_pending.empty() || !g_consoleRun.load(); });
            batch.swap(g_pending);
        }
        for (const auto& line : batch)
            PrintLine(line);
    }
}

} // namespace

// ---------------------------------------------------------------- log API -----
void Log(LogLevel level, const std::string& text) {
    LogLine line{ Now(), level, text };
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_history.push_back(line);
        while (g_history.size() > kHistoryCap)
            g_history.pop_front();
        g_pending.push_back(std::move(line));
    }
    g_logCv.notify_one();
}

void LogInfo(const std::string& text) { Log(LogLevel::Info,    text); }
void LogOk  (const std::string& text) { Log(LogLevel::Success, text); }
void LogWarn(const std::string& text) { Log(LogLevel::Warning, text); }
void LogErr (const std::string& text) { Log(LogLevel::Error,   text); }
void LogCmd (const std::string& text) { Log(LogLevel::Command, text); }

void CopyLog(std::vector<LogLine>& out) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    out.assign(g_history.begin(), g_history.end());
}

void ClearLog() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_history.clear();
}

// ------------------------------------------------------------- console ctl ----
void ConsoleStart() {
    if (g_consoleRun.exchange(true))
        return;                          // already running
    g_consoleThread = std::thread(ConsoleLoop);
}

void ConsoleStop() {
    if (!g_consoleRun.exchange(false))
        return;
    g_logCv.notify_all();
    if (g_consoleThread.joinable())
        g_consoleThread.join();
}

// ---------------------------------------------------------- control channel ---
// The Python loader exposes a line protocol over localhost TCP. Each command is
// one UTF-8 line ("<cmd> [args...]\n"); the reply is one line ("OK ..." /
// "ERR ..."). We reconnect per command - simplest and robust - and bound every
// blocking step with a timeout so a down or hung loader can never wedge the UI.
namespace {

constexpr const char*    kCtlHost          = "127.0.0.1";
constexpr unsigned short kCtlPort          = 31350;
constexpr long           kConnectTimeoutMs = 2000;    // localhost connect ceiling
constexpr long           kIoTimeoutMs      = 12000;   // send/recv ceiling (native enum/farm are slow)

std::once_flag g_wsaOnce;
bool           g_wsaOk = false;

void EnsureWinsock() {
    std::call_once(g_wsaOnce, [] {
        WSADATA wsa;
        g_wsaOk = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    });
}

// Connect -> send one line -> read one line -> close. Returns the response line
// (trailing CR/LF stripped) on success, or a synthetic "ERR <reason>" on any
// socket failure so callers always get a usable string and the UI never throws.
std::string SendCommand(const std::string& command) {
    EnsureWinsock();
    if (!g_wsaOk)
        return "ERR winsock init failed";

    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return "ERR socket() failed (" + std::to_string(WSAGetLastError()) + ")";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(kCtlPort);
    if (::inet_pton(AF_INET, kCtlHost, &addr.sin_addr) != 1) {
        ::closesocket(sock);
        return "ERR bad host address";
    }

    // --- connect with a bounded timeout (non-blocking connect + select) ------
    u_long nonblock = 1;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            ::closesocket(sock);
            return "ERR loader not reachable (" + std::to_string(err) + ")";
        }
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        timeval tv{};
        tv.tv_sec  = kConnectTimeoutMs / 1000;
        tv.tv_usec = (kConnectTimeoutMs % 1000) * 1000;
        if (::select(0, nullptr, &wset, nullptr, &tv) <= 0) {
            ::closesocket(sock);
            return "ERR loader not running (connect timeout)";
        }
        int soerr = 0, soerrLen = sizeof(soerr);
        ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &soerrLen);
        if (soerr != 0) {
            ::closesocket(sock);
            return "ERR loader refused connection (" + std::to_string(soerr) + ")";
        }
    }

    // back to blocking, but with send/recv timeouts so a hung loader can't wedge us
    nonblock = 0;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    DWORD tmo = static_cast<DWORD>(kIoTimeoutMs);
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&tmo), sizeof(tmo));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&tmo), sizeof(tmo));

    // --- send the command line ----------------------------------------------
    std::string line = command;
    line.push_back('\n');
    size_t sent = 0;
    while (sent < line.size()) {
        int n = ::send(sock, line.data() + sent, static_cast<int>(line.size() - sent), 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            ::closesocket(sock);
            return "ERR send failed (" + std::to_string(err) + ")";
        }
        sent += static_cast<size_t>(n);
    }

    // --- read one response line ---------------------------------------------
    std::string resp;
    char buf[512];
    for (;;) {
        int n = ::recv(sock, buf, static_cast<int>(sizeof(buf)), 0);
        if (n > 0) {
            resp.append(buf, buf + n);
            size_t nl = resp.find('\n');
            if (nl != std::string::npos) { resp.resize(nl); break; }
            if (resp.size() > (1u << 20)) break;          // 1 MB sanity cap
        } else if (n == 0) {
            break;                                        // peer closed cleanly
        } else {
            int err = WSAGetLastError();
            ::closesocket(sock);
            if (err == WSAETIMEDOUT)
                return "ERR loader timeout (no response)";
            if (resp.empty())
                return "ERR recv failed (" + std::to_string(err) + ")";
            break;
        }
    }
    ::closesocket(sock);

    while (!resp.empty() && (resp.back() == '\r' || resp.back() == '\n'))
        resp.pop_back();

    if (resp.empty())
        return "ERR empty response";
    return resp;
}

} // namespace

// ---------------------------------------------------------- integration seam --
std::string Dispatch(const std::string& command) {
    LogCmd(command);
    std::string response = SendCommand(command);
    state().lastResponse = response;
    if (response.rfind("OK", 0) == 0)
        LogOk(response);
    else if (response.rfind("ERR", 0) == 0)
        LogErr(response);
    else
        LogInfo(response);
    return response;
}

// ===========================================================================
//  CONTROL PANEL operations
// ===========================================================================
void StartBot() { state().running = true;  isRunning = true;  LogInfo("bot started"); }
void StopBot()  { state().running = false; isRunning = false; LogInfo("bot stopped"); }
void ToggleBot(){ state().running ? StopBot() : StartBot(); }

void PlantAll()  { Dispatch("plant"); }        // plant [crop] - default crop, all fields
void HarvestAll(){ Dispatch("harvest"); }      // harvest - every ready field
void OpenMarket(){ LogInfo("open the roadside shop, then use Developer > Roadside Shop"); }
void Sell(const std::string& slot, const std::string& count,
          const std::string& price, bool ad, const std::string& item) {
    // control protocol: sell <slot> [count] [price] [ad]  (item kept as a trailing
    // optional the loader accepts; harmless if it ignores it).
    Dispatch("sell " + slot + " " + count + " " + price + " " +
             (ad ? "1" : "0") + " " + item);
}

void FarmStart() {
    State& s = state();
    s.farmLoop = true;
    // farm start [wait] [crop]
    Dispatch("farm start " + std::to_string(s.farmWaitSeconds) + " " +
             std::to_string(s.farmCropId));
}
void FarmStop() { state().farmLoop = false; Dispatch("farm stop"); }

void GetFieldIDs() { Dispatch("fields"); }
void TestADB() {                                // ask the loader to probe the ADB device
    std::string r = Dispatch("adb");
    state().deviceOnline = (r.rfind("OK", 0) == 0);
}
void RefreshInfo() { Dispatch("status"); }      // loader status snapshot

// ===========================================================================
//  DEVELOPER MODE operations (1:1 with loader.py commands)
// ===========================================================================
static std::string Join(const std::string& a, const std::string& b) {
    return b.empty() ? a : a + " " + b;
}

// --- Memory ---
std::string ReadMem(const std::string& type, const std::string& offset, const std::string& len) {
    return Dispatch(Join("read " + type + " " + offset, len));
}
void WriteMem(const std::string& type, const std::string& offset, const std::string& value) {
    Dispatch("write " + type + " " + offset + " " + value);
}
std::string DumpMem(const std::string& offset, const std::string& len) {
    return Dispatch("dump " + offset + " " + len);
}
void PatternScan(const std::string& pattern) {
    Dispatch("scan " + pattern);
}
std::string ReadAbs(const std::string& addr, const std::string& len) {
    return Dispatch("rabs " + addr + " " + len);
}
void WriteAbs(const std::string& addr, const std::string& hexbytes) {
    Dispatch("wabs " + addr + " " + hexbytes);
}

// --- Value scanner ---
void ValueScan  (const std::string& type, const std::string& value) { Dispatch("vscan " + type + " " + value); }
void ValueNarrow(const std::string& type, const std::string& value) { Dispatch("vnarrow " + type + " " + value); }
void ValueList  ()                                                  { Dispatch("vlist"); }
void ValueWrite (const std::string& value, const std::string& index){ Dispatch(Join("vwrite " + value, index)); }
void ValueReset ()                                                  { state().scanMatches = -1; Dispatch("vreset"); }

// --- Patching & caves ---
void AllocCave(const std::string& size)                              { Dispatch(Join("cave", size)); }
void Nop      (const std::string& offset, const std::string& count)  { Dispatch("nop " + offset + " " + count); }
void FarJump  (const std::string& offset, const std::string& target) { Dispatch("farjump " + offset + " " + target); }
void Branch   (const std::string& offset, const std::string& target, bool link) {
    Dispatch("branch " + offset + " " + target + (link ? " link" : ""));
}
void CaveTest (const std::string& offset)    { Dispatch(Join("cavetest", offset)); }
void FlushTest(const std::string& offset)    { Dispatch(Join("flushtest", offset)); }
void GotHook  (const std::string& gotOffset) { Dispatch(Join("gothook", gotOffset)); }

// --- Command hooks & capture ---
void HookFn (const std::string& offset) { Dispatch("hook " + offset); }
void CmdHook()                          { Dispatch("cmdhook"); }
void CmdLog ()                          { Dispatch("cmdlog"); }
void ArgHook(const std::string& offset) { Dispatch(Join("arghook", offset)); }
void ArgLog ()                          { Dispatch("arglog"); }
void Capture(const std::string& secs)   { Dispatch(Join("capture", secs)); }

// --- Field enumeration & RE ---
void        Fields    ()                        { Dispatch("fields"); }
void        FindFields()                        { Dispatch("findfields"); }
void        FieldScan ()                        { LogWarn("fieldscan may freeze the game (full scan)"); Dispatch("fieldscan"); }
void        VtScan    ()                        { LogWarn("vtscan may freeze the game (full scan)");    Dispatch("vtscan"); }
void        Fdump     ()                        { Dispatch("fdump"); }
void        FieldDump ()                        { LogWarn("fielddump may freeze the game (full scan)"); Dispatch("fielddump"); }
void        ObjDump   (const std::string& addr) { Dispatch(Join("objdump", addr)); }
void        MgrDiag   ()                        { Dispatch("mgrdiag"); }
void        FindMgr   ()                        { Dispatch("findmgr"); }
void        FieldsDiag()                        { Dispatch("fieldsdiag"); }
void        DumpSo    (const std::string& outPath){ Dispatch(Join("dumpso", outPath)); }
std::string GetExport (const std::string& name) { return Dispatch("export " + name); }

} // namespace Engine
