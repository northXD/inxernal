#pragma once
// =============================================================================
//  INXERNAL - engine interface
// -----------------------------------------------------------------------------
//  This header is the seam between the UI (ui.cpp) and the actual bot logic.
//  Right now every function is a stub: it echoes an intent into the log system
//  and, for the developer-mode calls, funnels a loader.py-style command string
//  through Engine::Dispatch(). When the Python loader (loader.py + hook.js) is
//  ported to C++, wire Dispatch() to the real Frida/Gadget RPC bridge and every
//  button in the UI lights up without touching ui.cpp again.
//
//  Layout mirrors the plan in ui.cpp: the log/console lives here (the "always
//  on" side) and the UI is a detachable front-end that only talks to Engine::.
// =============================================================================

#include <string>
#include <vector>
#include <cstdint>

// Legacy global kept for existing references; kept in sync with state().running.
extern bool isRunning;

namespace Engine {

// ------------------------------------------------------------------ logging --
enum class LogLevel { Info, Success, Warning, Error, Debug, Command };

struct LogLine {
    double      time = 0.0;              // seconds since the console started
    LogLevel    level = LogLevel::Info;
    std::string text;
};

// ------------------------------------------------------- shared runtime state --
// Written by the engine / ops, read every frame by the UI to paint status.
struct State {
    bool                  running        = false;   // bot loop active
    bool                  deviceOnline   = false;   // ADB device present
    bool                  engineAttached = false;   // libg.so resolved / gadget attached
    bool                  heartbeatOk    = false;   // stable engine heartbeat
    bool                  farmLoop       = false;   // auto farm loop engaged
    int                   farmWaitSeconds = 120;
    int                   farmCropId     = 400001;  // wheat
    int                   pid            = 0;
    std::string           deviceId       = "-";
    std::string           libgBase       = "0x0";
    std::string           packageName    = "com.supercell.hayday";
    std::vector<uint32_t> currentFields;
    int                   scanMatches    = -1;       // last value-scan count (-1 = no scan)
    std::string           lastResponse   = "-";      // last reply from the loader control channel
};

State& state();

// -------------------------------------------------------- logging (thread safe) --
void        Log(LogLevel level, const std::string& text);
void        LogInfo(const std::string& text);
void        LogOk(const std::string& text);
void        LogWarn(const std::string& text);
void        LogErr(const std::string& text);
void        LogCmd(const std::string& text);
void        CopyLog(std::vector<LogLine>& out);   // snapshot the history for the UI panel
void        ClearLog();

// ---------------------------------------------------------- console subsystem --
// Prints the INXERNAL banner and runs the spinner + log-drain loop on its own
// thread. This is the "console" from the ui.cpp design note; the UI mirrors it.
void        ConsoleStart();
void        ConsoleStop();

// ------------------------------------------------------ the integration seam --
// Every action ends up here. Today: echo to the log. Tomorrow: run the ported
// loader command / Frida RPC and return the textual result.
std::string Dispatch(const std::string& command);

// =========================================================================== //
//  CONTROL PANEL (current mode) - high level, one-click bot operations         //
// =========================================================================== //
void StartBot();
void StopBot();
void ToggleBot();
void PlantAll();       // plant all
void HarvestAll();     // harvest all
void OpenMarket();     // market / roadside shop cycle
void Sell(const std::string& slot, const std::string& count,
          const std::string& price, bool ad, const std::string& item);  // sell <slot> ...
void FarmStart();      // farm  (harvest -> plant -> wait -> repeat)
void FarmStop();
void GetFieldIDs();    // fields
void TestADB();        // adb connectivity probe
void RefreshInfo();    // info

// =========================================================================== //
//  DEVELOPER MODE - the important functions (1:1 with loader.py commands)       //
//  Ported later; the UI already wires each one to its arguments.               //
// =========================================================================== //

// --- Memory (libg.so offsets) ------------------------------------------------
std::string ReadMem (const std::string& type, const std::string& offset, const std::string& len);
void        WriteMem(const std::string& type, const std::string& offset, const std::string& value);
std::string DumpMem (const std::string& offset, const std::string& len);
void        PatternScan(const std::string& pattern);   // scan  (file-backed libg.so AOB)
std::string ReadAbs (const std::string& addr, const std::string& len);
void        WriteAbs(const std::string& addr, const std::string& hexbytes);

// --- Value scanner (heap) ----------------------------------------------------
void ValueScan  (const std::string& type, const std::string& value);
void ValueNarrow(const std::string& type, const std::string& value);
void ValueList  ();
void ValueWrite (const std::string& value, const std::string& index);
void ValueReset ();

// --- ARM64 inline patching & code caves --------------------------------------
void AllocCave(const std::string& size);
void Nop      (const std::string& offset, const std::string& count);
void FarJump  (const std::string& offset, const std::string& target);
void Branch   (const std::string& offset, const std::string& target, bool link);
void CaveTest (const std::string& offset);
void FlushTest(const std::string& offset);
void GotHook  (const std::string& gotOffset);

// --- Command hooks & capture -------------------------------------------------
void HookFn (const std::string& offset);
void CmdHook();
void CmdLog ();
void ArgHook(const std::string& offset);
void ArgLog ();
void Capture(const std::string& secs);

// --- Field enumeration & reverse engineering ---------------------------------
//  NOTE: the *scan* based diagnostics (fieldscan/vtscan/fielddump) can freeze
//  the game via Promon - the UI flags them. fields/findfields are the safe path.
void        Fields    ();
void        FindFields();
void        FieldScan ();
void        VtScan    ();
void        Fdump     ();
void        FieldDump ();
void        ObjDump   (const std::string& addr);
void        MgrDiag   ();
void        FindMgr   ();
void        FieldsDiag();
void        DumpSo    (const std::string& outPath);
std::string GetExport (const std::string& name);

} // namespace Engine
