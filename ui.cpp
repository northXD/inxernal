// =============================================================================
//  INXERNAL - user interface  (Dear ImGui 1.92.x / DirectX 11 / Win32)
// -----------------------------------------------------------------------------
//  Two front-ends over one engine: this UI and a quiet console (engine.cpp).
//  The UI only ever calls Engine:: functions, so the console/engine could later
//  be split into its own process without touching this file.
//
//  Two sections (tabs):
//    - Control Panel : the current, one-click operating mode.
//    - Developer     : the low-level functions, one control per loader.py
//                      command, ready to wire up (Engine::Dispatch is the seam).
//  Font: Tahoma (regular + bold). Look: restrained, near-monochrome.
// =============================================================================

#include "engine.h"

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <chrono>

// ------------------------------------------------------------- D3D / Win32 ----
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ------------------------------------------------------------------- fonts ----
static ImFont* g_FontBody = nullptr;   // Tahoma
static ImFont* g_FontBold = nullptr;   // Tahoma Bold

// --------------------------------------------------------------- palette ------
// Greyscale + a single muted accent, used sparingly (wordmark, active tab,
// errors, the running state). Nothing else is coloured.
namespace col {
    const ImVec4 text   = ImVec4(0.84f, 0.84f, 0.86f, 1.00f);
    const ImVec4 dim    = ImVec4(0.48f, 0.49f, 0.53f, 1.00f);
    const ImVec4 faint  = ImVec4(0.33f, 0.34f, 0.38f, 1.00f);
    const ImVec4 accent = ImVec4(0.74f, 0.33f, 0.35f, 1.00f);   // muted crimson
    const ImVec4 warn   = ImVec4(0.72f, 0.60f, 0.44f, 1.00f);   // muted sand
}

// ============================================================================
//  Theme
// ============================================================================
static void ApplyInxernalStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 5.0f;
    s.ChildRounding     = 5.0f;
    s.FrameRounding     = 4.0f;
    s.PopupRounding     = 4.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.FrameBorderSize   = 1.0f;
    s.WindowBorderSize  = 0.0f;
    s.ChildBorderSize   = 1.0f;
    s.WindowPadding     = ImVec2(13, 12);
    s.FramePadding      = ImVec2(8, 5);
    s.ItemSpacing       = ImVec2(8, 7);
    s.ItemInnerSpacing  = ImVec2(6, 5);
    s.ScrollbarSize     = 11.0f;
    s.GrabMinSize       = 10.0f;
    s.TabBarBorderSize  = 0.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                 = col::text;
    c[ImGuiCol_TextDisabled]         = col::faint;
    c[ImGuiCol_WindowBg]             = ImVec4(0.066f, 0.067f, 0.075f, 1.00f);
    c[ImGuiCol_ChildBg]              = ImVec4(0.086f, 0.088f, 0.098f, 1.00f);
    c[ImGuiCol_PopupBg]              = ImVec4(0.086f, 0.088f, 0.098f, 0.98f);
    c[ImGuiCol_Border]               = ImVec4(0.150f, 0.152f, 0.170f, 1.00f);
    c[ImGuiCol_BorderShadow]         = ImVec4(0.000f, 0.000f, 0.000f, 0.00f);
    c[ImGuiCol_FrameBg]              = ImVec4(0.118f, 0.120f, 0.135f, 1.00f);
    c[ImGuiCol_FrameBgHovered]       = ImVec4(0.150f, 0.152f, 0.170f, 1.00f);
    c[ImGuiCol_FrameBgActive]        = ImVec4(0.175f, 0.177f, 0.198f, 1.00f);
    c[ImGuiCol_TitleBg]              = ImVec4(0.066f, 0.067f, 0.075f, 1.00f);
    c[ImGuiCol_TitleBgActive]        = ImVec4(0.086f, 0.088f, 0.098f, 1.00f);
    c[ImGuiCol_MenuBarBg]            = ImVec4(0.086f, 0.088f, 0.098f, 1.00f);
    c[ImGuiCol_ScrollbarBg]          = ImVec4(0.000f, 0.000f, 0.000f, 0.00f);
    c[ImGuiCol_ScrollbarGrab]        = ImVec4(0.190f, 0.192f, 0.212f, 1.00f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.250f, 0.252f, 0.275f, 1.00f);
    c[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.300f, 0.302f, 0.325f, 1.00f);
    c[ImGuiCol_CheckMark]            = col::accent;
    c[ImGuiCol_SliderGrab]           = ImVec4(0.360f, 0.362f, 0.390f, 1.00f);
    c[ImGuiCol_SliderGrabActive]     = col::accent;
    c[ImGuiCol_Button]               = ImVec4(0.145f, 0.147f, 0.165f, 1.00f);
    c[ImGuiCol_ButtonHovered]        = ImVec4(0.185f, 0.187f, 0.208f, 1.00f);
    c[ImGuiCol_ButtonActive]         = ImVec4(0.220f, 0.150f, 0.158f, 1.00f);
    c[ImGuiCol_Header]               = ImVec4(0.128f, 0.130f, 0.146f, 1.00f);
    c[ImGuiCol_HeaderHovered]        = ImVec4(0.162f, 0.164f, 0.183f, 1.00f);
    c[ImGuiCol_HeaderActive]         = ImVec4(0.180f, 0.182f, 0.203f, 1.00f);
    c[ImGuiCol_Separator]            = ImVec4(0.140f, 0.142f, 0.160f, 1.00f);
    c[ImGuiCol_SeparatorHovered]     = ImVec4(0.200f, 0.202f, 0.223f, 1.00f);
    c[ImGuiCol_SeparatorActive]      = col::accent;
    c[ImGuiCol_Tab]                  = ImVec4(0.086f, 0.088f, 0.098f, 1.00f);
    c[ImGuiCol_TabHovered]           = ImVec4(0.150f, 0.152f, 0.170f, 1.00f);
    c[ImGuiCol_TabSelected]          = ImVec4(0.128f, 0.130f, 0.146f, 1.00f);
    c[ImGuiCol_TabSelectedOverline]  = col::accent;
    c[ImGuiCol_TabDimmed]            = ImVec4(0.078f, 0.080f, 0.090f, 1.00f);
    c[ImGuiCol_TabDimmedSelected]    = ImVec4(0.110f, 0.112f, 0.126f, 1.00f);
    c[ImGuiCol_TableHeaderBg]        = ImVec4(0.110f, 0.112f, 0.126f, 1.00f);
    c[ImGuiCol_TableBorderStrong]    = ImVec4(0.170f, 0.172f, 0.190f, 1.00f);
    c[ImGuiCol_TableBorderLight]     = ImVec4(0.130f, 0.132f, 0.148f, 1.00f);
    c[ImGuiCol_TextSelectedBg]       = ImVec4(col::accent.x, col::accent.y, col::accent.z, 0.35f);
    c[ImGuiCol_NavHighlight]         = col::accent;
}

// ============================================================================
//  Small helpers
// ============================================================================
static void PushBold(float size) { ImGui::PushFont(g_FontBold, size); }
static void PushBody(float size) { ImGui::PushFont(g_FontBody, size); }

// Scale a fixed pixel dimension by the monitor DPI so panels don't clip text
// on high-DPI displays (fonts scale via FontScaleDpi; literals must too).
static float S(float v) {
    float d = ImGui::GetStyle().FontScaleDpi;
    return v * (d > 0.0f ? d : 1.0f);
}

// A small filled status dot, vertically centred to the current text line.
static void StatusDot(const ImVec4& color, float radius = 4.0f) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float cy = p.y + ImGui::GetTextLineHeight() * 0.5f;
    ImGui::GetWindowDrawList()->AddCircleFilled(
        ImVec2(p.x + radius + 1.0f, cy), radius, ImGui::GetColorU32(color));
    ImGui::Dummy(ImVec2(radius * 2.0f + 6.0f, ImGui::GetTextLineHeight()));
    ImGui::SameLine();
}

static void HelpMarker(const char* desc) {
    ImGui::SameLine();
    ImGui::TextColored(col::faint, "(?)");
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip))
        ImGui::SetTooltip("%s", desc);
}

// Small caps-ish section label.
static void SectionLabel(const char* text) {
    PushBold(13.0f);
    ImGui::TextColored(col::dim, "%s", text);
    ImGui::PopFont();
}

// label + value, with a subtle on/off dot. Distinguished only by brightness.
static void StatusItem(const char* label, const char* value, bool on) {
    StatusDot(on ? col::accent : col::faint, 3.5f);
    ImGui::TextColored(col::dim, "%s", label);
    ImGui::SameLine(0, 5);
    ImGui::TextColored(on ? col::text : col::dim, "%s", value);
}

// A fixed-width text field.
static bool Field(const char* id, const char* hint, char* buf, size_t sz, float w) {
    ImGui::SetNextItemWidth(w);
    return ImGui::InputTextWithHint(id, hint, buf, sz);
}

static std::string Str(const char* buf) { return std::string(buf); }

// Right-align a block of width `blockWidth` on the current line (clamped).
static void SameLineRightAlign(float blockWidth) {
    ImGui::SameLine();
    float avail = ImGui::GetContentRegionAvail().x;
    float gap = avail - blockWidth;
    ImGui::SameLine(0, gap > 6.0f ? gap : 6.0f);
}

// Flat run button used across developer rows.
static bool RunBtn(const char* id) { return ImGui::Button(id, ImVec2(92, 0)); }

// ============================================================================
//  Header bar
// ============================================================================
static void RenderHeaderBar() {
    const Engine::State& st = Engine::state();

    // Natural-height row (no fixed child) so it never clips at any DPI.
    PushBold(20.0f);
    ImGui::TextColored(col::accent, "INXERNAL");
    ImGui::PopFont();
    ImGui::SameLine(0, 9);
    ImGui::TextColored(col::faint, "by North");

    // Compact status, right aligned.
    ImGui::SameLine();
    float avail = ImGui::GetContentRegionAvail().x;
    const float block = S(520.0f);
    if (avail > block) ImGui::SameLine(0, avail - block);
    ImGui::BeginGroup();
    StatusItem("Bot", st.running ? "running" : "idle", st.running);
    ImGui::SameLine(0, 22);
    StatusItem("Device", st.deviceOnline ? st.deviceId.c_str() : "-", st.deviceOnline);
    ImGui::SameLine(0, 22);
    StatusItem("Engine", st.engineAttached ? "attached" : "detached", st.engineAttached);
    ImGui::SameLine(0, 22);
    StatusItem("libg", st.libgBase.c_str(), st.engineAttached);
    ImGui::EndGroup();
    ImGui::Separator();
}

// ============================================================================
//  Control Panel  (current mode)
// ============================================================================
static void ActionCard(const char* title, const char* subtitle,
                       const char* button, void(*onClick)()) {
    float h = S(116.0f);
    ImGui::BeginChild(title, ImVec2(S(226.0f), h), ImGuiChildFlags_Borders);
    PushBold(15.0f);
    ImGui::TextColored(col::text, "%s", title);
    ImGui::PopFont();
    ImGui::PushStyleColor(ImGuiCol_Text, col::dim);
    ImGui::TextWrapped("%s", subtitle);
    ImGui::PopStyleColor();
    ImGui::SetCursorPosY(h - S(38.0f));
    if (ImGui::Button(button, ImVec2(-1, S(28.0f))) && onClick) onClick();
    ImGui::EndChild();
}

static void RenderControlPanel() {
    ImGui::BeginChild("##cp_scroll", ImVec2(0, 0), ImGuiChildFlags_None);
    Engine::State& st = Engine::state();

    // --- Master start/stop -------------------------------------------------
    ImGui::BeginChild("##master", ImVec2(0, S(108.0f)), ImGuiChildFlags_Borders);
    SectionLabel("BOT CONTROL");
    ImGui::Spacing();
    StatusDot(st.running ? col::accent : col::faint, 5.0f);
    ImGui::TextColored(st.running ? col::text : col::dim,
                       st.running ? "Running" : "Idle");
    SameLineRightAlign(200.0f);
    if (st.running) {
        ImGui::PushStyleColor(ImGuiCol_Button,        col::accent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.38f, 0.40f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.96f, 0.94f, 0.94f, 1.0f));
        PushBold(15.0f);
        if (ImGui::Button("Stop Bot", ImVec2(200, 42))) Engine::ToggleBot();
        ImGui::PopFont();
        ImGui::PopStyleColor(3);
    } else {
        PushBold(15.0f);
        if (ImGui::Button("Start Bot", ImVec2(200, 42))) Engine::ToggleBot();
        ImGui::PopFont();
    }
    ImGui::EndChild();

    ImGui::Spacing();

    // --- Last loader response (control-channel reply) ----------------------
    ImGui::PushStyleColor(ImGuiCol_Text, col::dim);
    ImGui::TextWrapped("loader:  %s", st.lastResponse.c_str());
    ImGui::PopStyleColor();

    ImGui::Spacing();

    // --- Auto-farm loop ----------------------------------------------------
    ImGui::BeginChild("##farm", ImVec2(0, S(104.0f)), ImGuiChildFlags_Borders);
    SectionLabel("AUTO-FARM");
    HelpMarker("harvest all -> plant all -> wait -> repeat.\nSelf-syncs from any starting state.");
    ImGui::Spacing();
    ImGui::SetNextItemWidth(110);
    ImGui::InputInt("wait (s)", &st.farmWaitSeconds);
    if (st.farmWaitSeconds < 5) st.farmWaitSeconds = 5;
    ImGui::SameLine(0, 22);
    ImGui::SetNextItemWidth(130);
    ImGui::InputInt("crop id", &st.farmCropId);
    ImGui::SameLine(0, 22);
    if (!st.farmLoop) {
        if (ImGui::Button("Engage", ImVec2(110, 28))) Engine::FarmStart();
    } else {
        if (ImGui::Button("Disengage", ImVec2(110, 28))) Engine::FarmStop();
        ImGui::SameLine();
        StatusDot(col::accent);
        ImGui::TextColored(col::dim, "looping");
    }
    ImGui::EndChild();

    ImGui::Spacing();
    SectionLabel("QUICK ACTIONS");
    ImGui::Spacing();

    ActionCard("Plant All", "Plant every field with the current crop. Reads live field ids.",
               "Plant", Engine::PlantAll);
    ImGui::SameLine();
    ActionCard("Harvest All", "Harvest every ready field. Safe no-op on empty fields.",
               "Harvest", Engine::HarvestAll);
    ImGui::SameLine();
    ActionCard("Market", "Open the roadside shop, then list a crate in Developer > Roadside Shop.",
               "Open", Engine::OpenMarket);
    ImGui::SameLine();
    ActionCard("Field IDs", "Read the current field ids live (they grow every cycle).",
               "Read", Engine::GetFieldIDs);

    ImGui::Spacing();

    // --- Field id readout --------------------------------------------------
    ImGui::BeginChild("##fields", ImVec2(0, S(90.0f)), ImGuiChildFlags_Borders);
    SectionLabel("FIELD IDS");
    ImGui::SameLine(0, 14);
    if (ImGui::SmallButton("Refresh"))  Engine::GetFieldIDs();
    ImGui::SameLine();
    if (ImGui::SmallButton("Test ADB")) Engine::TestADB();      // -> adb device check
    ImGui::SameLine();
    if (ImGui::SmallButton("Status"))   Engine::RefreshInfo();  // -> status
    ImGui::Spacing();
    if (st.currentFields.empty()) {
        ImGui::TextColored(col::dim, "none yet - press Read");
    } else {
        std::string ids;
        for (size_t i = 0; i < st.currentFields.size(); ++i) {
            ids += std::to_string(st.currentFields[i]);
            if (i + 1 < st.currentFields.size()) ids += ", ";
        }
        ImGui::TextWrapped("%s", ids.c_str());
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

// ============================================================================
//  Developer Mode
// ============================================================================
static void RenderDeveloperMode() {
    ImGui::BeginChild("##dev_scroll", ImVec2(0, 0), ImGuiChildFlags_None);

    ImGui::PushStyleColor(ImGuiCol_Text, col::dim);
    ImGui::TextWrapped("Each control maps to one loader.py command and routes through "
                       "Engine::Dispatch() - wire that up to go live.");
    ImGui::PopStyleColor();
    ImGui::Spacing();

    static const char* kReadTypes  = "int\0float\0double\0long\0ptr\0str\0bytes\0";
    static const char* kWriteTypes = "int\0float\0double\0long\0bytes\0";
    static const char* kValTypes   = "int\0float\0double\0short\0long\0";
    static const char* kReadNames[]  = {"int","float","double","long","ptr","str","bytes"};
    static const char* kWriteNames[] = {"int","float","double","long","bytes"};
    static const char* kValNames[]   = {"int","float","double","short","long"};

    // --- Memory ------------------------------------------------------------
    if (ImGui::CollapsingHeader("Memory  (libg.so offsets)", ImGuiTreeNodeFlags_DefaultOpen)) {
        static int  rType = 0;
        static char rOff[64] = "", rLen[16] = "256";
        ImGui::SetNextItemWidth(105); ImGui::Combo("##rtype", &rType, kReadTypes);
        ImGui::SameLine(); Field("##roff", "offset (0x..)", rOff, sizeof(rOff), 150);
        ImGui::SameLine(); Field("##rlen", "len", rLen, sizeof(rLen), 66);
        ImGui::SameLine(); if (RunBtn("read")) Engine::ReadMem(kReadNames[rType], Str(rOff), Str(rLen));

        static int  wType = 0;
        static char wOff[64] = "", wVal[64] = "";
        ImGui::SetNextItemWidth(105); ImGui::Combo("##wtype", &wType, kWriteTypes);
        ImGui::SameLine(); Field("##woff", "offset (0x..)", wOff, sizeof(wOff), 150);
        ImGui::SameLine(); Field("##wval", "value", wVal, sizeof(wVal), 150);
        ImGui::SameLine(); if (RunBtn("write")) Engine::WriteMem(kWriteNames[wType], Str(wOff), Str(wVal));

        static char dOff[64] = "", dLen[16] = "64";
        Field("##doff", "offset (0x..)", dOff, sizeof(dOff), 150);
        ImGui::SameLine(); Field("##dlen", "length", dLen, sizeof(dLen), 86);
        ImGui::SameLine(); if (RunBtn("dump")) Engine::DumpMem(Str(dOff), Str(dLen));

        static char sPat[128] = "";
        Field("##spat", "AOB pattern  e.g.  1F 20 03 D5", sPat, sizeof(sPat), 258);
        ImGui::SameLine(); if (RunBtn("scan##aob")) Engine::PatternScan(Str(sPat));
        ImGui::SameLine(); ImGui::TextColored(col::dim, "file-backed libg.so scan");

        static char raAddr[64] = "", raLen[16] = "16";
        Field("##raaddr", "abs addr (0x..)", raAddr, sizeof(raAddr), 168);
        ImGui::SameLine(); Field("##ralen", "len", raLen, sizeof(raLen), 66);
        ImGui::SameLine(); if (RunBtn("rabs")) Engine::ReadAbs(Str(raAddr), Str(raLen));

        static char waAddr[64] = "", waHex[128] = "";
        Field("##waaddr", "abs addr (0x..)", waAddr, sizeof(waAddr), 168);
        ImGui::SameLine(); Field("##wahex", "hex bytes", waHex, sizeof(waHex), 218);
        ImGui::SameLine(); if (RunBtn("wabs")) Engine::WriteAbs(Str(waAddr), Str(waHex));
    }

    // --- Value scanner -----------------------------------------------------
    if (ImGui::CollapsingHeader("Value Scanner  (heap)")) {
        const Engine::State& st = Engine::state();
        static int  vType = 0;
        static char vVal[64] = "";
        ImGui::SetNextItemWidth(105); ImGui::Combo("##vtype", &vType, kValTypes);
        ImGui::SameLine(); Field("##vval", "value", vVal, sizeof(vVal), 150);
        ImGui::SameLine(); if (RunBtn("scan"))       Engine::ValueScan(kValNames[vType], Str(vVal));
        ImGui::SameLine(); if (RunBtn("narrow"))     Engine::ValueNarrow(kValNames[vType], Str(vVal));
        HelpMarker("scan writable heap for a value, then narrow repeatedly as it changes.");

        static char vwVal[64] = "", vwIdx[16] = "";
        Field("##vwval", "new value", vwVal, sizeof(vwVal), 150);
        ImGui::SameLine(); Field("##vwidx", "index (opt)", vwIdx, sizeof(vwIdx), 86);
        ImGui::SameLine(); if (RunBtn("write##val")) Engine::ValueWrite(Str(vwVal), Str(vwIdx));
        ImGui::SameLine(); if (ImGui::Button("list", ImVec2(66,0)))  Engine::ValueList();
        ImGui::SameLine(); if (ImGui::Button("reset", ImVec2(66,0))) Engine::ValueReset();

        if (st.scanMatches >= 0) {
            ImGui::TextColored(col::dim, "last scan:");
            ImGui::SameLine();
            ImGui::TextColored(col::text, "%d matches", st.scanMatches);
        }
    }

    // --- ARM64 patching & caves -------------------------------------------
    if (ImGui::CollapsingHeader("ARM64 Patching & Code Caves")) {
        static char cSize[16] = "256";
        Field("##csize", "cave size", cSize, sizeof(cSize), 105);
        ImGui::SameLine(); if (RunBtn("cave")) Engine::AllocCave(Str(cSize));
        ImGui::SameLine(); ImGui::TextColored(col::dim, "allocate rwx guest memory for shellcode");

        static char nOff[64] = "", nCnt[16] = "4";
        Field("##noff", "offset (0x..)", nOff, sizeof(nOff), 150);
        ImGui::SameLine(); Field("##ncnt", "byte count", nCnt, sizeof(nCnt), 86);
        ImGui::SameLine(); if (RunBtn("nop")) Engine::Nop(Str(nOff), Str(nCnt));

        static char fjOff[64] = "", fjTgt[64] = "";
        Field("##fjoff", "offset (0x..)", fjOff, sizeof(fjOff), 150);
        ImGui::SameLine(); Field("##fjtgt", "abs target (0x..)", fjTgt, sizeof(fjTgt), 168);
        ImGui::SameLine(); if (RunBtn("farjump")) Engine::FarJump(Str(fjOff), Str(fjTgt));
        HelpMarker("16-byte position-independent far branch (any distance).");

        static char brOff[64] = "", brTgt[64] = ""; static bool brLink = false;
        Field("##broff", "offset (0x..)", brOff, sizeof(brOff), 150);
        ImGui::SameLine(); Field("##brtgt", "abs target (0x..)", brTgt, sizeof(brTgt), 168);
        ImGui::SameLine(); ImGui::Checkbox("BL", &brLink);
        ImGui::SameLine(); if (RunBtn("branch")) Engine::Branch(Str(brOff), Str(brTgt), brLink);
        HelpMarker("encode a B / BL (+-128MB range).");

        static char ctOff[64] = "", ftOff[64] = "", ghOff[64] = "";
        Field("##ctoff", "offset (opt)", ctOff, sizeof(ctOff), 150);
        ImGui::SameLine(); if (RunBtn("cavetest"))  Engine::CaveTest(Str(ctOff));
        ImGui::SameLine(); Field("##ftoff", "offset (opt)", ftOff, sizeof(ftOff), 150);
        ImGui::SameLine(); if (RunBtn("flushtest")) Engine::FlushTest(Str(ftOff));
        Field("##ghoff", "GOT offset (opt)", ghOff, sizeof(ghOff), 150);
        ImGui::SameLine(); if (RunBtn("gothook")) Engine::GotHook(Str(ghOff));
        HelpMarker("data/GOT hooks survive Promon and need no cache flush.");
    }

    // --- Command hooks & capture ------------------------------------------
    if (ImGui::CollapsingHeader("Command Hooks & Capture")) {
        static char hOff[64] = "";
        Field("##hoff", "offset (0x..)", hOff, sizeof(hOff), 150);
        ImGui::SameLine(); if (RunBtn("hook")) Engine::HookFn(Str(hOff));
        ImGui::SameLine(); if (ImGui::Button("cmdhook", ImVec2(86,0))) Engine::CmdHook();
        ImGui::SameLine(); if (ImGui::Button("cmdlog", ImVec2(76,0)))  Engine::CmdLog();

        static char aOff[64] = "";
        Field("##aoff", "arg hook offset", aOff, sizeof(aOff), 150);
        ImGui::SameLine(); if (RunBtn("arghook")) Engine::ArgHook(Str(aOff));
        ImGui::SameLine(); if (ImGui::Button("arglog", ImVec2(76,0))) Engine::ArgLog();

        static char capSecs[16] = "5";
        Field("##capsecs", "seconds", capSecs, sizeof(capSecs), 86);
        ImGui::SameLine(); if (RunBtn("capture")) Engine::Capture(Str(capSecs));
    }

    // --- Roadside shop (sell) ---------------------------------------------
    if (ImGui::CollapsingHeader("Roadside Shop  (Sell)")) {
        static char sSlot[16] = "0", sCnt[16] = "10", sPrice[16] = "1", sItem[16] = "400001";
        static bool sAd = false;
        Field("##sslot",  "slot",    sSlot,  sizeof(sSlot),  66);
        ImGui::SameLine(); Field("##scnt",   "count",   sCnt,   sizeof(sCnt),   78);
        ImGui::SameLine(); Field("##sprice", "price",   sPrice, sizeof(sPrice), 78);
        ImGui::SameLine(); Field("##sitem",  "item id", sItem,  sizeof(sItem),  96);
        ImGui::SameLine(); ImGui::Checkbox("advertise", &sAd);
        ImGui::SameLine(); if (RunBtn("sell")) Engine::Sell(Str(sSlot), Str(sCnt), Str(sPrice), sAd, Str(sItem));
        ImGui::TextColored(col::dim, "open the roadside shop first; slot = crate index (0-based)");
    }

    // --- Field enumeration & RE -------------------------------------------
    if (ImGui::CollapsingHeader("Field Enumeration & Reverse Engineering")) {
        if (ImGui::Button("fields", ImVec2(92,0)))      Engine::Fields();
        ImGui::SameLine(); if (ImGui::Button("findfields", ImVec2(92,0))) Engine::FindFields();
        ImGui::SameLine(); if (ImGui::Button("findmgr", ImVec2(92,0)))    Engine::FindMgr();
        ImGui::SameLine(); if (ImGui::Button("mgrdiag", ImVec2(92,0)))    Engine::MgrDiag();
        ImGui::SameLine(); if (ImGui::Button("fdump", ImVec2(92,0)))      Engine::Fdump();
        ImGui::SameLine(); if (ImGui::Button("fieldsdiag", ImVec2(92,0))) Engine::FieldsDiag();

        static char odAddr[64] = "";
        Field("##odaddr", "obj addr (0x..)", odAddr, sizeof(odAddr), 150);
        ImGui::SameLine(); if (RunBtn("objdump")) Engine::ObjDump(Str(odAddr));

        static char soPath[128] = "";
        Field("##sopath", "out path (opt)", soPath, sizeof(soPath), 218);
        ImGui::SameLine(); if (RunBtn("dumpso")) Engine::DumpSo(Str(soPath));

        static char exName[64] = "";
        Field("##exname", "export name", exName, sizeof(exName), 150);
        ImGui::SameLine(); if (RunBtn("export")) Engine::GetExport(Str(exName));

        ImGui::Spacing();
        ImGui::TextColored(col::warn, "freeze risk - full scans, dev only");
        if (ImGui::Button("fieldscan", ImVec2(104,0)))  Engine::FieldScan();
        ImGui::SameLine(); if (ImGui::Button("vtscan", ImVec2(104,0)))    Engine::VtScan();
        ImGui::SameLine(); if (ImGui::Button("fielddump", ImVec2(104,0))) Engine::FieldDump();
    }

    // --- Raw console -------------------------------------------------------
    if (ImGui::CollapsingHeader("Raw Console", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char rawCmd[256] = "";
        ImGui::TextColored(col::dim, "nxrth>");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-108);
        bool submit = ImGui::InputTextWithHint("##rawcmd", "type a command, e.g.  plant all",
                                               rawCmd, sizeof(rawCmd),
                                               ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if ((RunBtn("send") || submit) && rawCmd[0] != '\0') {
            Engine::Dispatch(Str(rawCmd));
            rawCmd[0] = '\0';
        }
    }

    ImGui::EndChild();
}

// ============================================================================
//  Status bar  (minimal footer - the real log lives in the OS console)
// ============================================================================
static void RenderStatusBar() {
    ImGui::TextColored(col::dim, "INXERNAL");
    ImGui::SameLine(0, 10);
    ImGui::TextColored(col::faint, "by North");
}

// ============================================================================
//  Main
// ============================================================================
int main(int, char**) {
    Engine::ConsoleStart();   // start the quiet console/log first

    ImGui_ImplWin32_EnableDpiAwareness();
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(
        ::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                       GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                       L"MAcrooo", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Vague", WS_OVERLAPPEDWINDOW,
                                100, 100, (int)(1160 * main_scale), (int)(800 * main_scale),
                                nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        Engine::LogErr("D3D11 device creation failed");
        Engine::ConsoleStop();
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ApplyInxernalStyle();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(main_scale);
    style.FontScaleDpi = main_scale;

    // --- Fonts: Tahoma (regular + bold) -----------------------------------
    ImFontConfig cfg; cfg.OversampleH = 2; cfg.OversampleV = 1;
    g_FontBody = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\tahoma.ttf",  16.0f, &cfg);
    g_FontBold = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\tahomabd.ttf", 16.0f, &cfg);
    if (g_FontBody == nullptr) {
        g_FontBody = io.Fonts->AddFontDefault();
        Engine::LogWarn("Tahoma not found - using the default font");
    }
    if (g_FontBold == nullptr) g_FontBold = g_FontBody;
    io.FontDefault = g_FontBody;
    style.FontSizeBase = 16.0f;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = ImVec4(0.045f, 0.045f, 0.052f, 1.00f);

    bool done = false;
    using rclock = std::chrono::steady_clock;
    const double kFrameMs = 1000.0 / 30.0;   // cap at 30 fps - light on CPU/GPU
    while (!done) {
        auto frameStart = rclock::now();
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                                 ImGuiWindowFlags_NoBringToFrontOnFocus;
        ImGui::Begin("INXERNAL", nullptr, flags);

        RenderHeaderBar();
        ImGui::Spacing();

        float footer = ImGui::GetFrameHeightWithSpacing();
        float bodyHeight = ImGui::GetContentRegionAvail().y - footer - style.ItemSpacing.y;
        if (bodyHeight < S(150.0f)) bodyHeight = S(150.0f);

        ImGui::BeginChild("##body", ImVec2(0, bodyHeight), ImGuiChildFlags_None);
        if (ImGui::BeginTabBar("##modes", ImGuiTabBarFlags_None)) {
            if (ImGui::BeginTabItem("  Control Panel  ")) {
                ImGui::Spacing();
                RenderControlPanel();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("  Developer  ")) {
                ImGui::Spacing();
                RenderDeveloperMode();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::EndChild();

        ImGui::Spacing();
        RenderStatusBar();

        ImGui::End();

        ImGui::Render();
        const float cc[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w,
                              clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_pSwapChain->Present(0, 0);   // no vsync; the limiter sets the rate
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        double frameMs = std::chrono::duration<double, std::milli>(rclock::now() - frameStart).count();
        if (frameMs < kFrameMs) ::Sleep(static_cast<DWORD>(kFrameMs - frameMs));
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    Engine::ConsoleStop();
    return 0;
}

// ============================================================================
//  D3D helpers
// ============================================================================
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
