// =============================================================================
//  xways-updater — X-Tension installer/updater for X-Ways Forensics.
//
//  Inspired by Eric Zimmerman's XWFIM, adapted as an X-Tension so it lives
//  inside an existing X-Ways install. Reads the user's X-Ways license
//  credentials, downloads the requested version of the main app (Dongle or
//  BYOD), extracts it to a sibling folder named after the detected version
//  (e.g. xwf21-7sr3), and optionally pulls Viewer / Tesseract / Excire / a
//  Conditional Coloring config, copies *.cfg files and HashDB folders from
//  the current install, and creates a desktop shortcut (with optional admin
//  elevation flag).
//
//  Auth scheme: HTTP Basic on every download URL. Realm is
//  "Latest password from x-ways.net/license.html". Credentials stored next
//  to the DLL in xways-updater.cfg, DPAPI-encrypted (per Windows user).
//
//  Important file-name detail (v0.1):
//    - Dongle main exe inside xw_forensics.zip:  xwforensics64.exe
//    - BYOD   main exe inside xwb.zip:           xwb64.exe
//    Folder-name auto-detection reads VERSIONINFO from whichever of those
//    two is present after extraction.
// =============================================================================

#define NOMINMAX
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <objbase.h>
#include <objidl.h>
#include <knownfolders.h>
#include <process.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cwctype>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include "resource.h"

// --- Identity ---------------------------------------------------------------
static const wchar_t* NAME        = L"xways-updater";
static const wchar_t* VERSION     = L"0.1.2";
static const wchar_t* DESCRIPTION = L"Download and install X-Ways Forensics (Dongle or BYOD) plus optional resources.";

// Verbose per-file/per-step diagnostics. Off by default for shipped builds —
// flip to true locally if you're debugging copy/extract behavior.
static constexpr bool VERBOSE = false;

// --- Constants --------------------------------------------------------------
//   Auth host shared by everything except the BYOD app, which sits on the
//   .com domain. Realm + Basic auth confirmed by HEAD probe (2026-05-06).
//   Both .net and .com accept the same dongle creds for resources.
static const wchar_t* HOST_DONGLE   = L"www.x-ways.net";
static const wchar_t* HOST_BYOD     = L"www.x-ways.com";

static const wchar_t* PATH_DONGLE_INDEX   = L"/xwf/";
static const wchar_t* PATH_DONGLE_CURRENT = L"/xwf/xw_forensics.zip";
static const wchar_t* PATH_BYOD_INDEX     = L"/xwb/";
static const wchar_t* PATH_BYOD_CURRENT   = L"/xwb/xwb.zip";

static const wchar_t* URL_VIEWER          = L"https://www.x-ways.net/res/viewer/xw_viewer.zip";
static const wchar_t* URL_TESSERACT       = L"https://www.x-ways.net/res/Tesseract.zip";
static const wchar_t* URL_EXCIRE          = L"https://www.x-ways.net/res/Excire.zip";
//   AFF4 X-Tension — keep pinned to a known-good version. Bump when a newer
//   release shows up at https://www.x-ways.net/res/ (manual operation).
static const wchar_t* URL_AFF4            = L"https://www.x-ways.net/res/aff4-xways-2.1.1.zip";
//   Conditional Coloring lives behind a directory listing — file name has a
//   space, so the URL is percent-encoded.
static const wchar_t* URL_COND_COLORING   = L"https://www.x-ways.net/res/conditional%20coloring/Conditional%20Coloring.cfg";

static const wchar_t* USER_AGENT          = L"xways-updater/0.1.2 (X-Tension)";

// --- XT_Prepare nOpType ----------------------------------------------------
enum : DWORD {
    XT_ACTION_RUN = 0,
    XT_ACTION_RVS = 1,
    XT_ACTION_LSS = 2,
    XT_ACTION_PSS = 3,
    XT_ACTION_DBC = 4,
    XT_ACTION_SHC = 5,
};

// --- Function pointer typedefs (only what we need) -------------------------
typedef VOID (__stdcall *pfn_XWF_OutputMessage)(const wchar_t*, DWORD);

static pfn_XWF_OutputMessage XWF_OutputMessage = nullptr;

// HMODULE for our own DLL (captured in DllMain). Used to resolve the sidecar
// cfg path. The X-Ways main module (GetModuleHandleW(NULL)) gives us the
// running install's location.
static HMODULE g_hSelf    = nullptr;
static HWND    g_hMainWnd = nullptr;

// --- Progress reporting -----------------------------------------------------
// The settings dialog now hosts the install worker (instead of dismissing on
// OK and showing a separate progress UI). The worker thread updates this
// struct as bytes arrive and posts WM_APP_PROGRESS / WM_APP_STATUS / WM_APP_DONE
// to the dialog HWND. Bytes-done is split into a "before this file" baseline
// plus the current file's running count so the bar moves smoothly across the
// whole batch (main app + N optionals).
struct ProgressState {
    HWND     hDlg              = nullptr;  // dialog to PostMessage to
    uint64_t totalExpected     = 0;        // sum of all HEAD content-lengths
    uint64_t cumulativeBefore  = 0;        // bytes finalised before current file
    bool     active            = false;
};
static ProgressState g_progress;

static void ProgressSetStatus(const std::wstring& s) {
    if (!g_progress.hDlg) return;
    // Heap-allocate so PostMessage (async) can hand ownership to the dialog.
    wchar_t* buf = new wchar_t[s.size() + 1];
    memcpy(buf, s.c_str(), (s.size() + 1) * sizeof(wchar_t));
    PostMessageW(g_progress.hDlg, WM_APP + 2 /*WM_APP_STATUS*/, 0, (LPARAM)buf);
}
static void ProgressPostPercent(uint64_t bytesOverall) {
    if (!g_progress.hDlg) return;
    int permille = 0;
    if (g_progress.totalExpected > 0) {
        if (bytesOverall >= g_progress.totalExpected) permille = 1000;
        else permille = (int)((bytesOverall * 1000) / g_progress.totalExpected);
    }
    PostMessageW(g_progress.hDlg, WM_APP + 1 /*WM_APP_PROGRESS*/, (WPARAM)permille, 0);
}
static void ProgressBegin(uint64_t total) {
    g_progress.totalExpected    = total;
    g_progress.cumulativeBefore = 0;
    g_progress.active           = true;
    ProgressPostPercent(0);
}
static void ProgressEnd() {
    g_progress.active = false;
}
// RAII guard so we always disarm the progress callback on every return path
// out of RunInstall / RunExtrasOnly (early failures otherwise leave the bar
// updating against a stale dialog handle on retry).
struct ProgressGuard {
    bool armed;
    ProgressGuard() : armed(false) {}
    void arm(uint64_t total) { ProgressBegin(total); armed = true; }
    ~ProgressGuard() { if (armed) ProgressEnd(); }
};
// Switch the dialog progress bar to/from marquee (indeterminate) mode.
// Used for the long post-download tail (extract / copy / shortcut / MOTW)
// where bytes-based progress stops advancing and the bar would otherwise
// look frozen. Marquee = bar pulses left-to-right while we keep working.
static void ProgressBeginMarquee(const std::wstring& status) {
    if (!g_progress.hDlg) return;
    if (!status.empty()) ProgressSetStatus(status);
    PostMessageW(g_progress.hDlg, WM_APP + 4 /*WM_APP_MARQUEE*/, 1, 0);
}
static void ProgressEndMarquee() {
    if (!g_progress.hDlg) return;
    PostMessageW(g_progress.hDlg, WM_APP + 4 /*WM_APP_MARQUEE*/, 0, 0);
}
// Call after a successful download to advance the "completed" baseline by
// the actual on-disk size of the file just written. Subsequent file
// progress will then add to that running total.
static void ProgressFileDone(const std::wstring& path) {
    if (!g_progress.active) return;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    CloseHandle(h);
    g_progress.cumulativeBefore += (uint64_t)sz.QuadPart;
    ProgressPostPercent(g_progress.cumulativeBefore);
}

// --- Logging ----------------------------------------------------------------
// Both Log and LogVerbose emit to the X-Ways Messages window via flag 0.
// We deliberately do NOT use the "send to Output window" flag (0x08) — it
// pops a second window the user has to dismiss; the Messages window is
// enough.
static void Log(const std::wstring& m) {
    std::wstring s = L"["; s += NAME; s += L"] "; s += m;
    if (XWF_OutputMessage) XWF_OutputMessage(s.c_str(), 0);
}
static void LogVerbose(const std::wstring& m) {
    if (!VERBOSE) return;
    std::wstring s = L"["; s += NAME; s += L"] "; s += m;
    if (XWF_OutputMessage) XWF_OutputMessage(s.c_str(), 0);
}

template <typename T>
static T Resolve(HMODULE h, const char* name, int& missing) {
    T p = reinterpret_cast<T>(GetProcAddress(h, name));
    if (!p) ++missing;
    return p;
}
static int RetrieveFunctionPointers() {
    HMODULE h = GetModuleHandleW(nullptr);
    int n = 0;
    XWF_OutputMessage = Resolve<pfn_XWF_OutputMessage>(h, "XWF_OutputMessage", n);
    return n;
}

// --- Path / string helpers --------------------------------------------------
static std::wstring GetSelfDirectory() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(g_hSelf, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    return path;
}
static std::wstring GetXWaysInstallDir() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(GetModuleHandleW(nullptr), path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    return path;
}
static std::wstring GetParent(const std::wstring& dir) {
    size_t pos = dir.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return dir;
    return dir.substr(0, pos);
}
// Default first-run install base, per license type:
//   Dongle -> "<systemdrive>\xwf"   (typically C:\xwf)
//   BYOD   -> "<systemdrive>\xwfb"  (typically C:\xwfb)
// The dongle default matches Eric Zimmerman's XWFIM convention so analysts
// who already have an XWFIM-style layout get drop-in compatibility; the BYOD
// suffix keeps the two product variants from co-mingling. Once the user
// picks a different value in the dialog, that choice persists in cfg and
// overrides this default on subsequent runs.
static std::wstring GetDefaultInstallBase(bool isByod) {
    const wchar_t* leaf = isByod ? L"xwfb" : L"xwf";
    wchar_t winDir[MAX_PATH] = {0};
    UINT n = GetSystemWindowsDirectoryW(winDir, MAX_PATH);
    if (n >= 3 && winDir[1] == L':') {
        std::wstring base;
        base.append(winDir, 3);   // "C:\" / "D:\" / etc.
        base += leaf;
        return base;
    }
    return std::wstring(L"C:\\") + leaf;
}
static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static bool DirExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
static std::wstring TrimW(const std::wstring& s) {
    size_t lo = 0, hi = s.size();
    while (lo < hi && iswspace(s[lo])) ++lo;
    while (hi > lo && iswspace(s[hi - 1])) --hi;
    return s.substr(lo, hi - lo);
}
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
// Percent-decode a URL-style string (e.g. "Conditional%20Coloring.cfg" ->
// "Conditional Coloring.cfg"). Decoded byte stream is treated as UTF-8 so
// non-ASCII filenames survive a round trip.
static std::wstring UrlDecode(const std::wstring& s);
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
static std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}
static std::wstring UrlDecode(const std::wstring& s) {
    std::string bytes;
    bytes.reserve(s.size());
    auto hexv = [](wchar_t c)->int {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
        if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
        return -1;
    };
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == L'%' && i + 2 < s.size()) {
            int hi = hexv(s[i+1]);
            int lo = hexv(s[i+2]);
            if (hi >= 0 && lo >= 0) {
                bytes.push_back(static_cast<char>((hi << 4) | lo));
                i += 3;
                continue;
            }
        }
        // Non-encoded char: pass it through. ASCII goes verbatim; anything
        // above 0x7F gets re-encoded as UTF-8 so the byte buffer we hand to
        // Utf8ToWide is well-formed.
        if (s[i] < 0x80) {
            bytes.push_back(static_cast<char>(s[i]));
        } else {
            bytes.append(WideToUtf8(std::wstring(1, s[i])));
        }
        ++i;
    }
    return Utf8ToWide(bytes);
}

// Validate user-supplied folder name. Allowed: letters, digits, '.', '_',
// '-', ' '. Rejected: anything that looks like a path or could escape the
// install base (slashes, drive letters, ".", ".."), plus any character that
// could break our tar.exe command-line construction (quotes, control chars,
// shell metas). Returns empty string if the name is unsafe.
static std::wstring SanitizeFolderName(const std::wstring& raw) {
    std::wstring s = TrimW(raw);
    if (s.empty()) return L"";          // empty is OK — caller falls back to auto-name
    if (s == L"." || s == L"..")        return L"";
    if (s.size() > 200)                 return L"";  // sanity cap on length
    for (wchar_t c : s) {
        if (c < 0x20)                  return L"";   // control chars
        if (c == L'/' || c == L'\\')   return L"";   // path separators
        if (c == L':')                 return L"";   // drive-letter / ADS
        if (c == L'"' || c == L'\'')   return L"";   // quote chars (cmdline safety)
        if (c == L'<' || c == L'>')    return L"";
        if (c == L'|' || c == L'?'  || c == L'*') return L"";
        if (c == 0x7F)                 return L"";
    }
    return s;
}

// If <base>\<filename> doesn't exist, return that path as-is. Otherwise
// insert "-2", "-3", ... before the extension and return the first variant
// that doesn't exist. Returns empty string if 99 variants all already exist.
// Used for the app-only and tools-only modes where we drop files directly
// into the base folder rather than creating a per-install subfolder.
static std::wstring UniqueFilePath(const std::wstring& base, const std::wstring& filename) {
    std::wstring full = JoinPath(base, filename);
    if (!FileExists(full)) return full;

    size_t dotPos = filename.find_last_of(L'.');
    std::wstring stem = (dotPos != std::wstring::npos) ? filename.substr(0, dotPos) : filename;
    std::wstring ext  = (dotPos != std::wstring::npos) ? filename.substr(dotPos)    : std::wstring();
    for (int i = 2; i < 100; ++i) {
        wchar_t suffix[16];
        swprintf_s(suffix, L"-%d", i);
        std::wstring candidate = JoinPath(base, stem + suffix + ext);
        if (!FileExists(candidate)) return candidate;
    }
    return L"";
}

// Verify that `dest` resolves to a path that's strictly inside `base`.
// Defends against ".."-style escapes that our SanitizeFolderName already
// blocks, but keeps a second check for cases where `base` itself contains
// junctions/symlinks that could redirect the canonical path. Both args
// should be absolute. Returns true if dest is under base.
static bool DestinationIsUnderBase(const std::wstring& base, const std::wstring& dest) {
    auto canon = [](const std::wstring& p) -> std::wstring {
        wchar_t buf[MAX_PATH * 4] = {0};
        DWORD n = GetFullPathNameW(p.c_str(), _countof(buf), buf, nullptr);
        if (n == 0 || n >= _countof(buf)) return p;
        std::wstring out = buf;
        // Strip trailing separator (besides drive root) for comparison.
        if (out.size() > 3 && (out.back() == L'\\' || out.back() == L'/')) out.pop_back();
        std::transform(out.begin(), out.end(), out.begin(), ::towlower);
        return out;
    };
    std::wstring cb = canon(base);
    std::wstring cd = canon(dest);
    if (cb.empty() || cd.empty()) return false;
    if (cd.size() <= cb.size())   return false;
    if (cd.compare(0, cb.size(), cb) != 0) return false;
    wchar_t sep = cd[cb.size()];
    return sep == L'\\' || sep == L'/';
}

// --- Base64 (for storing DPAPI ciphertext in plain-text cfg) ---------------
static std::string Base64Encode(const std::vector<BYTE>& data) {
    if (data.empty()) return {};
    DWORD len = 0;
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len))
        return {};
    std::string out(len, '\0');
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &len))
        return {};
    out.resize(len);
    return out;
}
static std::vector<BYTE> Base64Decode(const std::string& s) {
    if (s.empty()) return {};
    DWORD len = 0;
    if (!CryptStringToBinaryA(s.c_str(), (DWORD)s.size(),
                              CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
        return {};
    std::vector<BYTE> out(len);
    if (!CryptStringToBinaryA(s.c_str(), (DWORD)s.size(),
                              CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr))
        return {};
    out.resize(len);
    return out;
}

// --- DPAPI encrypt/decrypt --------------------------------------------------
//   CryptProtectData ties the ciphertext to the current Windows user account
//   (CRYPTPROTECT_UI_FORBIDDEN = no UI even if elevation is needed). To
//   decrypt on a different machine or user, the user must re-enter creds.
static std::string EncryptStringDPAPI(const std::wstring& plain) {
    if (plain.empty()) return {};
    DATA_BLOB in;
    in.pbData = (BYTE*)plain.data();
    in.cbData = (DWORD)(plain.size() * sizeof(wchar_t));
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"xways-updater", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out)) return {};
    std::vector<BYTE> v(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return Base64Encode(v);
}
static std::wstring DecryptStringDPAPI(const std::string& base64) {
    if (base64.empty()) return {};
    std::vector<BYTE> blob = Base64Decode(base64);
    if (blob.empty()) return {};
    DATA_BLOB in;
    in.pbData = blob.data();
    in.cbData = (DWORD)blob.size();
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) return {};
    std::wstring w((wchar_t*)out.pbData, out.cbData / sizeof(wchar_t));
    LocalFree(out.pbData);
    return w;
}

// --- Sidecar config (xways-updater.cfg next to the DLL) ---------------------
//   Plain-text key=value, one per line, # for comments. Passwords are stored
//   as DPAPI ciphertext base64-encoded. Recognised keys:
//     dongle_user, dongle_pass_b64
//     byod_user,   byod_pass_b64
//     license_type   = dongle | byod
//     install_base   = parent dir for new installs
//     include_beta   = 1|0
//     copy_cfg, copy_hashdb, create_shortcut, shortcut_admin = 1|0
struct Cfg {
    std::wstring dongleUser;
    std::wstring donglePass;
    std::wstring byodUser;
    std::wstring byodPass;
    std::wstring licenseType    = L"dongle";  // dongle | byod
    std::wstring installBase;
    // Mode controls whether we download the main app + extras (full) or only
    // the optional resources (extras_only). Backed by the tri-state checkbox
    // in the dialog.
    std::wstring mode           = L"full";    // full | extras_only
    bool         hasByodCreds   = false;
    bool         includeBeta    = false;
    bool         copyCfg        = true;
    bool         copyHashDb     = true;
    bool         copyXtensions  = true;
    bool         createShortcut = true;
    bool         shortcutAdmin  = true;       // always-on now (no UI toggle)
    // Default-on: Viewer Component, Conditional Coloring, AFF4 — small,
    // commonly wanted, low cost. Off by default: Tesseract (~55 MB) and
    // Excire (~275 MB) — explicit opt-in since they're heavy.
    bool         dlViewer       = true;
    bool         dlCondColoring = true;
    bool         dlAFF4         = true;
    bool         dlTesseract    = false;
    bool         dlExcire       = false;
    bool         remember       = true;
};

static std::wstring CfgPath() { return GetSelfDirectory() + L"\\xways-updater.cfg"; }

// Sidecar config persists ONLY credentials. Every other setting is derived
// at dialog open from struct defaults — install base from the running
// install's parent dir, mode = full, all download / copy / shortcut
// checkboxes per Cfg{} defaults. Older cfg files with extra keys are
// silently ignored (the unknown keys aren't matched below).
static Cfg LoadCfg() {
    Cfg c;
    std::wstring p = CfgPath();
    if (!FileExists(p)) return c;
    std::ifstream f(p);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        auto trim = [](std::string& s) {
            while (!s.empty() && (s.front()==' '||s.front()=='\t'||s.front()=='\r')) s.erase(s.begin());
            while (!s.empty() && (s.back()==' '||s.back()=='\t'||s.back()=='\r'))   s.pop_back();
        };
        trim(k); trim(v);
        std::wstring wv = Utf8ToWide(v);
        if      (k == "dongle_user")     c.dongleUser = wv;
        else if (k == "dongle_pass_b64") c.donglePass = DecryptStringDPAPI(v);
        else if (k == "byod_user")       c.byodUser   = wv;
        else if (k == "byod_pass_b64")   c.byodPass   = DecryptStringDPAPI(v);
        // Any other keys (legacy preferences) are silently ignored.
    }
    return c;
}

static void SaveCfg(const Cfg& c) {
    std::ofstream f(CfgPath(), std::ios::trunc);
    if (!f.is_open()) return;
    f << "# xways-updater sidecar config (credentials only).\n";
    f << "# Passwords are DPAPI-encrypted, scoped to the current Windows user.\n";
    f << "# Every other setting is derived at dialog open and not persisted.\n";
    f << "dongle_user="     << WideToUtf8(c.dongleUser) << "\n";
    if (c.remember && !c.donglePass.empty())
        f << "dongle_pass_b64=" << EncryptStringDPAPI(c.donglePass) << "\n";
    f << "byod_user="       << WideToUtf8(c.byodUser) << "\n";
    if (c.remember && !c.byodPass.empty())
        f << "byod_pass_b64="   << EncryptStringDPAPI(c.byodPass) << "\n";
}

// --- WinHTTP helpers --------------------------------------------------------
//   Thin wrappers around WinHTTP synchronous calls. Every request goes via
//   HTTPS on port 443; HTTP Basic auth is set with WinHttpSetCredentials
//   *before* sending. Server enforces a 1000 req/IP rate limit (we use far
//   fewer than that).
struct HttpResult {
    DWORD              statusCode = 0;
    DWORD              winhttpErr = 0;     // GetLastError when a WinHttp* call fails
    uint64_t           contentLength = 0;
    std::vector<BYTE>  body;
    std::wstring       error;              // raw low-level message; UI uses FormatHttpError instead
};

// Map WinHTTP / HTTP-level failures to plain-English messages a user can act
// on. Pass the host so the message names where the connection went.
static std::wstring FormatHttpError(const HttpResult& r, const std::wstring& host) {
    // Application-level (HTTP) responses come first; status code 0 means the
    // request never produced a response.
    switch (r.statusCode) {
        case 401: return L"Invalid credentials — " + host + L" rejected the username/password.";
        case 403: return L"403 Forbidden — " + host + L" refused the request (account may not be entitled to this download).";
        case 404: return L"404 Not Found — the requested file isn't on " + host + L" anymore.";
        case 429: return L"429 Too Many Requests — slow down and try again in a few minutes.";
        case 500: return L"500 Internal Server Error from " + host + L" — try again later.";
        case 502: return L"502 Bad Gateway from " + host + L" — try again later.";
        case 503: return L"503 Service Unavailable — " + host + L" is busy or in maintenance.";
        case 504: return L"504 Gateway Timeout from " + host + L".";
        default: break;
    }
    if (r.statusCode != 0) {
        wchar_t b[160];
        swprintf_s(b, L"HTTP %lu from %s — unexpected response.", r.statusCode, host.c_str());
        return b;
    }
    // Transport-level failures (no HTTP response received).
    switch (r.winhttpErr) {
        case ERROR_WINHTTP_TIMEOUT:
            return L"Connection to " + host + L" timed out. Check your internet connection or try again.";
        case ERROR_WINHTTP_NAME_NOT_RESOLVED:
            return L"Cannot resolve hostname '" + host + L"'. DNS failure or no internet connection.";
        case ERROR_WINHTTP_CANNOT_CONNECT:
            return L"Cannot connect to " + host + L". The server may be down, or your firewall / network is blocking outbound HTTPS.";
        case ERROR_WINHTTP_CONNECTION_ERROR:
            return L"Connection to " + host + L" was lost or reset. Retry usually fixes this.";
        case ERROR_WINHTTP_SECURE_FAILURE:
            return L"TLS / certificate validation failed contacting " + host + L". Corporate proxy with MITM cert? Clock drift?";
        case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
            return L"Invalid HTTPS response from " + host + L".";
        case ERROR_WINHTTP_OPERATION_CANCELLED:
            return L"Request was cancelled.";
        case 0:
            // Truly unknown — surface whatever low-level message we captured.
            return r.error.empty() ? (L"Unknown error contacting " + host) : r.error;
        default: {
            wchar_t b[200];
            swprintf_s(b, L"Network error contacting %s (WinHTTP code 0x%08lX). %s",
                       host.c_str(), r.winhttpErr,
                       r.error.empty() ? L"" : (L"Detail: " + r.error).c_str());
            return b;
        }
    }
}

static HttpResult HttpRequest(const std::wstring& host,
                              const std::wstring& path,
                              const std::wstring& user,
                              const std::wstring& pass,
                              bool                isHead,
                              const std::wstring& outFile = L"",
                              std::function<bool(uint64_t,uint64_t)> progress = nullptr)
{
    HttpResult r;
    HINTERNET hSession = WinHttpOpen(USER_AGENT,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { r.error = L"WinHttpOpen failed"; return r; }
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(),
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { r.error = L"WinHttpConnect failed"; WinHttpCloseHandle(hSession); return r; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        isHead ? L"HEAD" : L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) { r.error = L"WinHttpOpenRequest failed"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return r; }

    // Build "Authorization: Basic <b64(user:pass)>" and send pre-emptively.
    //   WinHttpSetCredentials only sends creds *in response to* a 401 challenge,
    //   not on the initial request, so a one-shot HEAD with creds-set-but-not-
    //   in-headers returns 401 and looks like a bad-cred failure even when the
    //   creds are right. Pre-emptive header bypasses WinHTTP's challenge dance.
    std::wstring extraHeaders;
    if (!user.empty()) {
        std::string up = WideToUtf8(user) + ":" + WideToUtf8(pass);
        std::vector<BYTE> upBytes(up.begin(), up.end());
        std::string b64 = Base64Encode(upBytes);
        extraHeaders = L"Authorization: Basic " + Utf8ToWide(b64) + L"\r\n";
    }
    LPCWSTR hdrPtr = extraHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extraHeaders.c_str();
    DWORD   hdrLen = extraHeaders.empty() ? 0 : (DWORD)-1L;

    BOOL ok = WinHttpSendRequest(hRequest, hdrPtr, hdrLen,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, nullptr);

    if (ok) {
        DWORD code = 0;
        DWORD codeSize = sizeof(code);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeSize, WINHTTP_NO_HEADER_INDEX);
        r.statusCode = code;

        uint64_t totalLen = 0;
        wchar_t lenBuf[64] = {0}; DWORD lenSize = sizeof(lenBuf);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH,
                                WINHTTP_HEADER_NAME_BY_INDEX, lenBuf,
                                &lenSize, WINHTTP_NO_HEADER_INDEX)) {
            totalLen = _wcstoui64(lenBuf, nullptr, 10);
        }
        r.contentLength = totalLen;

        if (!isHead && code >= 200 && code < 300) {
            HANDLE hOut = INVALID_HANDLE_VALUE;
            if (!outFile.empty()) {
                hOut = CreateFileW(outFile.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hOut == INVALID_HANDLE_VALUE) {
                    r.error = L"failed to open output file: " + outFile;
                }
            }
            if (r.error.empty()) {
                std::vector<BYTE> buf(64 * 1024);
                uint64_t got = 0;
                bool aborted = false;
                while (true) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
                        r.error = L"WinHttpQueryDataAvailable failed"; break;
                    }
                    if (avail == 0) break;
                    while (avail > 0) {
                        DWORD chunk = std::min(avail, (DWORD)buf.size());
                        DWORD readn = 0;
                        if (!WinHttpReadData(hRequest, buf.data(), chunk, &readn)) {
                            r.error = L"WinHttpReadData failed"; break;
                        }
                        if (readn == 0) break;
                        if (hOut != INVALID_HANDLE_VALUE) {
                            DWORD written = 0;
                            WriteFile(hOut, buf.data(), readn, &written, nullptr);
                        } else {
                            r.body.insert(r.body.end(), buf.begin(), buf.begin() + readn);
                        }
                        got += readn;
                        avail -= readn;
                        if (progress && !progress(got, totalLen)) { aborted = true; break; }
                    }
                    if (!r.error.empty() || aborted) break;
                }
                if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
                if (aborted) r.error = L"download cancelled";
            }
        }
    } else {
        r.winhttpErr = GetLastError();
        wchar_t buf[64];
        swprintf_s(buf, L"WinHTTP error 0x%08lX", r.winhttpErr);
        r.error = buf;
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return r;
}

static std::wstring ParseUrl(const std::wstring& url, std::wstring& host, std::wstring& path) {
    URL_COMPONENTS uc{};
    uc.dwStructSize     = sizeof(uc);
    wchar_t hostBuf[256] = {0};
    wchar_t pathBuf[2048] = {0};
    uc.lpszHostName     = hostBuf;
    uc.dwHostNameLength = _countof(hostBuf);
    uc.lpszUrlPath      = pathBuf;
    uc.dwUrlPathLength  = _countof(pathBuf);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return L"WinHttpCrackUrl failed";
    host = hostBuf;
    path = pathBuf;
    return L"";
}

// --- Apache index parser ----------------------------------------------------
//   Pulls every <a href="..."> from the directory listing. Filters to entries
//   matching xw_forensics<digits>(-beta).zip or xwb<digits>(-beta).zip.
struct IndexEntry {
    std::wstring filename;     // e.g. xw_forensics217.zip
    std::wstring displayLabel; // e.g. v21.7
    std::wstring lastModified; // e.g. "2026-04-09 16:43" (best-effort, may be empty)
    int          major = 0;
    int          minor = 0;
    bool         isBeta = false;
};

// Match an Apache directory listing's "Last modified" field. Most server
// configs render "YYYY-MM-DD HH:MM" or "DD-Mmm-YYYY HH:MM" right after the
// </a> closing tag of the link. We look in a small window after the href
// for either pattern and return the first hit.
static std::string TryMatchApacheDate(const std::string& s, size_t startPos, size_t windowSize = 200) {
    size_t end = (startPos + windowSize < s.size()) ? startPos + windowSize : s.size();
    for (size_t i = startPos; i + 16 < end; ++i) {
        // YYYY-MM-DD HH:MM  (e.g. 2026-04-09 16:43)
        if (isdigit((unsigned char)s[i+0]) && isdigit((unsigned char)s[i+1]) &&
            isdigit((unsigned char)s[i+2]) && isdigit((unsigned char)s[i+3]) &&
            s[i+4] == '-' &&
            isdigit((unsigned char)s[i+5]) && isdigit((unsigned char)s[i+6]) &&
            s[i+7] == '-' &&
            isdigit((unsigned char)s[i+8]) && isdigit((unsigned char)s[i+9]) &&
            (s[i+10] == ' ' || s[i+10] == 'T') &&
            isdigit((unsigned char)s[i+11]) && isdigit((unsigned char)s[i+12]) &&
            s[i+13] == ':' &&
            isdigit((unsigned char)s[i+14]) && isdigit((unsigned char)s[i+15])) {
            return s.substr(i, 16);
        }
        // DD-Mmm-YYYY HH:MM (e.g. 09-Apr-2026 16:43)
        if (i + 17 < end &&
            isdigit((unsigned char)s[i+0]) && isdigit((unsigned char)s[i+1]) &&
            s[i+2] == '-' &&
            isalpha((unsigned char)s[i+3]) && isalpha((unsigned char)s[i+4]) && isalpha((unsigned char)s[i+5]) &&
            s[i+6] == '-' &&
            isdigit((unsigned char)s[i+7]) && isdigit((unsigned char)s[i+8]) &&
            isdigit((unsigned char)s[i+9]) && isdigit((unsigned char)s[i+10]) &&
            s[i+11] == ' ' &&
            isdigit((unsigned char)s[i+12]) && isdigit((unsigned char)s[i+13]) &&
            s[i+14] == ':' &&
            isdigit((unsigned char)s[i+15]) && isdigit((unsigned char)s[i+16])) {
            return s.substr(i, 17);
        }
    }
    return {};
}

static std::vector<IndexEntry> ParseAppIndex(const std::string& html, bool isByod) {
    std::vector<IndexEntry> out;
    std::string s = html;
    // case-insensitive search for href=
    size_t pos = 0;
    while (true) {
        size_t h = s.find("href=\"", pos);
        if (h == std::string::npos) {
            // also try uppercase HREF=
            h = s.find("HREF=\"", pos);
            if (h == std::string::npos) break;
        }
        size_t start = h + 6;
        size_t end = s.find('"', start);
        if (end == std::string::npos) break;
        std::string href = s.substr(start, end - start);
        pos = end + 1;
        // Filter: filename only (no slashes, no parent navigation)
        if (href.empty() || href.find('/') != std::string::npos) continue;

        const char* prefix = isByod ? "xwb" : "xw_forensics";
        size_t plen = strlen(prefix);
        if (href.size() < plen + 4 || _strnicmp(href.c_str(), prefix, plen) != 0) continue;
        if (href.size() < 4 || _stricmp(href.c_str() + href.size() - 4, ".zip") != 0) continue;

        std::string core = href.substr(plen, href.size() - plen - 4); // e.g. "217" or "218-beta"
        bool beta = false;
        if (core.size() > 5) {
            std::string suffix = core.substr(core.size() - 5);
            std::transform(suffix.begin(), suffix.end(), suffix.begin(), ::tolower);
            if (suffix == "-beta") { beta = true; core = core.substr(0, core.size() - 5); }
        }
        if (core.empty()) continue;
        bool digitsOnly = true;
        for (char c : core) if (!isdigit((unsigned char)c)) { digitsOnly = false; break; }
        if (!digitsOnly) continue;

        IndexEntry e;
        e.filename = Utf8ToWide(href);
        e.isBeta = beta;
        // 217 -> major=21, minor=7; 218 -> major=21, minor=8; 200 -> major=20, minor=0
        // Convention: last digit is the minor; rest is the major.
        if (core.size() == 1) { e.major = 0; e.minor = core[0]-'0'; }
        else { e.major = std::stoi(core.substr(0, core.size()-1)); e.minor = core.back()-'0'; }

        // Look for "YYYY-MM-DD HH:MM" or similar in the next ~200 bytes after
        // this row's </a>. Apache's default index template puts the date right
        // after the link's closing tag.
        std::string date = TryMatchApacheDate(s, end + 1, 200);
        if (!date.empty()) e.lastModified = Utf8ToWide(date);

        wchar_t lab[64];
        // displayLabel is just the version (e.g. "v21.8"); beta status is
        // surfaced as a tag at the END of the dropdown row, not in the
        // version label itself — keeps the leftmost column clean and
        // aligns visually with the (Latest) tag.
        swprintf_s(lab, L"v%d.%d", e.major, e.minor);
        e.displayLabel = lab;
        out.push_back(e);
    }
    // Sort newest first (by major*10+minor, beta after stable of same version).
    std::sort(out.begin(), out.end(), [](const IndexEntry& a, const IndexEntry& b){
        int va = a.major*100 + a.minor*10 + (a.isBeta ? 1 : 0);
        int vb = b.major*100 + b.minor*10 + (b.isBeta ? 1 : 0);
        return va > vb;
    });
    return out;
}

// --- Zip extraction (tar.exe) ----------------------------------------------
//   bsdtar shipped in C:\Windows\System32\tar.exe handles zip archives since
//   Windows 10 1803. Cleaner than COM IShellDispatch and avoids a third-party
//   library dep.
static bool ExtractZip(const std::wstring& zipPath, const std::wstring& destDir, std::wstring& errOut) {
    if (!CreateDirectoryW(destDir.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            wchar_t buf[64]; swprintf_s(buf, L"CreateDirectory(%lu)", err);
            errOut = buf;
            return false;
        }
    }
    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring tarExe = std::wstring(sysDir) + L"\\tar.exe";
    if (!FileExists(tarExe)) {
        errOut = L"tar.exe not found in System32 (need Windows 10 1803+)";
        return false;
    }
    std::wstring cmd = L"\"" + tarExe + L"\" -xf \"" + zipPath + L"\" -C \"" + destDir + L"\"";

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(L'\0');
    if (!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        DWORD err = GetLastError();
        wchar_t buf[64]; swprintf_s(buf, L"CreateProcess(tar) failed (%lu)", err);
        errOut = buf;
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (code != 0) {
        wchar_t buf[64]; swprintf_s(buf, L"tar exited with code %lu", code);
        errOut = buf;
        return false;
    }
    return true;
}

// --- VERSIONINFO reader -----------------------------------------------------
//   Reads the FileVersion string from a PE binary. X-Ways uses a string like
//   "21.7 SR-3" / "21.7 SR-7" for stable, or "21.8 Beta 5" for prereleases.
//   We parse loosely into major.minor.{sr|betaNum}.
struct VerInfo {
    int          major = 0;
    int          minor = 0;
    int          sr    = 0;
    bool         haveSr = false;
    int          betaNum = 0;          // 0 if not a beta or beta number unknown
    bool         haveBeta = false;
    std::wstring rawString;
};

// Search for an "SR-N" / "SR N" / "SR.N" / "SRN" pattern (case-insensitive)
// in arbitrary text. Returns the SR number (>0) on first match, 0 otherwise.
static int FindSRInText(const std::wstring& text) {
    if (text.size() < 3) return 0;
    for (size_t i = 0; i + 2 < text.size(); ++i) {
        wchar_t a = (wchar_t)towlower(text[i]);
        wchar_t b = (wchar_t)towlower(text[i+1]);
        if (a != L's' || b != L'r') continue;
        // require word-start: previous char must be non-alnum (or start of string)
        if (i > 0) {
            wchar_t prev = text[i-1];
            if (iswalnum(prev)) continue;
        }
        size_t j = i + 2;
        while (j < text.size() && (text[j] == L'-' || text[j] == L' ' || text[j] == L'.' || text[j] == L'_')) ++j;
        if (j >= text.size() || !iswdigit(text[j])) continue;
        int n = 0;
        while (j < text.size() && iswdigit(text[j])) { n = n*10 + (text[j]-L'0'); ++j; }
        if (n > 0) return n;
    }
    return 0;
}

// Scan the .exe binary itself for "<major>.<minor> SR-N" — the Help → About
// dialog text is baked into the binary as a literal string (in both ASCII and
// UTF-16LE flavors depending on which resource carries it). This is the most
// reliable SR source when VERSIONINFO doesn't expose it. Capped at 64 MB so
// we don't pull a giant file into memory.
static int ScanBinaryForSR(const std::wstring& exePath, int major, int minor) {
    if (major == 0) return 0;
    HANDLE h = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    const uint64_t kMaxScan = 64ULL * 1024 * 1024;
    uint64_t total = (uint64_t)sz.QuadPart;
    if (total > kMaxScan) total = kMaxScan;
    std::vector<BYTE> buf((size_t)total);
    DWORD got = 0;
    ReadFile(h, buf.data(), (DWORD)total, &got, nullptr);
    CloseHandle(h);
    if (got == 0) return 0;

    char ascii[16];
    sprintf_s(ascii, "%d.%d", major, minor);
    size_t alen = strlen(ascii);
    auto isDigit = [](BYTE c) { return c >= '0' && c <= '9'; };
    auto isAlnum = [](BYTE c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    };

    // Padding gap allowed between "<maj>.<min>" and " SR-N":
    //   - Newer X-Ways (21.1+) stores them contiguously ("21.7 SR-3").
    //   - 21.0 and earlier stored them in a fixed-offset resource block
    //     with ~39 NULs of padding between the slots. Empirically verified
    //     against xwforensics64.exe v21.0 SR-11 and v20.8 SR-9: "<maj>.<min>"
    //     and " SR-N" sit ~44 bytes apart, gap is pure 0x00.
    // Only NUL / space / underscore are accepted as padding; anything else
    // aborts the match so we don't bridge across unrelated content.
    static constexpr size_t kMaxPadAscii = 256;
    static constexpr size_t kMaxPadWide  = 512; // = 256 wchars

    // ASCII pass.
    for (size_t i = 0; i + alen + 4 < got; ++i) {
        if (memcmp(buf.data() + i, ascii, alen) != 0) continue;
        if (i > 0 && isAlnum(buf[i-1])) continue;
        size_t j = i + alen;
        size_t maxLook = (j + kMaxPadAscii < got) ? j + kMaxPadAscii : got;
        while (j < maxLook && (buf[j] == 0x00 || buf[j] == ' ' || buf[j] == '_')) ++j;
        if (j + 2 > got) continue;
        BYTE a = buf[j], b = buf[j+1];
        if (!((a == 'S' || a == 's') && (b == 'R' || b == 'r'))) continue;
        size_t k = j + 2;
        while (k < got && (buf[k] == '-' || buf[k] == ' ' || buf[k] == '.')) ++k;
        if (k >= got || !isDigit(buf[k])) continue;
        int n = 0, digits = 0;
        while (k < got && isDigit(buf[k]) && digits < 3) {
            n = n*10 + (buf[k]-'0'); ++k; ++digits;
        }
        if (n > 0 && n < 100) return n;
    }

    // UTF-16LE pass — same logic, each char is 2 bytes with high byte 0.
    // Padding accepts U+0000 (two NULs), space (0x20 0x00), underscore.
    std::vector<BYTE> wide;
    wide.reserve(alen * 2);
    for (size_t i = 0; i < alen; ++i) { wide.push_back((BYTE)ascii[i]); wide.push_back(0); }
    for (size_t i = 0; i + wide.size() + 16 < got; i += 2) {
        if (memcmp(buf.data() + i, wide.data(), wide.size()) != 0) continue;
        size_t j = i + wide.size();
        size_t maxLook = (j + kMaxPadWide < got) ? j + kMaxPadWide : got;
        while (j + 1 < maxLook && buf[j+1] == 0 &&
               (buf[j] == 0x00 || buf[j] == ' ' || buf[j] == '_')) j += 2;
        if (j + 4 > got) continue;
        if (buf[j+1] != 0 || buf[j+3] != 0) continue;
        BYTE a = buf[j], b = buf[j+2];
        if (!((a == 'S' || a == 's') && (b == 'R' || b == 'r'))) continue;
        size_t k = j + 4;
        while (k + 1 < got && buf[k+1] == 0 && (buf[k] == '-' || buf[k] == ' ' || buf[k] == '.')) k += 2;
        if (k + 1 >= got || buf[k+1] != 0 || !isDigit(buf[k])) continue;
        int n = 0, digits = 0;
        while (k + 1 < got && buf[k+1] == 0 && isDigit(buf[k]) && digits < 3) {
            n = n*10 + (buf[k]-'0'); k += 2; ++digits;
        }
        if (n > 0 && n < 100) return n;
    }
    return 0;
}

// Best-effort scan of small text files in a directory for an SR pattern.
// Looks at the first ~64KB of each candidate (readme.txt, !readme.txt,
// version.txt) — enough to catch any header line.
// Run the staged xwforensics64.exe (or xwb64.exe) with the `GetLicID:<file>`
// CLI parameter. X-Ways writes a startup banner like
//   "MM/DD/YYYY, HH:MM:SS  X-Ways Forensics [BYOD] 21.7 SR-3 x64, User: ..."
// to <exe dir>\msglog.txt at session start, then exits because GetLicID:
// only fetches the dongle ID and quits. We snapshot msglog size before the
// run, launch the exe with a 10-second timeout, then parse the freshly-
// appended banner line for the SR. See docs/xways-command-line.md.
//
// Side effects: writes one line to <exe dir>\msglog.txt and creates a tiny
// nLicID output file (cleaned up below). For our use the exe lives in a
// tempdir staging area that gets RemoveTreeBestEffort'd by TempDirGuard.
//
// Returns parsed major/minor and either an SR or a Beta number. The msglog
// banner is the most authoritative source we have, so callers should let
// these values override stale VERSIONINFO data (e.g. a 21.8 beta whose
// VERSIONINFO still says 21.7).
struct BannerInfo {
    bool ok       = false;
    int  major    = 0;
    int  minor    = 0;
    int  sr       = 0;     // 0 if not stable / not parsed
    int  betaNum  = 0;     // 0 if not beta / not parsed
};
static BannerInfo GetBannerViaGetLicID(const std::wstring& exePath) {
    BannerInfo result;
    std::wstring exeDir = exePath.substr(0, exePath.find_last_of(L"\\/"));
    std::wstring msglogPath = JoinPath(exeDir, L"msglog.txt");

    uint64_t sizeBefore = 0;
    {
        HANDLE h = CreateFileW(msglogPath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            GetFileSizeEx(h, &sz);
            sizeBefore = sz.QuadPart;
            CloseHandle(h);
        }
    }

    // Final command line — Override:1 alone, no GetLicID: action verb.
    // Background: combining Override:N with GetLicID:<path> produces a
    // Win32 ERROR_INVALID_NAME popup ("Cannot open 'GetLicID:C:\...'")
    // because X-Ways consumes Override:N as the action and the second
    // arg becomes a positional file path. The literal "GetLicID:C:\..."
    // has two colons; Win32 rejects it before X-Ways control flow runs.
    // No documented workaround exists. Full investigation logged in
    // [docs/xways-command-line.md] under "Empirical findings".
    //
    // We only wanted the side-effect of GetLicID — the session-start
    // banner X-Ways writes to msglog.txt — and that banner is written
    // for ANY launch, not just GetLicID launches. Override:1 alone:
    //   * Auto-OKs the multi-instance prompt that fires because the
    //     host X-Ways is already running. The default radio is "Start
    //     another instance", so OK starts a fresh second instance.
    //   * The second instance writes its session banner to msglog.txt
    //     within ~1s, then sits ~5s before self-exiting with
    //     exitCode=0x0000042B (ERROR_PROCESS_ABORTED).
    //   * No second <verb>:<value> arg = no Win32 popup.
    // Avoid `auto` here — combined with a crashed second instance it
    // can take down the host X-Ways.
    std::wstring cmd = L"\"" + exePath + L"\" \"Override:1\"";
    Log(L"  GetLicID: launching: " + cmd);
    Log(L"  GetLicID: cwd:       " + exeDir);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    BOOL launched = CreateProcessW(nullptr, cmdBuf.data(),
                                   nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr,
                                   exeDir.c_str(),
                                   &si, &pi);
    if (!launched) {
        DWORD ge = GetLastError();
        wchar_t b[200];
        swprintf_s(b, L"  GetLicID: CreateProcess failed (%lu); cmd=%s", ge, cmd.c_str());
        Log(b);
        return result;
    }

    // 10s is plenty — Override:1 self-exits within ~6s in practice.
    DWORD r = WaitForSingleObject(pi.hProcess, 10000);
    bool timedOut = (r != WAIT_OBJECT_0);
    if (timedOut) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    {
        wchar_t b[200];
        swprintf_s(b, L"  GetLicID: process %s; exitCode=0x%08lX",
                   timedOut ? L"timed out (10s) and was terminated" : L"exited cleanly",
                   exitCode);
        Log(b);
    }

    HANDLE h = CreateFileW(msglogPath.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        Log(L"  GetLicID: msglog.txt not present after run: " + msglogPath);
        return result;
    }
    LARGE_INTEGER szAfter{};
    GetFileSizeEx(h, &szAfter);
    {
        wchar_t b[200];
        swprintf_s(b, L"  GetLicID: msglog size before=%llu after=%llu (path=%s)",
                   (unsigned long long)sizeBefore,
                   (unsigned long long)szAfter.QuadPart,
                   msglogPath.c_str());
        Log(b);
    }
    if (szAfter.QuadPart == 0) {
        CloseHandle(h);
        Log(L"  GetLicID: msglog is empty.");
        return result;
    }
    // Read up to the LAST 64 KB of the file — banners live one per session,
    // and we want the most recent one (which corresponds to the run we just
    // launched if the banner got written, otherwise the most recent prior
    // run for the same staged binary). Reading from the tail keeps us O(1)
    // even if msglog has accumulated many sessions.
    constexpr DWORD kTailBytes = 64 * 1024;
    DWORD readSize = (szAfter.QuadPart > kTailBytes)
                       ? kTailBytes
                       : (DWORD)szAfter.QuadPart;
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)(szAfter.QuadPart - readSize);
    SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    std::vector<char> buf(readSize);
    DWORD got = 0;
    ReadFile(h, buf.data(), readSize, &got, nullptr);
    CloseHandle(h);
    if (got == 0) {
        Log(L"  GetLicID: msglog read returned 0 bytes.");
        return result;
    }

    std::string content(buf.data(), got);
    // Scan EVERY "X-Ways Forensics" occurrence and try to parse a
    // versioned banner. msglog under Override:1 contains both a real
    // session-start banner ("X-Ways Forensics 21.7 SR-3 x64, ..." or
    // "X-Ways Forensics BYOD 21.8 Beta 5 x64, ...") AND redirected
    // dialog titles (also "X-Ways Forensics", but followed by '***'
    // or dialog body text — no version digits). We accept the first
    // occurrence that yields a valid <major>.<minor> SR-<n> or
    // <major>.<minor> Beta <n> triple.
    size_t scan = 0;
    while ((scan = content.find("X-Ways Forensics", scan)) != std::string::npos) {
        int m1 = 0, m2 = 0, m3 = 0;
        // Stable: "X-Ways Forensics [BYOD] <maj>.<min> SR-<n>"
        int n = sscanf_s(content.c_str() + scan,
                         "X-Ways Forensics%*[^0-9]%d.%d SR-%d",
                         &m1, &m2, &m3);
        if (n >= 3 && m3 > 0) {
            result.ok = true; result.major = m1; result.minor = m2; result.sr = m3;
            wchar_t b[160];
            swprintf_s(b, L"  GetLicID: parsed banner -> %d.%d SR-%d", m1, m2, m3);
            Log(b);
            return result;
        }
        // Beta: "X-Ways Forensics [BYOD] <maj>.<min> Beta <n>"
        m1 = m2 = m3 = 0;
        n = sscanf_s(content.c_str() + scan,
                     "X-Ways Forensics%*[^0-9]%d.%d Beta %d",
                     &m1, &m2, &m3);
        if (n >= 3 && m3 > 0) {
            result.ok = true; result.major = m1; result.minor = m2; result.betaNum = m3;
            wchar_t b[160];
            swprintf_s(b, L"  GetLicID: parsed banner -> %d.%d Beta %d", m1, m2, m3);
            Log(b);
            return result;
        }
        scan += 16;  // length of "X-Ways Forensics" — advance past this match
    }
    // No occurrence parsed cleanly. Surface the first 200 chars so we
    // can see what was in there.
    std::string preview = content.substr(0, std::min<size_t>(content.size(), 200));
    Log(L"  GetLicID: msglog has 'X-Ways Forensics' string(s) but no parseable "
        L"version+SR-or-Beta triple. Preview: " + Utf8ToWide(preview));
    return result;
}

static int FindSRInTextFiles(const std::wstring& dir) {
    static const wchar_t* kCandidates[] = {
        L"!readme.txt", L"readme.txt", L"README.txt", L"version.txt", L"VERSION.txt"
    };
    for (const wchar_t* name : kCandidates) {
        std::wstring full = JoinPath(dir, name);
        if (!FileExists(full)) continue;
        HANDLE h = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        std::vector<char> buf(64 * 1024);
        DWORD got = 0;
        ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
        CloseHandle(h);
        if (got == 0) continue;
        // X-Ways readme files are typically Latin-1 / Windows-1252; treat as
        // CP1252 so non-ASCII bytes don't trip the wide-string conversion.
        int wlen = MultiByteToWideChar(CP_ACP, 0, buf.data(), (int)got, nullptr, 0);
        std::wstring w(wlen, L'\0');
        MultiByteToWideChar(CP_ACP, 0, buf.data(), (int)got, w.data(), wlen);
        int n = FindSRInText(w);
        if (n > 0) return n;
    }
    return 0;
}

static VerInfo ReadFileVersion(const std::wstring& exePath) {
    VerInfo v;
    DWORD dummy = 0;
    DWORD size  = GetFileVersionInfoSizeW(exePath.c_str(), &dummy);
    if (size == 0) return v;
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(exePath.c_str(), 0, size, data.data())) return v;

    // Pull the binary fixed version first (most reliable major.minor).
    VS_FIXEDFILEINFO* ffi = nullptr; UINT flen = 0;
    if (VerQueryValueW(data.data(), L"\\", (LPVOID*)&ffi, &flen) && ffi) {
        v.major = HIWORD(ffi->dwFileVersionMS);
        v.minor = LOWORD(ffi->dwFileVersionMS);
        // FileVersionLS may carry the SR in either word. Prefer non-zero,
        // smallest plausible value (SR < 100).
        WORD lsHi = HIWORD(ffi->dwFileVersionLS);
        WORD lsLo = LOWORD(ffi->dwFileVersionLS);
        if (lsHi > 0 && lsHi < 100)      { v.sr = lsHi; v.haveSr = true; }
        else if (lsLo > 0 && lsLo < 100) { v.sr = lsLo; v.haveSr = true; }
    }

    // Walk every translation entry and pull every common string field.
    // X-Ways' SR may live in any of FileVersion / ProductVersion / Comments
    // / OriginalFilename — search them all.
    static const wchar_t* kFields[] = {
        L"FileVersion", L"ProductVersion", L"FileDescription", L"ProductName",
        L"Comments",    L"OriginalFilename", L"InternalName", L"PrivateBuild",
        L"SpecialBuild"
    };
    struct Translation { WORD lang, codepage; };
    Translation* tr = nullptr;
    UINT trLen = 0;
    std::wstring searchBlob;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                       (LPVOID*)&tr, &trLen) && tr && trLen >= sizeof(Translation)) {
        size_t numTr = trLen / sizeof(Translation);
        for (size_t t = 0; t < numTr; ++t) {
            for (const wchar_t* field : kFields) {
                wchar_t sub[160];
                swprintf_s(sub, L"\\StringFileInfo\\%04x%04x\\%s",
                           tr[t].lang, tr[t].codepage, field);
                wchar_t* str = nullptr; UINT slen = 0;
                if (VerQueryValueW(data.data(), sub, (LPVOID*)&str, &slen) && str) {
                    if (v.rawString.empty() && wcscmp(field, L"FileVersion") == 0) {
                        v.rawString = str;
                    }
                    searchBlob += L" ";
                    searchBlob += str;
                }
            }
        }
    }

    // If FFI didn't give a major/minor, parse FileVersion string.
    if (v.major == 0 && !v.rawString.empty()) {
        std::wstring s = v.rawString;
        size_t i = 0;
        auto skipNonDigit = [&](){ while (i < s.size() && !iswdigit(s[i])) ++i; };
        auto readInt = [&](int& out) {
            int n = 0; bool any = false;
            while (i < s.size() && iswdigit(s[i])) { any = true; n = n*10 + (s[i]-L'0'); ++i; }
            out = n; return any;
        };
        int rmaj = 0, rmin = 0;
        if (readInt(rmaj)) v.major = rmaj;
        skipNonDigit();
        if (readInt(rmin)) v.minor = rmin;
    }

    // SR fallback: search every VERSIONINFO string field for an SR pattern.
    if (!v.haveSr) {
        int srFound = FindSRInText(searchBlob);
        if (srFound > 0) { v.sr = srFound; v.haveSr = true; }
    }
    return v;
}

// Folder-name prefix follows the chosen license type so a Dongle install and
// a BYOD install of the same version can sit side-by-side without colliding:
//   Dongle stable -> xwf21-7sr3
//   BYOD   stable -> xwb21-7sr3
//   BYOD   beta   -> xwb21-8-beta5      (when beta number was parsed from the msglog banner)
//   BYOD   beta   -> xwb21-8-beta       (fallback: user picked a -beta.zip but parser couldn't extract a beta number)
static std::wstring BuildAutoFolderName(const VerInfo& v, bool isByod, bool selectedBeta) {
    wchar_t buf[64];
    const wchar_t* prefix = isByod ? L"xwb" : L"xwf";
    if (v.haveBeta && v.betaNum > 0) {
        swprintf_s(buf, L"%s%d-%d-beta%d", prefix, v.major, v.minor, v.betaNum);
    } else if (selectedBeta) {
        swprintf_s(buf, L"%s%d-%d-beta", prefix, v.major, v.minor);
    } else if (v.haveSr) {
        swprintf_s(buf, L"%s%d-%dsr%d", prefix, v.major, v.minor, v.sr);
    } else {
        swprintf_s(buf, L"%s%d-%d", prefix, v.major, v.minor);
    }
    return buf;
}

// --- Running install detection ---------------------------------------------
//   Identify the X-Ways currently hosting our DLL: product type (Dongle vs
//   BYOD) and full version (major.minor[.sr]). Used to (a) default the
//   license-type radio in the settings dialog, (b) populate the footer
//   status line, and (c) refuse a same-version reinstall.
//
//   Detection sources (most authoritative first):
//     1. msglog.txt banner — X-Ways writes "MM/DD/YYYY, HH:MM:SS  X-Ways
//        Forensics [BYOD] <maj>.<min> SR-N x64, ..." on every session start.
//        See docs/xways-command-line.md.
//     2. Running-module filename — xwb*.exe = BYOD, otherwise Dongle.
//     3. VERSIONINFO + binary scan of the running exe — fallback for SR.
struct RunningInstall {
    bool         isByod = false;
    int          major = 0;
    int          minor = 0;
    int          sr = 0;
    bool         haveSr = false;
    std::wstring mainExe;        // full path to running xwforensics64.exe / xwb64.exe
    std::wstring installDir;     // dir of mainExe
    std::wstring rawBanner;      // msglog banner line, if found (for logging)
};

static RunningInstall DetectRunningInstall() {
    RunningInstall r;
    wchar_t modPath[MAX_PATH] = {0};
    GetModuleFileNameW(GetModuleHandleW(nullptr), modPath, MAX_PATH);
    r.mainExe = modPath;
    r.installDir = GetXWaysInstallDir();

    // Product type from filename (case-insensitive).
    std::wstring leaf = modPath;
    size_t slash = leaf.find_last_of(L"\\/");
    if (slash != std::wstring::npos) leaf = leaf.substr(slash + 1);
    std::transform(leaf.begin(), leaf.end(), leaf.begin(), ::towlower);
    if (leaf.rfind(L"xwb", 0) == 0) r.isByod = true;

    // Read msglog.txt and find the most recent banner line.
    std::wstring msglogPath = JoinPath(r.installDir, L"msglog.txt");
    if (FileExists(msglogPath)) {
        std::ifstream f(msglogPath);
        std::string line, lastBanner;
        while (std::getline(f, line)) {
            if (line.find("X-Ways Forensics") != std::string::npos &&
                (line.find("x64") != std::string::npos || line.find("x86") != std::string::npos)) {
                lastBanner = line;
            }
        }
        if (!lastBanner.empty()) {
            r.rawBanner = Utf8ToWide(lastBanner);
            // Re-evaluate product type from banner if it explicitly says BYOD.
            if (lastBanner.find("BYOD") != std::string::npos) r.isByod = true;
            // Parse "<maj>.<min> SR-<N>" out of the line.
            size_t p = lastBanner.find("X-Ways Forensics");
            if (p != std::string::npos) {
                std::string tail = lastBanner.substr(p);
                int maj = 0, min_ = 0, sr = 0;
                int n = sscanf_s(tail.c_str(), "%*[^0-9]%d.%d SR-%d", &maj, &min_, &sr);
                if (n >= 2) { r.major = maj; r.minor = min_; }
                if (n >= 3 && sr > 0) { r.sr = sr; r.haveSr = true; }
            }
        }
    }

    // Fallback to VERSIONINFO + binary scan if msglog didn't give us version.
    if (r.major == 0) {
        VerInfo v = ReadFileVersion(modPath);
        r.major = v.major; r.minor = v.minor;
        if (v.haveSr) { r.sr = v.sr; r.haveSr = true; }
        if (!r.haveSr && v.major > 0) {
            int sr = ScanBinaryForSR(modPath, v.major, v.minor);
            if (sr > 0) { r.sr = sr; r.haveSr = true; }
        }
    }
    return r;
}

static std::wstring FormatRunningSummary(const RunningInstall& r) {
    if (r.major == 0) return L"Detected current install: (version unknown)";
    wchar_t buf[200];
    if (r.haveSr) {
        swprintf_s(buf, L"Detected current install: X-Ways Forensics %s%d.%d SR-%d",
                   r.isByod ? L"BYOD " : L"", r.major, r.minor, r.sr);
    } else {
        swprintf_s(buf, L"Detected current install: X-Ways Forensics %s%d.%d",
                   r.isByod ? L"BYOD " : L"", r.major, r.minor);
    }
    return buf;
}

// --- SHA256 of an on-disk file (CryptoAPI) ---------------------------------
//   Returns lowercase 64-char hex on success, empty string on failure.
//   Used to log a verifiable hash of every downloaded artifact (zips + loose
//   files) to the Messages window.
static std::wstring Sha256File(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CloseHandle(h); return L"";
    }
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); CloseHandle(h); return L"";
    }
    BYTE buf[64 * 1024];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
        if (!CryptHashData(hHash, buf, got, 0)) {
            CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
            CloseHandle(h); return L"";
        }
    }
    CloseHandle(h);
    BYTE digest[32]; DWORD digestLen = 32;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return L"";
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    wchar_t hex[65] = {0};
    for (int i = 0; i < 32; ++i) swprintf_s(hex + i*2, 3, L"%02x", digest[i]);
    return hex;
}

// --- File / directory copy --------------------------------------------------
//   Recursive directory copy via SHFileOperationW (FOF_NOCONFIRMATION
//   suppresses prompts, FOF_NOERRORUI hides per-file error popups, but we
//   still surface a final success/fail). pFrom/pTo must be double-null-
//   terminated.
static bool CopyTreeShellApi(const std::wstring& src, const std::wstring& dst) {
    std::wstring from = src; from.push_back(L'\0'); from.push_back(L'\0');
    std::wstring to   = dst; to.push_back(L'\0');   to.push_back(L'\0');
    SHFILEOPSTRUCTW op{};
    op.wFunc  = FO_COPY;
    op.pFrom  = from.c_str();
    op.pTo    = to.c_str();
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_SILENT;
    int rc = SHFileOperationW(&op);
    return rc == 0 && !op.fAnyOperationsAborted;
}

// Recursively copy the *contents* of srcDir into dstDir (NOT srcDir itself).
// Existing destination files are overwritten. dstDir is created if needed.
// Returns true if every file copied successfully. Used for the AFF4 merge
// where the zip's `ImageIOAFF4.dll` + `x64\ImageIOAFF4.dll` layout has to
// land flat in the install dir alongside X-Ways' own root + x64\ files.
static bool MergeTreeContents(const std::wstring& srcDir, const std::wstring& dstDir) {
    SHCreateDirectoryExW(nullptr, dstDir.c_str(), nullptr);
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((srcDir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring srcChild = JoinPath(srcDir, fd.cFileName);
        std::wstring dstChild = JoinPath(dstDir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!MergeTreeContents(srcChild, dstChild)) ok = false;
        } else {
            if (!CopyFileW(srcChild.c_str(), dstChild.c_str(), /*failIfExists=*/FALSE)) ok = false;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}

// --- Shortcut creation ------------------------------------------------------
//   Standard IShellLinkW + IPersistFile recipe. SLDF_RUNAS_USER sets the
//   "Run as administrator" advanced-properties checkbox so the .lnk requests
//   elevation when launched.
static HRESULT CreateAppShortcut(const std::wstring& targetExe,
                                 const std::wstring& workingDir,
                                 const std::wstring& shortcutPath,
                                 const std::wstring& description,
                                 bool runAsAdmin) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool comInited = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    IShellLinkW* link = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (void**)&link);
    if (SUCCEEDED(hr)) {
        link->SetPath(targetExe.c_str());
        link->SetWorkingDirectory(workingDir.c_str());
        if (!description.empty()) link->SetDescription(description.c_str());
        if (runAsAdmin) {
            IShellLinkDataList* dl = nullptr;
            if (SUCCEEDED(link->QueryInterface(IID_IShellLinkDataList, (void**)&dl)) && dl) {
                DWORD flags = 0;
                dl->GetFlags(&flags);
                dl->SetFlags(flags | SLDF_RUNAS_USER);
                dl->Release();
            }
        }
        IPersistFile* pf = nullptr;
        hr = link->QueryInterface(IID_IPersistFile, (void**)&pf);
        if (SUCCEEDED(hr) && pf) {
            hr = pf->Save(shortcutPath.c_str(), TRUE);
            pf->Release();
        }
        link->Release();
    }
    if (comInited) CoUninitialize();
    return hr;
}

static std::wstring GetDesktopPath() {
    wchar_t* p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &p))) {
        std::wstring r = p;
        CoTaskMemFree(p);
        return r;
    }
    return L"";
}

// --- Browse-for-folder ------------------------------------------------------
static std::wstring BrowseForFolder(HWND parent, const std::wstring& title, const std::wstring& start) {
    BROWSEINFOW bi{};
    bi.hwndOwner = parent;
    bi.lpszTitle = title.c_str();
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpfn      = [](HWND hwnd, UINT uMsg, LPARAM /*lp*/, LPARAM lpData) -> int {
        if (uMsg == BFFM_INITIALIZED && lpData) {
            SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, lpData);
        }
        return 0;
    };
    bi.lParam    = (LPARAM)start.c_str();
    LPITEMIDLIST idl = SHBrowseForFolderW(&bi);
    if (!idl) return L"";
    wchar_t buf[MAX_PATH] = {0};
    SHGetPathFromIDListW(idl, buf);
    CoTaskMemFree(idl);
    return buf;
}

// --- Dialog-driven settings struct -----------------------------------------
struct Settings {
    Cfg            cfg;
    std::wstring   chosenFilename;        // filename relative to /xwf/ or /xwb/
    std::wstring   chosenLabel;
    std::wstring   folderNameOverride;    // empty = auto
    RunningInstall running;               // captured pre-dialog
    bool           pickedDongle = true;
    bool           chosenIsBeta = false;  // mirrors VersionEntry.isBeta of the dropdown selection
    bool           okPressed    = false;
};

// Forwards
static bool DownloadAppZip(const Settings& s, const std::wstring& zipOut, std::wstring& err);
static std::vector<IndexEntry> RefreshVersions(bool isByod, const std::wstring& user, const std::wstring& pass, std::wstring& err);
static void ShowAboutDialog(HWND parent);

// --- Dialog proc ------------------------------------------------------------
static void EnableDongleCredFields(HWND h, bool on) {
    // Includes the section header — when dongle creds aren't needed at all
    // (MainOnly + BYOD radio), the entire row should look greyed.
    EnableWindow(GetDlgItem(h, IDC_LABEL_DONGLE_HEADER), on);
    EnableWindow(GetDlgItem(h, IDC_LABEL_DONGLE_USER), on);
    EnableWindow(GetDlgItem(h, IDC_EDIT_DONGLE_USER),  on);
    EnableWindow(GetDlgItem(h, IDC_LABEL_DONGLE_PASS), on);
    EnableWindow(GetDlgItem(h, IDC_EDIT_DONGLE_PASS),  on);
    EnableWindow(GetDlgItem(h, IDC_BTN_TOGGLE_DONGLE_PASS), on);
    EnableWindow(GetDlgItem(h, IDC_BTN_TEST_DONGLE),   on);
}

static void EnableBYODCredFields(HWND h, bool on) {
    EnableWindow(GetDlgItem(h, IDC_LABEL_BYOD_USER), on);
    EnableWindow(GetDlgItem(h, IDC_EDIT_BYOD_USER),  on);
    EnableWindow(GetDlgItem(h, IDC_LABEL_BYOD_PASS), on);
    EnableWindow(GetDlgItem(h, IDC_EDIT_BYOD_PASS),  on);
    EnableWindow(GetDlgItem(h, IDC_BTN_TOGGLE_BYOD_PASS), on);
    EnableWindow(GetDlgItem(h, IDC_BTN_TEST_BYOD),   on);
}

// Toggle ES_PASSWORD masking on a password edit field. Updates the toggle
// button text to "Show" / "Hide" so the current state is visible.
static void TogglePasswordVisibility(HWND hDlg, int editId, int btnId) {
    HWND edit = GetDlgItem(hDlg, editId);
    if (!edit) return;
    wchar_t cur = (wchar_t)SendMessageW(edit, EM_GETPASSWORDCHAR, 0, 0);
    if (cur != 0) {
        // Currently masked → reveal.
        SendMessageW(edit, EM_SETPASSWORDCHAR, 0, 0);
        SetDlgItemTextW(hDlg, btnId, L"Hide");
    } else {
        // Currently revealed → mask with dot (matches default style).
        SendMessageW(edit, EM_SETPASSWORDCHAR, (WPARAM)L'\x25CF', 0);
        SetDlgItemTextW(hDlg, btnId, L"Show");
    }
    InvalidateRect(edit, nullptr, TRUE);
}
static void SetCheck(HWND h, int id, bool v) {
    SendDlgItemMessageW(h, id, BM_SETCHECK, v ? BST_CHECKED : BST_UNCHECKED, 0);
}
static bool GetCheck(HWND h, int id) {
    return SendDlgItemMessageW(h, id, BM_GETCHECK, 0, 0) == BST_CHECKED;
}
static std::wstring GetText(HWND h, int id) {
    int len = GetWindowTextLengthW(GetDlgItem(h, id));
    std::wstring s(len + 1, L'\0');
    GetDlgItemTextW(h, id, s.data(), len + 1);
    s.resize(wcsnlen(s.c_str(), len + 1));
    return s;
}
static void SetText(HWND h, int id, const std::wstring& s) {
    SetDlgItemTextW(h, id, s.c_str());
}

// Apply +bold+11pt to group titles for visual emphasis. The credential sub-
// headers (Dongle / BYOD section labels) get the same bold face — since they
// act like nested group titles for the indented username/password rows.
static void StyleGroupTitles(HWND hDlg) {
    static const int kBoldGroups[] = {
        IDC_GROUP_LICENSE, IDC_GROUP_CREDS, IDC_GROUP_VERSION,
        IDC_GROUP_INSTALL, IDC_GROUP_OPTIONAL, IDC_GROUP_COPY,
        IDC_GROUP_SHORTCUT
    };
    static const int kBoldHeaders[] = {
        IDC_LABEL_DONGLE_HEADER, IDC_LABEL_BYOD_HEADER
    };
    HFONT hf = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
    if (!hf) return;
    LOGFONTW lf{}; GetObjectW(hf, sizeof(lf), &lf);
    lf.lfWeight = FW_BOLD;
    LONG bigH = (LONG)(lf.lfHeight * 1.15);
    LONG normalH = lf.lfHeight;
    static HFONT g_hfBoldBig = nullptr;
    static HFONT g_hfBold    = nullptr;
    if (!g_hfBoldBig) { lf.lfHeight = bigH;    g_hfBoldBig = CreateFontIndirectW(&lf); }
    if (!g_hfBold)    { lf.lfHeight = normalH; g_hfBold    = CreateFontIndirectW(&lf); }
    if (g_hfBoldBig) {
        for (int id : kBoldGroups) {
            HWND h = GetDlgItem(hDlg, id);
            if (h) SendMessageW(h, WM_SETFONT, (WPARAM)g_hfBoldBig, TRUE);
        }
    }
    if (g_hfBold) {
        for (int id : kBoldHeaders) {
            HWND h = GetDlgItem(hDlg, id);
            if (h) SendMessageW(h, WM_SETFONT, (WPARAM)g_hfBold, TRUE);
        }
    }
}

// Repopulate the version combo from a parsed index.
struct DlgState {
    Settings*               s = nullptr;
    std::vector<IndexEntry> versions;
    int                     latestIdx = -1;     // index of the "(Latest)" entry in `versions`
    RunningInstall          running;
    int                     refreshFlashPhase = 0;
    int                     fieldFlashPhase = 0;
    std::vector<int>        fieldFlashIds;       // edit-control IDs currently flashing
    HICON                   hIconSmall = nullptr;
    HICON                   hIconBig   = nullptr;
    bool                    populating = false;
    bool                    refreshed  = false;  // true after first successful refresh
    // Install worker — set when an install is running inside the dialog.
    HANDLE                  hWorker      = nullptr;
    bool                    workerActive = false;
    bool                    workerOk     = false;
    std::wstring            workerErr;
    std::wstring            workerFinalDir;
};

// Lazily-created yellow brush used to highlight cred-field flashes via
// WM_CTLCOLOREDIT. Win32 owns the brush for the lifetime of the process.
static HBRUSH GetFieldFlashBrush() {
    static HBRUSH g_hYellowBrush = nullptr;
    if (!g_hYellowBrush) g_hYellowBrush = CreateSolidBrush(RGB(255, 245, 130));
    return g_hYellowBrush;
}

// Begin flashing a set of edit fields (yellow background pulse, ~6 frames
// over ~1.2s), and set keyboard focus to the first one so the user can type
// into it immediately.
static void StartFieldFlash(HWND hDlg, DlgState* ds, std::vector<int> ids) {
    if (ids.empty()) return;
    ds->fieldFlashIds = std::move(ids);
    ds->fieldFlashPhase = 0;
    SetTimer(hDlg, TIMER_FIELD_FLASH, 200, nullptr);
    HWND hFirst = GetDlgItem(hDlg, ds->fieldFlashIds.front());
    if (hFirst) SetFocus(hFirst);
}

// Tri-state mode of the "Full install" checkbox at the top of the dialog.
//   BST_CHECKED        — Full install options          (main app + selected optional items)
//   BST_INDETERMINATE  — Download tools only           (skip main app; pull selected optional items)
//   BST_UNCHECKED      — Download main app only        (main app only; skip ALL optional items)
enum class InstallMode { Full, ExtrasOnly, MainOnly };

static InstallMode GetInstallMode(HWND hDlg) {
    LRESULT s = SendDlgItemMessageW(hDlg, IDC_CHK_FULL_INSTALL, BM_GETCHECK, 0, 0);
    if (s == BST_CHECKED)       return InstallMode::Full;
    if (s == BST_INDETERMINATE) return InstallMode::ExtrasOnly;
    return InstallMode::MainOnly;
}

static const wchar_t* ModeToCfgString(InstallMode m) {
    switch (m) {
        case InstallMode::Full:       return L"full";
        case InstallMode::ExtrasOnly: return L"extras_only";
        case InstallMode::MainOnly:   return L"main_only";
    }
    return L"full";
}

// Check whether the resolved <install base>\<folder name> already exists on
// disk. If so, show the red-bold "Folder already exists" warning and disable
// the Install button. Only relevant in Full mode — main-only and tools-only
// drop files directly into the base with collision-avoiding suffixes, so
// the folder-name field doesn't drive a destination there and the warning
// is permanently hidden.
static void UpdateFolderExistsWarning(HWND hDlg) {
    HWND hWarn = GetDlgItem(hDlg, IDC_LABEL_FOLDER_EXISTS);
    HWND hInst = GetDlgItem(hDlg, IDC_BTN_INSTALL);
    if (GetInstallMode(hDlg) != InstallMode::Full) {
        SetWindowTextW(hWarn, L"");
        ShowWindow(hWarn, SW_HIDE);
        EnableWindow(hInst, TRUE);
        return;
    }
    std::wstring base   = GetText(hDlg, IDC_EDIT_INSTALL_BASE);
    std::wstring folder = TrimW(GetText(hDlg, IDC_EDIT_FOLDER_NAME));
    bool conflict = false;
    if (!base.empty() && !folder.empty()) {
        std::wstring full = JoinPath(base, folder);
        conflict = DirExists(full);
    }
    if (conflict) {
        SetWindowTextW(hWarn, L"Folder already exists");
        ShowWindow(hWarn, SW_SHOW);
        EnableWindow(hInst, FALSE);
    } else {
        SetWindowTextW(hWarn, L"");
        ShowWindow(hWarn, SW_HIDE);
        EnableWindow(hInst, TRUE);
    }
}

// Forward decl — PopulateVersionCombo is defined further down (after the
// helpers that use it indirectly via ResetVersionsList).
struct DlgState;
static void PopulateVersionCombo(HWND hDlg, DlgState* ds, bool includeBeta, const std::wstring& preferFilename);

// Update the folder-name cue banner so the example name matches the active
// (mode, license radio) combination. Called on dialog init and on every
// mode-checkbox or radio click.
static void UpdateFolderCueBanner(HWND hDlg) {
    InstallMode m = GetInstallMode(hDlg);
    bool isByod = GetCheck(hDlg, IDC_RADIO_BYOD);
    const wchar_t* banner;
    if (m == InstallMode::ExtrasOnly) {
        banner = L"(blank = auto-name like xways-tools-<timestamp>)";
    } else if (isByod) {
        banner = L"(blank = auto-name from detected version, e.g. xwb21-7sr3)";
    } else {
        banner = L"(blank = auto-name from detected version, e.g. xwf21-7sr3)";
    }
    SendDlgItemMessageW(hDlg, IDC_EDIT_FOLDER_NAME, EM_SETCUEBANNER, TRUE,
                        (LPARAM)banner);
}

// Wipe the cached version list + refresh state. Called when the license
// radio changes (the /xwf/ and /xwb/ Apache indexes hold different
// filenames, so the previously-loaded list no longer applies). After this
// the dropdown shows the "Current (click Refresh ...)" placeholder again,
// and the Refresh-button flash will fire on the next dropdown click since
// `refreshed` is back to false.
static void ResetVersionsList(HWND hDlg, DlgState* ds) {
    ds->versions.clear();
    ds->refreshed = false;
    ds->latestIdx = -1;
    PopulateVersionCombo(hDlg, ds, GetCheck(hDlg, IDC_CHK_INCLUDE_BETA), L"");
}

// Update the mode checkbox caption based on its current state. The unchecked
// variant additionally includes the active license (Dongle / BYOD) since
// "main app only" depends on which radio is selected.
static void UpdateModeCheckboxLabel(HWND hDlg) {
    InstallMode m = GetInstallMode(hDlg);
    const wchar_t* label = L"Full install options";
    if (m == InstallMode::ExtrasOnly) {
        label = L"Download tools only";
    } else if (m == InstallMode::MainOnly) {
        label = GetCheck(hDlg, IDC_RADIO_BYOD)
            ? L"Download BYOD app only"
            : L"Download Dongle app only";
    }
    SetDlgItemTextW(hDlg, IDC_CHK_FULL_INSTALL, label);
}

// Single source of truth for the (mode, radio) → field-enable matrix.
// Called from WM_INITDIALOG and from every command handler that toggles
// the mode checkbox or the license radio.
//
//   Mode        | Radio  | Dongle creds | BYOD creds | Copy/shortcut | Optionals
//   Full        | Dongle | enabled      | disabled   | enabled       | enabled
//   Full        | BYOD   | enabled      | enabled    | enabled       | enabled
//   ExtrasOnly  | Dongle | enabled      | disabled   | DISABLED      | enabled
//   MainOnly    | Dongle | enabled      | disabled   | enabled       | DISABLED
//   MainOnly    | BYOD   | DISABLED     | enabled    | DISABLED      | DISABLED
//
// Rationale for "MainOnly + BYOD" disabling Copy/shortcut: the user is
// downloading just the BYOD app — typically the existing install is Dongle
// (or a different BYOD), so blanket-copying configs/shortcut into a BYOD
// folder may not be the right defaults. Easy to re-enable manually if the
// user does want that.
static void UpdateDialogEnables(HWND hDlg) {
    InstallMode m = GetInstallMode(hDlg);
    bool isByod   = GetCheck(hDlg, IDC_RADIO_BYOD);
    bool needMainApp   = (m != InstallMode::ExtrasOnly);
    bool wantOptionals = (m != InstallMode::MainOnly);

    bool dongleCredsNeeded = !(m == InstallMode::MainOnly && isByod);
    bool byodCredsNeeded   = needMainApp && isByod;
    // Copy + shortcut only meaningful in Full mode (we're putting a complete
    // install at the destination). Both extras-only and main-only skip the
    // copy stage and the desktop shortcut.
    bool copyShortcutOK    = (m == InstallMode::Full);

    // BYOD radio only meaningful when we're actually fetching the main app.
    EnableWindow(GetDlgItem(hDlg, IDC_RADIO_BYOD), needMainApp);
    if (!needMainApp) {
        SetCheck(hDlg, IDC_RADIO_DONGLE, true);
        SetCheck(hDlg, IDC_RADIO_BYOD,   false);
    }

    EnableDongleCredFields(hDlg, dongleCredsNeeded);
    EnableBYODCredFields  (hDlg, byodCredsNeeded);

    for (int id : { IDC_CHK_COPY_CFG, IDC_CHK_COPY_HASHDB, IDC_CHK_COPY_XTENSIONS,
                    IDC_CHK_CREATE_SHORTCUT }) {
        EnableWindow(GetDlgItem(hDlg, id), copyShortcutOK);
    }
    for (int id : { IDC_CHK_DL_VIEWER, IDC_CHK_DL_TESSERACT, IDC_CHK_DL_EXCIRE,
                    IDC_CHK_DL_COND_COLORING, IDC_CHK_DL_AFF4 }) {
        EnableWindow(GetDlgItem(hDlg, id), wantOptionals);
    }

    // "Install" labels apply only to Full mode (a complete install with the
    // main app + extras + copies + shortcut). Both other modes ("Download
    // tools only" and "Download Dongle/BYOD app only") are conceptually a
    // download: the result is a folder of files, not a usable, completely-
    // configured install. So they all flip to "Download …".
    bool isFullMode = (m == InstallMode::Full);
    SetText(hDlg, IDC_LABEL_INSTALL_BASE, isFullMode ? L"Install to:" : L"Download to:");
    SetText(hDlg, IDC_GROUP_INSTALL,      isFullMode ? L"Install location" : L"Download location");
    SetDlgItemTextW(hDlg, IDC_BTN_INSTALL, isFullMode ? L"&Install" : L"&Download");

    // Folder name only applies to Full mode (subfolder under base). The
    // app-only / tools-only modes drop files directly into the base with
    // collision-avoiding suffixes — no folder-name input needed.
    EnableWindow(GetDlgItem(hDlg, IDC_LABEL_FOLDER_NAME), isFullMode);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_FOLDER_NAME),  isFullMode);
    UpdateFolderExistsWarning(hDlg);

    // X-Ways flatly refuses to load a newer version's .cfg in an older
    // build ("You must not re-use a later version's .cfg file in an older
    // version"). When the analyst picks a version OLDER than what's
    // currently running, force-uncheck and disable the "Copy custom configs"
    // checkbox so we don't carry forward incompatible settings. Same-or-
    // newer keeps the user's choice intact.
    DlgState* ds = (DlgState*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
    if (ds && copyShortcutOK) {  // only matters in Full mode (Copy is otherwise disabled anyway)
        int runVer = ds->running.major * 100 + ds->running.minor * 10;
        int selVer = -1;
        HWND combo = GetDlgItem(hDlg, IDC_COMBO_VERSION);
        int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
        LRESULT data = SendMessageW(combo, CB_GETITEMDATA, sel, 0);
        if (data != (LRESULT)-1 && data != CB_ERR && !ds->versions.empty()) {
            int i = (int)data;
            if (i >= 0 && i < (int)ds->versions.size()) {
                selVer = ds->versions[i].major * 100 + ds->versions[i].minor * 10;
            }
        }
        bool isOlder = (runVer > 0 && selVer > 0 && selVer < runVer);
        HWND hCfg = GetDlgItem(hDlg, IDC_CHK_COPY_CFG);
        // Disable the checkbox when picking an older version (keeps the
        // analyst from carrying forward incompatible .cfg files), but
        // leave the existing check state alone — when the analyst flips
        // back to a same-or-newer version, the box re-enables with their
        // prior preference intact (Copy enforces wantOptionals via the
        // mode matrix above; no need to override the user's check here).
        EnableWindow(hCfg, isOlder ? FALSE : TRUE);
    }
}

// RunInstall is defined further down (after several support helpers); the
// dialog worker thread calls into it.
static bool RunInstall(Settings& s, std::wstring& finalInstallDir, std::wstring& err);

// Worker context owned by the dialog while the install runs. Heap-allocated
// when the user clicks Install, freed by the thread proc on the way out.
struct DlgWorkerCtx {
    Settings* s;
    DlgState* ds;
};
static unsigned __stdcall DlgWorkerThread(void* p) {
    auto* w = (DlgWorkerCtx*)p;
    w->ds->workerOk = RunInstall(*w->s, w->ds->workerFinalDir, w->ds->workerErr);
    PostMessageW(g_progress.hDlg, WM_APP + 3 /*WM_APP_DONE*/,
                 (WPARAM)(w->ds->workerOk ? 1 : 0), 0);
    delete w;
    return 0;
}

// IDs of every interactive control in the dialog. Enabled / disabled
// wholesale when an install starts/finishes — also referenced by the
// per-mode UpdateDialogEnables matrix.
static const int kAllInputCtlIds[] = {
    IDC_RADIO_DONGLE, IDC_RADIO_BYOD, IDC_CHK_FULL_INSTALL,
    IDC_EDIT_DONGLE_USER, IDC_EDIT_DONGLE_PASS, IDC_BTN_TOGGLE_DONGLE_PASS, IDC_BTN_TEST_DONGLE,
    IDC_EDIT_BYOD_USER,   IDC_EDIT_BYOD_PASS,   IDC_BTN_TOGGLE_BYOD_PASS,   IDC_BTN_TEST_BYOD,
    IDC_CHK_REMEMBER_CREDS,
    IDC_COMBO_VERSION, IDC_BTN_REFRESH_VERSIONS, IDC_CHK_INCLUDE_BETA,
    IDC_EDIT_INSTALL_BASE, IDC_BTN_BROWSE_INSTALL_BASE, IDC_EDIT_FOLDER_NAME,
    IDC_CHK_DL_VIEWER, IDC_CHK_DL_TESSERACT, IDC_CHK_DL_EXCIRE,
    IDC_CHK_DL_COND_COLORING, IDC_CHK_DL_AFF4,
    IDC_CHK_COPY_CFG, IDC_CHK_COPY_HASHDB, IDC_CHK_COPY_XTENSIONS,
    IDC_CHK_CREATE_SHORTCUT,
    IDC_BTN_INSTALL, IDCANCEL,
    // IDC_BTN_ABOUT and IDC_BTN_OPEN_FOLDER stay enabled — both are
    // read-only/info actions and don't interfere with the running worker.
};

// Show or hide the progress bar + status label, and disable / re-enable all
// interactive controls. Called when the worker thread starts and stops.
// Always clears any leftover marquee animation so the bar starts each run
// in determinate mode.
static void SetDialogBusy(HWND hDlg, bool busy) {
    HWND hProg   = GetDlgItem(hDlg, IDC_PROGRESS_INSTALL);
    HWND hStatus = GetDlgItem(hDlg, IDC_LABEL_PROGRESS_STATUS);
    if (busy) {
        // Force determinate mode in case a prior failed run left marquee on.
        SendMessageW(hProg, PBM_SETMARQUEE, FALSE, 0);
        LONG_PTR style = GetWindowLongPtrW(hProg, GWL_STYLE);
        SetWindowLongPtrW(hProg, GWL_STYLE, style & ~PBS_MARQUEE);
        SendMessageW(hProg, PBM_SETRANGE32, 0, 1000);
        SendMessageW(hProg, PBM_SETPOS, 0, 0);
        ShowWindow(hProg,   SW_SHOW);
        ShowWindow(hStatus, SW_SHOW);
    } else {
        SendMessageW(hProg, PBM_SETMARQUEE, FALSE, 0);
        ShowWindow(hProg,   SW_HIDE);
        ShowWindow(hStatus, SW_HIDE);
        SetWindowTextW(hStatus, L"");
    }
    for (int id : kAllInputCtlIds) {
        HWND h = GetDlgItem(hDlg, id);
        if (h) EnableWindow(h, busy ? FALSE : TRUE);
    }
    if (!busy) {
        // Restore per-mode enable matrix so radio/combo state goes back
        // to whatever the current mode dictates.
        UpdateDialogEnables(hDlg);
    }
}

static void PopulateVersionCombo(HWND hDlg, DlgState* ds, bool includeBeta, const std::wstring& preferFilename) {
    ds->populating = true;
    HWND combo = GetDlgItem(hDlg, IDC_COMBO_VERSION);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);

    if (ds->versions.empty()) {
        // No refresh has happened yet — placeholder entry that maps to the
        // canonical unversioned zip name (xw_forensics.zip / xwb.zip).
        int idx = (int)SendMessageW(combo, CB_ADDSTRING, 0,
            (LPARAM)L"Current (click Refresh to load full version list)");
        SendMessageW(combo, CB_SETITEMDATA, idx, (LPARAM)-1);
        SendMessageW(combo, CB_SETCURSEL, idx, 0);
        ds->populating = false;
        return;
    }

    // Identify the highest non-beta entry — that's "the latest stable".
    ds->latestIdx = -1;
    for (size_t i = 0; i < ds->versions.size(); ++i) {
        if (!ds->versions[i].isBeta) { ds->latestIdx = (int)i; break; }
    }

    int select = -1;
    int dataIdx = 0;
    for (auto& e : ds->versions) {
        if (e.isBeta && !includeBeta) { ++dataIdx; continue; }
        // Plain text format:
        //   v21.7   2026-04-09 16:46   xw_forensics217.zip   (Latest)
        //   v21.8   2026-04-29 12:37   xw_forensics218-beta.zip   (beta)
        std::wstring lab = e.displayLabel;
        if (!e.lastModified.empty()) { lab += L"   "; lab += e.lastModified; }
        lab += L"   "; lab += e.filename;
        if (dataIdx == ds->latestIdx) lab += L"   (Latest)";
        else if (e.isBeta)            lab += L"   (beta)";
        int i = (int)SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)lab.c_str());
        SendMessageW(combo, CB_SETITEMDATA, i, (LPARAM)dataIdx);
        if (!preferFilename.empty() && e.filename == preferFilename) select = i;
        else if (select < 0 && dataIdx == ds->latestIdx)             select = i;
        ++dataIdx;
    }
    if (select < 0) select = 0;
    SendMessageW(combo, CB_SETCURSEL, select, 0);
    ds->populating = false;
}

// Owner-draw column rendering was tried (CBS_OWNERDRAWFIXED + WM_DRAWITEM)
// but rendered cramped at typical MS Shell Dlg sizes. We fell back to a
// plain text combo with three-space-separated columns — see PopulateVersionCombo.

static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    DlgState* ds = (DlgState*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        ds = (DlgState*)lp;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)ds);
        StyleGroupTitles(hDlg);

        // Title bar — set dynamically so it picks up the running version.
        // Leading spaces leave breathing room around the title-bar icon.
        {
            wchar_t titleBuf[128];
            swprintf_s(titleBuf, L"  x-ways updater %s", VERSION);
            SetWindowTextW(hDlg, titleBuf);
        }

        const Cfg& c = ds->s->cfg;

        // Title-bar icon — try a few candidate locations so the user doesn't
        // have to think too hard about where to drop xways-updater.ico. We log the
        // outcome to the Messages window so it's easy to debug if missing.
        std::vector<std::wstring> iconCandidates;
        iconCandidates.push_back(GetSelfDirectory() + L"\\xways-updater.ico");
        iconCandidates.push_back(GetParent(GetSelfDirectory()) + L"\\xways-updater.ico");
        bool iconLoaded = false;
        for (const auto& p : iconCandidates) {
            if (!FileExists(p)) continue;
            HICON hSmall = (HICON)LoadImageW(nullptr, p.c_str(), IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
            HICON hBig   = (HICON)LoadImageW(nullptr, p.c_str(), IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            if (hSmall || hBig) {
                ds->hIconSmall = hSmall;
                ds->hIconBig   = hBig;
                if (hSmall) SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hSmall);
                if (hBig)   SendMessageW(hDlg, WM_SETICON, ICON_BIG,   (LPARAM)hBig);
                iconLoaded = true;
                break;
            }
        }
        if (!iconLoaded) {
            std::wstring tried;
            for (size_t i = 0; i < iconCandidates.size(); ++i) {
                if (i) tried += L"; ";
                tried += iconCandidates[i];
            }
            Log(L"No xways-updater.ico found (looked in: " + tried + L"). Drop a 16x16+32x32 .ico file at one of those paths to set the title icon — no rebuild needed.");
        }

        // License radio — XT_Prepare always sets cfg.licenseType to match
        // the running X-Ways flavor, so this radio anchors to whatever's
        // currently in use. Toggling within the dialog still works for
        // cross-license testing; the next session re-anchors to running.
        bool defaultByod = (c.licenseType == L"byod");
        SetCheck(hDlg, IDC_RADIO_DONGLE, !defaultByod);
        SetCheck(hDlg, IDC_RADIO_BYOD,    defaultByod);

        // Mode tri-state. Three states:
        //   BST_CHECKED       — full install (default)
        //   BST_INDETERMINATE — extras-only
        //   BST_UNCHECKED     — main-app-only (skip optional downloads)
        LRESULT modeState = BST_CHECKED;
        if      (c.mode == L"extras_only") modeState = BST_INDETERMINATE;
        else if (c.mode == L"main_only")   modeState = BST_UNCHECKED;
        SendDlgItemMessageW(hDlg, IDC_CHK_FULL_INSTALL, BM_SETCHECK, modeState, 0);
        UpdateModeCheckboxLabel(hDlg);

        // Credentials
        SetText(hDlg, IDC_EDIT_DONGLE_USER, c.dongleUser);
        SetText(hDlg, IDC_EDIT_DONGLE_PASS, c.donglePass);
        SetText(hDlg, IDC_EDIT_BYOD_USER, c.byodUser);
        SetText(hDlg, IDC_EDIT_BYOD_PASS, c.byodPass);
        SetCheck(hDlg, IDC_CHK_REMEMBER_CREDS, c.remember);

        // Version
        SetCheck(hDlg, IDC_CHK_INCLUDE_BETA, c.includeBeta);
        // Empty placeholder until user clicks Refresh (avoid surprise network
        // call on dialog open).
        PopulateVersionCombo(hDlg, ds, c.includeBeta, L"");
        // Widen the dropdown list itself (independent of the closed combo
        // width) so all four owner-draw columns fit without ellipsis.
        SendDlgItemMessageW(hDlg, IDC_COMBO_VERSION, CB_SETDROPPEDWIDTH, 480, 0);

        // Detected line is split into two static controls so the prefix can
        // stay default black/regular while only the value gets bold + blue
        // (bold via WM_SETFONT here, blue via WM_CTLCOLORSTATIC below).
        // FormatRunningSummary returns "Detected current install: <value>";
        // strip the prefix off here since the prefix is its own control now.
        {
            std::wstring full = FormatRunningSummary(ds->running);
            const wchar_t* kPrefix = L"Detected current install: ";
            std::wstring value = (full.rfind(kPrefix, 0) == 0)
                ? full.substr(wcslen(kPrefix)) : full;
            SetText(hDlg, IDC_LABEL_DETECTED, value);
        }
        {
            HFONT hf = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
            LOGFONTW lf{}; if (hf) GetObjectW(hf, sizeof(lf), &lf);
            lf.lfWeight = FW_BOLD;
            static HFONT g_hfLabelBold = nullptr;
            if (!g_hfLabelBold) g_hfLabelBold = CreateFontIndirectW(&lf);
            if (g_hfLabelBold) SendDlgItemMessageW(hDlg, IDC_LABEL_DETECTED, WM_SETFONT, (WPARAM)g_hfLabelBold, TRUE);
        }

        // Folder-name cue banner (greyed placeholder when the field is empty).
        // Uses (mode, radio) to pick the example name — see helper.
        UpdateFolderCueBanner(hDlg);

        // Bold font on the "Folder already exists" warning. Color comes from
        // WM_CTLCOLORSTATIC below. Hidden by default — only appears when the
        // user types a folder name that already exists at the install base.
        {
            HFONT hf = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
            LOGFONTW lf{}; if (hf) GetObjectW(hf, sizeof(lf), &lf);
            lf.lfWeight = FW_BOLD;
            static HFONT g_hfWarnBold = nullptr;
            if (!g_hfWarnBold) g_hfWarnBold = CreateFontIndirectW(&lf);
            if (g_hfWarnBold)
                SendDlgItemMessageW(hDlg, IDC_LABEL_FOLDER_EXISTS, WM_SETFONT, (WPARAM)g_hfWarnBold, TRUE);
        }
        UpdateFolderExistsWarning(hDlg);

        // Tooltip on the "Copy custom configs" checkbox: explain what we copy
        // and remind the analyst to review the rest.
        {
            INITCOMMONCONTROLSEX icc{};
            icc.dwSize = sizeof(icc);
            icc.dwICC  = ICC_BAR_CLASSES;
            InitCommonControlsEx(&icc);
            HWND hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, nullptr,
                WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                hDlg, nullptr, g_hSelf, nullptr);
            if (hTip) {
                static const wchar_t* kCopyTip =
                    L"Copies these from the current install root:\n"
                    L"  - *.cfg files (WinHex.cfg, Conditional Coloring.cfg, ...)\n"
                    L"  - *.tpl files (hex-editor templates) — only if not already in the new install\n"
                    L"  - *.dlg files (saved dialog selections)\n"
                    L"  - investigator.ini\n"
                    L"  - Passwords.txt\n"
                    L"  - Programs.txt";
                TOOLINFOW ti{};
                ti.cbSize   = sizeof(ti);
                ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
                ti.hwnd     = hDlg;
                ti.uId      = (UINT_PTR)GetDlgItem(hDlg, IDC_CHK_COPY_CFG);
                ti.lpszText = (LPWSTR)kCopyTip;
                SendMessageW(hTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
                SendMessageW(hTip, TTM_SETMAXTIPWIDTH, 0, 360);
            }
        }

        // Install location
        std::wstring base = c.installBase.empty() ? GetDefaultInstallBase(defaultByod) : c.installBase;
        SetText(hDlg, IDC_EDIT_INSTALL_BASE, base);
        SetText(hDlg, IDC_EDIT_FOLDER_NAME, L"");

        // Optional + copy + shortcut state
        SetCheck(hDlg, IDC_CHK_DL_VIEWER,         c.dlViewer);
        SetCheck(hDlg, IDC_CHK_DL_TESSERACT,      c.dlTesseract);
        SetCheck(hDlg, IDC_CHK_DL_EXCIRE,         c.dlExcire);
        SetCheck(hDlg, IDC_CHK_DL_COND_COLORING,  c.dlCondColoring);
        SetCheck(hDlg, IDC_CHK_DL_AFF4,           c.dlAFF4);
        SetCheck(hDlg, IDC_CHK_COPY_CFG,          c.copyCfg);
        SetCheck(hDlg, IDC_CHK_COPY_HASHDB,       c.copyHashDb);
        SetCheck(hDlg, IDC_CHK_COPY_XTENSIONS,    c.copyXtensions);
        SetCheck(hDlg, IDC_CHK_CREATE_SHORTCUT,   c.createShortcut);

        // All mode/radio-driven enable logic in one place. Conditional
        // Coloring is treated like every other Download tools item — its
        // own checkbox controls it. When both copy_cfg and dl_cond_coloring
        // are on, the *.cfg copy loop skips Conditional Coloring.cfg so the
        // downloaded fresh version wins.
        UpdateDialogEnables(hDlg);

        // Refresh-button flash trigger lives on CBN_DROPDOWN now (only fires
        // before the first successful refresh). See WM_COMMAND below.
        return TRUE;
    }

    case WM_DESTROY: {
        if (ds && ds->hIconSmall) { DestroyIcon(ds->hIconSmall); ds->hIconSmall = nullptr; }
        if (ds && ds->hIconBig)   { DestroyIcon(ds->hIconBig);   ds->hIconBig   = nullptr; }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        HWND hCtl = (HWND)lp;
        int id = GetDlgCtrlID(hCtl);
        if (id == IDC_LABEL_DETECTED) {
            // Detected installed version — blue.
            SetTextColor(hdc, RGB(0, 80, 200));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
        }
        if (id == IDC_LABEL_FOLDER_EXISTS) {
            // "Folder already exists" warning — red.
            SetTextColor(hdc, RGB(200, 0, 0));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
        }
        break;
    }

    case WM_CTLCOLOREDIT: {
        // Pulse-highlight cred-field background while flashing.
        if (ds && (ds->fieldFlashPhase % 2 == 1)) {
            HWND hCtl = (HWND)lp;
            int id = GetDlgCtrlID(hCtl);
            for (int flashId : ds->fieldFlashIds) {
                if (flashId == id) {
                    HDC hdc = (HDC)wp;
                    SetBkColor(hdc, RGB(255, 245, 130));
                    SetBkMode(hdc, OPAQUE);
                    return (INT_PTR)GetFieldFlashBrush();
                }
            }
        }
        break;
    }

    case WM_TIMER: {
        if (wp == TIMER_REFRESH_FLASH) {
            HWND b = GetDlgItem(hDlg, IDC_BTN_REFRESH_VERSIONS);
            // Toggle the "pushed" visual state for a soft flash effect.
            SendMessageW(b, BM_SETSTATE, (ds->refreshFlashPhase % 2 == 0) ? TRUE : FALSE, 0);
            ds->refreshFlashPhase++;
            if (ds->refreshFlashPhase >= 6) {
                SendMessageW(b, BM_SETSTATE, FALSE, 0);
                KillTimer(hDlg, TIMER_REFRESH_FLASH);
                ds->refreshFlashPhase = 0;
            }
            return TRUE;
        }
        if (wp == TIMER_FIELD_FLASH) {
            ds->fieldFlashPhase++;
            for (int id : ds->fieldFlashIds) {
                HWND h = GetDlgItem(hDlg, id);
                if (h) InvalidateRect(h, nullptr, TRUE);
            }
            if (ds->fieldFlashPhase >= 6) {
                KillTimer(hDlg, TIMER_FIELD_FLASH);
                ds->fieldFlashPhase = 0;
                ds->fieldFlashIds.clear();
                // Final repaint to clear the highlight.
                for (int id : { IDC_EDIT_DONGLE_USER, IDC_EDIT_DONGLE_PASS,
                                IDC_EDIT_BYOD_USER,   IDC_EDIT_BYOD_PASS }) {
                    HWND h = GetDlgItem(hDlg, id);
                    if (h) InvalidateRect(h, nullptr, TRUE);
                }
            }
            return TRUE;
        }
        break;
    }

    case WM_COMMAND: {
        WORD ctlId  = LOWORD(wp);
        WORD notify = HIWORD(wp);

        if (ctlId == IDC_BTN_ABOUT && notify == BN_CLICKED) {
            ShowAboutDialog(hDlg);
            return TRUE;
        }
        if (ctlId == IDC_BTN_OPEN_FOLDER && notify == BN_CLICKED) {
            // Open the running install's directory in Explorer. Detected at
            // dialog open via DetectRunningInstall(); falls back to the
            // module dir if the running info is somehow missing.
            std::wstring dir = !ds->running.installDir.empty()
                             ? ds->running.installDir
                             : GetXWaysInstallDir();
            ShellExecuteW(hDlg, L"explore", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (ctlId == IDC_COMBO_VERSION && notify == CBN_DROPDOWN) {
            // Nudge the user toward Refresh — but only the first time the
            // dropdown is opened, before they've populated the version list.
            if (!ds->refreshed && ds->refreshFlashPhase == 0) {
                SetTimer(hDlg, TIMER_REFRESH_FLASH, 200, nullptr);
            }
            return TRUE;
        }
        if (ctlId == IDC_COMBO_VERSION && notify == CBN_SELCHANGE) {
            // Selected version changed — re-evaluate the Copy custom configs
            // gate (auto-disabled when the picked version is OLDER than the
            // currently running install).
            if (!ds->populating) UpdateDialogEnables(hDlg);
            return TRUE;
        }
        if (ctlId == IDC_CHK_FULL_INSTALL && notify == BN_CLICKED) {
            UpdateModeCheckboxLabel(hDlg);
            UpdateDialogEnables(hDlg);
            UpdateFolderCueBanner(hDlg);
            return TRUE;
        }
        if ((ctlId == IDC_RADIO_DONGLE || ctlId == IDC_RADIO_BYOD) && notify == BN_CLICKED) {
            // Mode label depends on the active radio in the unchecked state.
            UpdateModeCheckboxLabel(hDlg);
            UpdateDialogEnables(hDlg);
            // Indexes are per-host; switching license invalidates the cached list.
            ResetVersionsList(hDlg, ds);
            UpdateFolderCueBanner(hDlg);
            // Auto-swap install base between the dongle/BYOD defaults so the
            // user doesn't have to retype after toggling license type. We only
            // swap when the field currently holds the OTHER license's default
            // — any custom path the user typed is preserved untouched.
            {
                bool nowByod = (ctlId == IDC_RADIO_BYOD);
                std::wstring cur = GetText(hDlg, IDC_EDIT_INSTALL_BASE);
                std::wstring otherDefault = GetDefaultInstallBase(!nowByod);
                if (_wcsicmp(cur.c_str(), otherDefault.c_str()) == 0) {
                    SetText(hDlg, IDC_EDIT_INSTALL_BASE, GetDefaultInstallBase(nowByod));
                    UpdateFolderExistsWarning(hDlg);
                }
            }
            return TRUE;
        }
        if (ctlId == IDC_BTN_TOGGLE_DONGLE_PASS && notify == BN_CLICKED) {
            TogglePasswordVisibility(hDlg, IDC_EDIT_DONGLE_PASS, IDC_BTN_TOGGLE_DONGLE_PASS);
            return TRUE;
        }
        if (ctlId == IDC_BTN_TOGGLE_BYOD_PASS && notify == BN_CLICKED) {
            TogglePasswordVisibility(hDlg, IDC_EDIT_BYOD_PASS, IDC_BTN_TOGGLE_BYOD_PASS);
            return TRUE;
        }
        if (ctlId == IDC_CHK_INCLUDE_BETA && notify == BN_CLICKED) {
            PopulateVersionCombo(hDlg, ds, GetCheck(hDlg, IDC_CHK_INCLUDE_BETA), L"");
            UpdateDialogEnables(hDlg);  // re-evaluate copy_cfg gate for new selection
            return TRUE;
        }
        if (ctlId == IDC_BTN_BROWSE_INSTALL_BASE) {
            std::wstring start = GetText(hDlg, IDC_EDIT_INSTALL_BASE);
            std::wstring picked = BrowseForFolder(hDlg, L"Pick install base folder", start);
            if (!picked.empty()) {
                SetText(hDlg, IDC_EDIT_INSTALL_BASE, picked);
                UpdateFolderExistsWarning(hDlg);
            }
            return TRUE;
        }
        if ((ctlId == IDC_EDIT_INSTALL_BASE || ctlId == IDC_EDIT_FOLDER_NAME) &&
            notify == EN_CHANGE) {
            UpdateFolderExistsWarning(hDlg);
            return TRUE;
        }
        if (ctlId == IDC_BTN_TEST_DONGLE) {
            std::wstring u = GetText(hDlg, IDC_EDIT_DONGLE_USER);
            std::wstring p = GetText(hDlg, IDC_EDIT_DONGLE_PASS);
            HttpResult r = HttpRequest(HOST_DONGLE, PATH_DONGLE_CURRENT, u, p, /*head=*/true);
            std::wstring msg = (r.statusCode == 200)
                ? L"OK — dongle credentials accepted."
                : FormatHttpError(r, HOST_DONGLE);
            MessageBoxW(hDlg, msg.c_str(), L"Test dongle credentials",
                        MB_OK | (r.statusCode == 200 ? MB_ICONINFORMATION : MB_ICONWARNING));
            return TRUE;
        }
        if (ctlId == IDC_BTN_TEST_BYOD) {
            std::wstring u = GetText(hDlg, IDC_EDIT_BYOD_USER);
            std::wstring p = GetText(hDlg, IDC_EDIT_BYOD_PASS);
            HttpResult r = HttpRequest(HOST_BYOD, PATH_BYOD_CURRENT, u, p, /*head=*/true);
            std::wstring msg = (r.statusCode == 200)
                ? L"OK — BYOD credentials accepted."
                : FormatHttpError(r, HOST_BYOD);
            MessageBoxW(hDlg, msg.c_str(), L"Test BYOD credentials",
                        MB_OK | (r.statusCode == 200 ? MB_ICONINFORMATION : MB_ICONWARNING));
            return TRUE;
        }
        if (ctlId == IDC_BTN_REFRESH_VERSIONS) {
            bool isByod = GetCheck(hDlg, IDC_RADIO_BYOD);
            int userId = isByod ? IDC_EDIT_BYOD_USER : IDC_EDIT_DONGLE_USER;
            int passId = isByod ? IDC_EDIT_BYOD_PASS : IDC_EDIT_DONGLE_PASS;
            std::wstring u = GetText(hDlg, userId);
            std::wstring p = GetText(hDlg, passId);

            // Pre-flight: don't try to connect when there's nothing to send.
            if (u.empty() || p.empty()) {
                std::vector<int> toFlash;
                if (u.empty()) toFlash.push_back(userId);
                if (p.empty()) toFlash.push_back(passId);
                MessageBoxW(hDlg,
                    isByod
                      ? L"Please enter your BYOD username and password before refreshing the version list."
                      : L"Please enter your dongle username and password before refreshing the version list.",
                    L"Credentials needed", MB_OK | MB_ICONINFORMATION);
                StartFieldFlash(hDlg, ds, std::move(toFlash));
                return TRUE;
            }

            std::wstring err;
            HCURSOR oldCur = SetCursor(LoadCursor(nullptr, IDC_WAIT));
            ds->versions = RefreshVersions(isByod, u, p, err);
            SetCursor(oldCur);
            if (!err.empty()) {
                MessageBoxW(hDlg, err.c_str(), L"Refresh versions", MB_OK | MB_ICONWARNING);
                // If creds were rejected, flash the active set so the user
                // sees where to fix it.
                if (err.find(L"Invalid credentials") != std::wstring::npos) {
                    StartFieldFlash(hDlg, ds, { userId, passId });
                }
            } else {
                ds->refreshed = true;
            }
            PopulateVersionCombo(hDlg, ds, GetCheck(hDlg, IDC_CHK_INCLUDE_BETA), L"");
            UpdateDialogEnables(hDlg);  // re-evaluate copy_cfg gate for newly-selected version
            return TRUE;
        }

        if (ctlId == IDC_BTN_INSTALL || ctlId == IDOK) {
            // Validate / collect
            Settings& s = *ds->s;
            InstallMode m = GetInstallMode(hDlg);
            s.cfg.mode = ModeToCfgString(m);
            bool needMainApp = (m != InstallMode::ExtrasOnly);
            bool wantOptionals = (m != InstallMode::MainOnly);
            s.pickedDongle = GetCheck(hDlg, IDC_RADIO_DONGLE);
            s.cfg.licenseType = s.pickedDongle ? L"dongle" : L"byod";
            s.cfg.dongleUser = GetText(hDlg, IDC_EDIT_DONGLE_USER);
            s.cfg.donglePass = GetText(hDlg, IDC_EDIT_DONGLE_PASS);
            s.cfg.byodUser   = GetText(hDlg, IDC_EDIT_BYOD_USER);
            s.cfg.byodPass   = GetText(hDlg, IDC_EDIT_BYOD_PASS);
            // Derived: BYOD creds present means we can save them.
            s.cfg.hasByodCreds   = !s.cfg.byodUser.empty() && !s.cfg.byodPass.empty();
            s.cfg.installBase    = GetText(hDlg, IDC_EDIT_INSTALL_BASE);
            // Folder name is user-controlled and feeds JoinPath() and the
            // tar.exe command line. Sanitize: only allow filename-safe chars
            // (no separators, drive letters, quotes, shell metas, control
            // chars). Empty = OK = auto-name from detected version.
            std::wstring folderRaw = TrimW(GetText(hDlg, IDC_EDIT_FOLDER_NAME));
            s.folderNameOverride = SanitizeFolderName(folderRaw);
            if (!folderRaw.empty() && s.folderNameOverride.empty()) {
                MessageBoxW(hDlg,
                    L"The folder name contains characters that aren't allowed.\n\n"
                    L"Use only letters, digits, dot, underscore, dash, or space.\n"
                    L"Path separators, drive letters, quotes, and shell symbols are blocked.",
                    L"Bad folder name", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            s.cfg.includeBeta    = GetCheck(hDlg, IDC_CHK_INCLUDE_BETA);
            s.cfg.dlViewer       = GetCheck(hDlg, IDC_CHK_DL_VIEWER);
            s.cfg.dlTesseract    = GetCheck(hDlg, IDC_CHK_DL_TESSERACT);
            s.cfg.dlExcire       = GetCheck(hDlg, IDC_CHK_DL_EXCIRE);
            s.cfg.dlCondColoring = GetCheck(hDlg, IDC_CHK_DL_COND_COLORING);
            s.cfg.dlAFF4         = GetCheck(hDlg, IDC_CHK_DL_AFF4);
            s.cfg.copyCfg        = GetCheck(hDlg, IDC_CHK_COPY_CFG);
            s.cfg.copyHashDb     = GetCheck(hDlg, IDC_CHK_COPY_HASHDB);
            s.cfg.copyXtensions  = GetCheck(hDlg, IDC_CHK_COPY_XTENSIONS);
            s.cfg.createShortcut = GetCheck(hDlg, IDC_CHK_CREATE_SHORTCUT);
            s.cfg.shortcutAdmin  = true;        // always-on; no UI toggle anymore
            s.cfg.remember       = GetCheck(hDlg, IDC_CHK_REMEMBER_CREDS);

            // Pick filename from combo
            HWND combo = GetDlgItem(hDlg, IDC_COMBO_VERSION);
            int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
            LRESULT data = SendMessageW(combo, CB_GETITEMDATA, sel, 0);
            int  selMajor = 0, selMinor = 0;
            s.chosenIsBeta = false;
            if (data == (LRESULT)-1 || ds->versions.empty()) {
                // No refresh yet — use the canonical unversioned zip alias.
                s.chosenFilename = s.pickedDongle ? L"xw_forensics.zip" : L"xwb.zip";
                s.chosenLabel = L"Current (alias)";
            } else {
                int i = (int)data;
                if (i >= 0 && i < (int)ds->versions.size()) {
                    s.chosenFilename = ds->versions[i].filename;
                    s.chosenLabel    = ds->versions[i].displayLabel;
                    selMajor         = ds->versions[i].major;
                    selMinor         = ds->versions[i].minor;
                    s.chosenIsBeta   = ds->versions[i].isBeta;
                } else {
                    s.chosenFilename = s.pickedDongle ? L"xw_forensics.zip" : L"xwb.zip";
                    s.chosenLabel = L"Current (alias)";
                }
            }
            // If the selected version is older than the running install,
            // force-skip the cfg copy regardless of the (preserved) check
            // state. The dialog disables the box visually; this is the
            // belt-and-suspenders enforcement at install time.
            int runVer = ds->running.major * 100 + ds->running.minor * 10;
            int selVer = selMajor * 100 + selMinor * 10;
            if (runVer > 0 && selVer > 0 && selVer < runVer) {
                s.cfg.copyCfg = false;
            }

            // Sanity checks. Cred requirements follow the (mode, radio) matrix
            // in UpdateDialogEnables — only require what we'll actually send.
            bool dongleCredsNeeded = !(m == InstallMode::MainOnly && !s.pickedDongle);
            bool byodCredsNeeded   = needMainApp && !s.pickedDongle;
            if (dongleCredsNeeded && (s.cfg.dongleUser.empty() || s.cfg.donglePass.empty())) {
                MessageBoxW(hDlg,
                    L"Dongle credentials are required (used for resources, and for the dongle app).",
                    L"Missing credentials", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            if (byodCredsNeeded && (s.cfg.byodUser.empty() || s.cfg.byodPass.empty())) {
                MessageBoxW(hDlg,
                    L"BYOD radio is selected but the BYOD username/password are empty.",
                    L"Missing BYOD credentials", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            if (s.cfg.installBase.empty()) {
                MessageBoxW(hDlg, L"Install base directory is not set.",
                            L"Bad install base", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            if (!DirExists(s.cfg.installBase)) {
                std::wstring msg = L"Install base directory does not exist:\n\n";
                msg += s.cfg.installBase;
                msg += L"\n\nCreate it now?";
                int r = MessageBoxW(hDlg, msg.c_str(), L"Bad install base",
                                    MB_YESNO | MB_ICONQUESTION);
                if (r != IDYES) return TRUE;
                int rc = SHCreateDirectoryExW(hDlg, s.cfg.installBase.c_str(), nullptr);
                if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS && rc != ERROR_FILE_EXISTS) {
                    wchar_t buf[256];
                    swprintf_s(buf, L"Failed to create install base directory (Win32 error %d):\n\n%s",
                               rc, s.cfg.installBase.c_str());
                    MessageBoxW(hDlg, buf, L"Bad install base", MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                if (!DirExists(s.cfg.installBase)) {
                    MessageBoxW(hDlg, L"Install base directory could not be created.",
                                L"Bad install base", MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                UpdateFolderExistsWarning(hDlg);
            }
            // Extras-only mode needs at least one optional download checked.
            if (m == InstallMode::ExtrasOnly &&
                !s.cfg.dlViewer && !s.cfg.dlTesseract && !s.cfg.dlExcire &&
                !s.cfg.dlCondColoring && !s.cfg.dlAFF4) {
                MessageBoxW(hDlg, L"'Download tools only' is selected but nothing in 'Optional downloads' is checked.\n\nPick at least one item, or switch the mode checkbox.",
                            L"Nothing to download", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            (void)wantOptionals;  // RunInstall reads s.cfg.mode + dl_* flags directly.
            // Persist credentials now (before the long-running install) so a
            // crash partway through doesn't lose them.
            SaveCfg(s.cfg);
            // Lock dialog, show progress bar, and spawn the worker thread.
            // The worker posts WM_APP_PROGRESS / WM_APP_STATUS / WM_APP_DONE
            // back to this dialog as it runs.
            SetDialogBusy(hDlg, true);
            ds->workerActive = true;
            ds->workerErr.clear();
            ds->workerFinalDir.clear();
            g_progress.hDlg = hDlg;
            // Worker context lives until DlgWorkerThread tears it down.
            auto* wctx = new DlgWorkerCtx{ &s, ds };
            ds->hWorker = (HANDLE)_beginthreadex(nullptr, 0, DlgWorkerThread,
                                                 wctx, 0, nullptr);
            if (!ds->hWorker) {
                delete wctx;
                ds->workerActive = false;
                g_progress.hDlg = nullptr;
                SetDialogBusy(hDlg, false);
                MessageBoxW(hDlg, L"Failed to start the install worker thread.",
                            L"xways-updater", MB_OK | MB_ICONERROR);
            }
            return TRUE;
        }
        if (ctlId == IDCANCEL) {
            // Refuse close while the worker is mid-flight — the network +
            // shell-copy threads don't have a graceful cancel path. Once the
            // worker posts WM_APP_DONE the dialog re-enables Cancel and the
            // user can dismiss.
            if (ds->workerActive) return TRUE;
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        return FALSE;
    }

    // Progress bar tick — wp is permille (0..1000).
    case WM_APP + 1: {  // WM_APP_PROGRESS
        HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_INSTALL);
        SendMessageW(hProg, PBM_SETPOS, (WPARAM)(int)wp, 0);
        return TRUE;
    }
    // Status label update — lp is a heap-allocated wchar_t* (we own it).
    case WM_APP + 2: {  // WM_APP_STATUS
        wchar_t* text = (wchar_t*)lp;
        if (text) {
            SetDlgItemTextW(hDlg, IDC_LABEL_PROGRESS_STATUS, text);
            delete[] text;
        }
        return TRUE;
    }
    // Marquee toggle — wp = 1 starts marquee (indeterminate), 0 stops and
    // pins back to 100% determinate. Toggling the PBS_MARQUEE style at
    // runtime requires SetWindowLongPtr + PBM_SETMARQUEE.
    case WM_APP + 4: {  // WM_APP_MARQUEE
        HWND hProg = GetDlgItem(hDlg, IDC_PROGRESS_INSTALL);
        if (!hProg) return TRUE;
        LONG_PTR style = GetWindowLongPtrW(hProg, GWL_STYLE);
        if (wp) {
            SetWindowLongPtrW(hProg, GWL_STYLE, style | PBS_MARQUEE);
            SendMessageW(hProg, PBM_SETMARQUEE, TRUE, 30);
        } else {
            SendMessageW(hProg, PBM_SETMARQUEE, FALSE, 0);
            SetWindowLongPtrW(hProg, GWL_STYLE, style & ~PBS_MARQUEE);
            SendMessageW(hProg, PBM_SETPOS, 1000, 0);
        }
        return TRUE;
    }
    // Worker thread finished — wp = 1 on success, 0 on failure.
    case WM_APP + 3: {  // WM_APP_DONE
        if (!ds) return TRUE;
        // Wait for the thread to actually exit so we don't leak the handle.
        if (ds->hWorker) {
            WaitForSingleObject(ds->hWorker, INFINITE);
            CloseHandle(ds->hWorker);
            ds->hWorker = nullptr;
        }
        ds->workerActive = false;
        g_progress.hDlg = nullptr;
        Settings& s = *ds->s;
        if (wp) {
            // Success — show the summary, then ask whether to stay open for another run.
            std::wstring msg = L"xways-updater finished successfully.\n\n";
            if (s.cfg.mode == L"main_only") {
                msg += L"Saved zip: " + ds->workerFinalDir + L"\n\n"
                       L"Extract this zip yourself when ready to install.";
            } else if (s.cfg.mode == L"extras_only") {
                msg += L"Files saved to: " + ds->workerFinalDir;
            } else {
                msg += L"Install folder: " + ds->workerFinalDir;
            }
            msg += L"\n\nKeep this dialog open to download or install something else?\n"
                   L"(Yes = stay open, No = close)";
            int r = MessageBoxW(hDlg, msg.c_str(), L"xways-updater",
                                MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2);
            if (r == IDYES) {
                // Reset to idle so the user can change selections and click Install again.
                SetDialogBusy(hDlg, false);
            } else {
                s.okPressed = true;
                EndDialog(hDlg, IDOK);
            }
        } else {
            // Failure — leave the dialog open so the user can correct and retry.
            std::wstring m = L"Install failed:\n\n" + ds->workerErr;
            MessageBoxW(hDlg, m.c_str(), L"xways-updater", MB_OK | MB_ICONERROR);
            SetDialogBusy(hDlg, false);
        }
        return TRUE;
    }

    case WM_CLOSE:
        if (ds && ds->workerActive) return TRUE;  // refuse close mid-install
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// --- Refresh versions: GET index, parse <a href> ---------------------------
static std::vector<IndexEntry> RefreshVersions(bool isByod, const std::wstring& user,
                                               const std::wstring& pass, std::wstring& err)
{
    std::wstring host = isByod ? HOST_BYOD : HOST_DONGLE;
    std::wstring path = isByod ? PATH_BYOD_INDEX : PATH_DONGLE_INDEX;
    HttpResult r = HttpRequest(host, path, user, pass, /*head=*/false);
    if (r.statusCode != 200 || r.winhttpErr != 0) {
        err = FormatHttpError(r, host);
        return {};
    }
    std::string body((const char*)r.body.data(), r.body.size());
    std::vector<IndexEntry> all = ParseAppIndex(body, isByod);

    // Supported floor: major >= 21. Older versions had quirks (no readme in
    // the dongle zip, fixed-offset resource layouts with NUL padding, no
    // session banner under Override:1 when the dongle is absent) that aren't
    // worth carrying. Drop pre-21 entries from the dropdown so the user can't
    // accidentally pick an unsupported one.
    std::vector<IndexEntry> filtered;
    filtered.reserve(all.size());
    for (auto& e : all) {
        if (e.major >= 21) filtered.push_back(std::move(e));
    }
    return filtered;
}

// --- Download orchestrator --------------------------------------------------
// Verify the install base is writable by creating then auto-deleting a tiny
// scratch file. Catches permission/read-only-volume issues *before* we burn
// minutes on a multi-hundred-MB download.
static bool ProbeWritable(const std::wstring& dir, std::wstring& err) {
    if (!DirExists(dir)) {
        err = L"directory does not exist: " + dir;
        return false;
    }
    wchar_t name[MAX_PATH];
    swprintf_s(name, L"%s\\xways-updater-probe-%lu.tmp",
               dir.c_str(), GetCurrentProcessId());
    HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        wchar_t b[256];
        swprintf_s(b, L"cannot write to '%s' (Win32 error %lu — try running X-Ways elevated, or pick a different install base)",
                   dir.c_str(), e);
        err = b;
        return false;
    }
    BYTE byte = 0xAB;
    DWORD written = 0;
    if (!WriteFile(h, &byte, 1, &written, nullptr) || written != 1) {
        DWORD e = GetLastError();
        wchar_t b[256];
        swprintf_s(b, L"write to '%s' failed (Win32 error %lu — disk full or quota exceeded?)",
                   dir.c_str(), e);
        err = b;
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);  // FILE_FLAG_DELETE_ON_CLOSE removes the file
    return true;
}

// Free bytes available to the *calling user* on the volume containing `dir`.
// Returns 0 on failure (caller should treat as "unknown" rather than zero).
static uint64_t GetFreeBytes(const std::wstring& dir) {
    ULARGE_INTEGER avail{};
    if (!GetDiskFreeSpaceExW(dir.c_str(), &avail, nullptr, nullptr)) return 0;
    return avail.QuadPart;
}

// HEAD a URL and return its Content-Length (0 on failure or missing header).
static uint64_t HeadContentLength(const std::wstring& url,
                                  const std::wstring& user, const std::wstring& pass)
{
    std::wstring host, path;
    if (!ParseUrl(url, host, path).empty()) return 0;
    HttpResult r = HttpRequest(host, path, user, pass, /*head=*/true);
    if (r.statusCode != 200) return 0;
    return r.contentLength;
}

static std::wstring TempDirForJob() {
    wchar_t buf[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, buf);
    std::wstring p = buf;
    wchar_t suffix[64];
    swprintf_s(suffix, L"xways-updater_%lu", GetCurrentProcessId());
    p = JoinPath(p, suffix);
    CreateDirectoryW(p.c_str(), nullptr);
    return p;
}

static bool RemoveTreeBestEffort(const std::wstring& dir) {
    std::wstring from = dir; from.push_back(L'\0'); from.push_back(L'\0');
    SHFILEOPSTRUCTW op{};
    op.wFunc  = FO_DELETE;
    op.pFrom  = from.c_str();
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    return SHFileOperationW(&op) == 0;
}

// RAII guard so we always clean up the temp dir on the way out of RunInstall,
// including failure paths. Set `disarm = true` if the caller wants to keep the
// dir for post-mortem inspection.
struct TempDirGuard {
    std::wstring path;
    bool         disarm = false;
    explicit TempDirGuard(std::wstring p) : path(std::move(p)) {}
    ~TempDirGuard() { if (!disarm && !path.empty()) RemoveTreeBestEffort(path); }
    TempDirGuard(const TempDirGuard&) = delete;
    TempDirGuard& operator=(const TempDirGuard&) = delete;
};

// Debug switch — when true, every TempDirGuard skips its cleanup so the
// temp dir survives for inspection. Set to true while iterating on
// detection logic; should be false in shipped builds.
static constexpr bool KEEP_TEMP_DIR = false;

// Defensive Mark-of-the-Web strip. The Zone.Identifier alternate data stream
// is what triggers Windows' "blocked DLL" behavior on extracted files. Our
// flow (WinHTTP download + tar.exe extract) shouldn't produce MOTW, but if a
// future change swaps in a different downloader/extractor that does, this
// keeps X-Ways' DLLs loadable.
static void StripMOTW(const std::wstring& filePath) {
    std::wstring zid = filePath + L":Zone.Identifier";
    DeleteFileW(zid.c_str());
}
static void StripMOTWRecursive(const std::wstring& dir) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = JoinPath(dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            StripMOTWRecursive(full);
        } else {
            StripMOTW(full);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static bool DownloadUrl(const std::wstring& url, const std::wstring& user,
                        const std::wstring& pass, const std::wstring& outFile,
                        const std::wstring& label, std::wstring& err)
{
    std::wstring host, path;
    std::wstring perr = ParseUrl(url, host, path);
    if (!perr.empty()) { err = perr; return false; }
    uint64_t lastBarBytes = 0;
    HttpResult r = HttpRequest(host, path, user, pass, /*head=*/false, outFile,
                               [&](uint64_t got, uint64_t total){
        // In-dialog progress bar: post at most once per 256 KB so we don't
        // flood the message queue, but always post the final (100%) tick so
        // the bar visibly fills before the file's done. Cumulative bytes feed
        // into the overall percent across all files in the install batch.
        if (g_progress.active) {
            constexpr uint64_t kBarStep = 256 * 1024;
            bool atEnd = (total > 0 && got >= total);
            if (got - lastBarBytes >= kBarStep || atEnd) {
                lastBarBytes = got;
                ProgressPostPercent(g_progress.cumulativeBefore + got);
            }
        }
        return true;
    });
    if (!r.error.empty()) { err = r.error; return false; }
    if (r.statusCode == 401) { err = L"401 Unauthorized: " + url; return false; }
    if (r.statusCode != 200) { wchar_t b[80]; swprintf_s(b, L"HTTP %lu fetching ", r.statusCode); err = std::wstring(b) + url; return false; }
    // Hash the saved file so the analyst has a verifiable record of exactly
    // what we pulled from x-ways.net (zip OR loose file).
    if (!outFile.empty()) {
        std::wstring sha = Sha256File(outFile);
        if (!sha.empty()) Log(L"   SHA256 " + label + L": " + sha);
    }
    return true;
}

// Wrap DownloadUrl with up to 3 attempts and exponential backoff (2s/4s).
// Skips retry for non-transient failures (auth or server-rejection codes
// that won't change on a retry). Each attempt overwrites the partial file
// (CREATE_ALWAYS in HttpRequest) so we don't accumulate stale bytes.
static bool DownloadUrlWithRetry(const std::wstring& url, const std::wstring& user,
                                 const std::wstring& pass, const std::wstring& outFile,
                                 const std::wstring& label, std::wstring& err)
{
    constexpr int kMaxAttempts = 3;
    std::wstring localErr;
    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        localErr.clear();
        if (DownloadUrl(url, user, pass, outFile, label, localErr)) return true;
        // Don't retry hard auth/server failures.
        if (localErr.find(L"401 Unauthorized") != std::wstring::npos ||
            localErr.find(L"HTTP 403")          != std::wstring::npos ||
            localErr.find(L"HTTP 404")          != std::wstring::npos) {
            err = localErr;
            return false;
        }
        if (attempt < kMaxAttempts) {
            DWORD waitMs = 2000u * attempt;
            wchar_t b[256];
            swprintf_s(b, L"  %s: attempt %d failed (%s) — retrying in %lus...",
                       label.c_str(), attempt, localErr.c_str(), waitMs / 1000);
            Log(b);
            Sleep(waitMs);
        }
    }
    err = localErr;
    return false;
}

// Execute the install. Return true on success.
// Extras-only flow: skip main app download/extract/version-detect; just pull
// the selected optional resources into <base>\<folderName>. Matches the
// half-checked tri-state in the dialog.
static bool RunExtrasOnly(Settings& s, std::wstring& finalInstallDir, std::wstring& err) {
    std::wstring base = s.cfg.installBase;
    std::wstring resUser = s.cfg.dongleUser, resPass = s.cfg.donglePass;

    // Pre-flight checks before we do anything expensive.
    if (!ProbeWritable(base, err)) return false;

    // Sum expected zip sizes via HEAD requests so we can compare against free
    // disk space and bail early if there's clearly not enough room.
    Log(L"Pre-flight: checking free space against expected download sizes...");
    uint64_t expectedZip = 0;
    auto addSize = [&](const wchar_t* url) {
        uint64_t n = HeadContentLength(url, resUser, resPass);
        if (n > 0) expectedZip += n;
    };
    if (s.cfg.dlViewer)       addSize(URL_VIEWER);
    if (s.cfg.dlTesseract)    addSize(URL_TESSERACT);
    if (s.cfg.dlExcire)       addSize(URL_EXCIRE);
    if (s.cfg.dlAFF4)         addSize(URL_AFF4);
    if (s.cfg.dlCondColoring) addSize(URL_COND_COLORING);
    // Reserve 3x expected zip size: download + extracted (~2x) staging.
    uint64_t reserved = expectedZip * 3;
    uint64_t freeBytes = GetFreeBytes(base);
    if (expectedZip > 0 && freeBytes > 0 && freeBytes < reserved) {
        wchar_t b[300];
        swprintf_s(b, L"low disk space: need ~%.1f GB on '%s', have %.1f GB. Free up space, pick a different install base, or uncheck some optional items.",
                   reserved / 1073741824.0, base.c_str(), freeBytes / 1073741824.0);
        err = b;
        return false;
    }
    if (expectedZip > 0) {
        wchar_t b[200];
        swprintf_s(b, L"  expected download ~%.1f MB; free space on target volume ~%.1f GB.",
                   expectedZip / 1048576.0, freeBytes / 1073741824.0);
        Log(b);
    }
    ProgressGuard pguard;
    pguard.arm(expectedZip);

    // Tools-only mode drops files DIRECTLY into the download base — no
    // subfolder, no rename. If a file with the same name already exists,
    // UniqueFilePath inserts -2 / -3 / ... before the extension so the
    // download lands without overwriting.
    finalInstallDir = base;  // surfaced in the success message
    Log(L"[1/2] Tools-only download to: " + base);

    std::wstring tempDir = TempDirForJob();
    TempDirGuard tempGuard(tempDir);
    if (KEEP_TEMP_DIR) {
        tempGuard.disarm = true;
        Log(L"  *** KEEP_TEMP_DIR=true — temp dir will NOT be cleaned: " + tempDir);
    }

    auto downloadOnly = [&](const wchar_t* url) {
        std::wstring urls = url;
        size_t slash = urls.find_last_of(L'/');
        std::wstring fname = (slash != std::wstring::npos) ? urls.substr(slash + 1) : urls;
        // Resource URLs are percent-encoded ("Conditional%20Coloring.cfg"); the
        // *file* on disk should be the human-readable form.
        fname = UrlDecode(fname);
        std::wstring dst = UniqueFilePath(base, fname);
        if (dst.empty()) {
            Log(std::wstring(L"    ") + fname + L": too many existing copies in destination — skipping.");
            return;
        }
        ProgressSetStatus(fname);
        Log(std::wstring(L"  Downloading ") + fname + L"...");
        std::wstring derr;
        if (!DownloadUrlWithRetry(url, resUser, resPass, dst, fname, derr)) {
            Log(std::wstring(L"    ") + fname + L" download failed: " + derr);
            return;
        }
        Log(L"    saved: " + dst);
        ProgressFileDone(dst);
    };
    Log(L"[2/2] Pulling selected tools (archives kept as-is, not extracted)...");
    if (s.cfg.dlViewer)       downloadOnly(URL_VIEWER);
    if (s.cfg.dlTesseract)    downloadOnly(URL_TESSERACT);
    if (s.cfg.dlExcire)       downloadOnly(URL_EXCIRE);
    if (s.cfg.dlAFF4)         downloadOnly(URL_AFF4);
    if (s.cfg.dlCondColoring) downloadOnly(URL_COND_COLORING);
    ProgressPostPercent(g_progress.totalExpected);  // pin to 100%
    return true;
}

static bool RunInstall(Settings& s, std::wstring& finalInstallDir, std::wstring& err) {
    // Branch on mode — extras-only takes a much simpler path.
    if (s.cfg.mode == L"extras_only") return RunExtrasOnly(s, finalInstallDir, err);

    std::wstring base = s.cfg.installBase;
    bool isByod = !s.pickedDongle;

    // Pick app credentials (BYOD if user picked BYOD AND has BYOD creds set)
    std::wstring appUser, appPass;
    if (isByod && s.cfg.hasByodCreds && !s.cfg.byodUser.empty()) {
        appUser = s.cfg.byodUser; appPass = s.cfg.byodPass;
    } else {
        appUser = s.cfg.dongleUser; appPass = s.cfg.donglePass;
    }
    // Resources always use dongle creds.
    std::wstring resUser = s.cfg.dongleUser, resPass = s.cfg.donglePass;

    // Pre-flight checks before we burn time on a multi-hundred-MB download.
    if (!ProbeWritable(s.cfg.installBase, err)) return false;

    bool wantOptionals = (s.cfg.mode != L"main_only");
    std::wstring appUrl;
    if (isByod) appUrl = std::wstring(L"https://") + HOST_BYOD + L"/xwb/" + s.chosenFilename;
    else        appUrl = std::wstring(L"https://") + HOST_DONGLE + L"/xwf/" + s.chosenFilename;

    // Sum expected zip sizes via HEAD so we can compare against free disk.
    Log(L"Pre-flight: checking free space against expected download sizes...");
    uint64_t expectedZip = 0;
    {
        uint64_t n = HeadContentLength(appUrl, appUser, appPass);
        if (n > 0) expectedZip += n;
    }
    if (wantOptionals) {
        auto addSize = [&](const wchar_t* url) {
            uint64_t n = HeadContentLength(url, resUser, resPass);
            if (n > 0) expectedZip += n;
        };
        if (s.cfg.dlViewer)       addSize(URL_VIEWER);
        if (s.cfg.dlTesseract)    addSize(URL_TESSERACT);
        if (s.cfg.dlExcire)       addSize(URL_EXCIRE);
        if (s.cfg.dlAFF4)         addSize(URL_AFF4);
        if (s.cfg.dlCondColoring) addSize(URL_COND_COLORING);
    }
    // Reserve 3x expected zip size: zip + extracted (~2x) staging. tar.exe
    // moves rather than re-copies into the final folder, so the doubling
    // estimate covers the worst-case extracted size.
    uint64_t reserved = expectedZip * 3;
    uint64_t freeBytes = GetFreeBytes(s.cfg.installBase);
    if (expectedZip > 0 && freeBytes > 0 && freeBytes < reserved) {
        wchar_t b[300];
        swprintf_s(b, L"low disk space: need ~%.1f GB on '%s', have %.1f GB. Free up space, pick a different install base, or uncheck some optional items.",
                   reserved / 1073741824.0, s.cfg.installBase.c_str(), freeBytes / 1073741824.0);
        err = b;
        return false;
    }
    if (expectedZip > 0) {
        wchar_t b[200];
        swprintf_s(b, L"  expected download ~%.1f MB; free space on target volume ~%.1f GB.",
                   expectedZip / 1048576.0, freeBytes / 1073741824.0);
        Log(b);
    }
    ProgressGuard pguard;
    pguard.arm(expectedZip);

    std::wstring tempDir = TempDirForJob();
    TempDirGuard tempGuard(tempDir);  // RAII: cleaned up on every return path
    if (KEEP_TEMP_DIR) {
        tempGuard.disarm = true;
        Log(L"  *** KEEP_TEMP_DIR=true — temp dir will NOT be cleaned: " + tempDir);
    }
    std::wstring zipPath = JoinPath(tempDir, s.chosenFilename);

    ProgressSetStatus(s.chosenFilename);
    Log(L"[1/4] Downloading main app: " + s.chosenFilename);
    Log(L"      from " + appUrl);
    if (!DownloadUrlWithRetry(appUrl, appUser, appPass, zipPath, s.chosenFilename, err)) return false;
    Log(L"      saved to " + zipPath);
    ProgressFileDone(zipPath);

    // App-only mode short-circuit: we never extract or install in this mode,
    // so skip extract + locate-exe + version-detect entirely. Drop the zip
    // straight into the download base with a collision-avoiding suffix on
    // the filename and we're done.
    if (s.cfg.mode == L"main_only") {
        std::wstring zipDst = UniqueFilePath(base, s.chosenFilename);
        if (zipDst.empty()) {
            err = L"too many existing copies of " + s.chosenFilename + L" in destination — clean up and retry";
            return false;
        }
        ProgressSetStatus(s.chosenFilename);
        Log(L"[2/2] App-only mode: placing zip directly in download location");
        Log(L"      target: " + zipDst);
        if (!MoveFileW(zipPath.c_str(), zipDst.c_str())) {
            // Cross-volume fallback.
            if (!CopyFileW(zipPath.c_str(), zipDst.c_str(), /*failIfExists=*/FALSE)) {
                err = L"failed to move/copy zip to destination";
                return false;
            }
        }
        Log(L"      Done. Extract this zip yourself when ready to install.");
        finalInstallDir = zipDst;  // surfaced in the success message
        ProgressPostPercent(g_progress.totalExpected);  // pin to 100%
        return true;
    }

    // Stage extraction in a temp subfolder so we can detect the version
    // before naming the final folder.
    std::wstring stageDir = JoinPath(tempDir, L"stage");
    ProgressSetStatus(L"Extracting " + s.chosenFilename);
    Log(L"[2/4] Extracting " + s.chosenFilename + L" -> " + stageDir);
    if (!ExtractZip(zipPath, stageDir, err)) return false;
    Log(L"      extracted.");

    // Locate the main exe in the staged tree.
    std::wstring mainExeName = isByod ? L"xwb64.exe" : L"xwforensics64.exe";
    std::wstring mainExe = JoinPath(stageDir, mainExeName);
    if (!FileExists(mainExe)) {
        // Some builds wrap contents in a top-level folder; try one level deeper.
        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW((stageDir + L"\\*").c_str(), &fd);
        bool found = false;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
                    std::wstring cand = JoinPath(JoinPath(stageDir, fd.cFileName), mainExeName);
                    if (FileExists(cand)) { mainExe = cand; stageDir = JoinPath(stageDir, fd.cFileName); found = true; break; }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        if (!found) {
            err = L"main exe not found in extracted zip: " + mainExeName;
            return false;
        }
    }

    // Decide final folder name.
    std::wstring folderName;
    if (!s.folderNameOverride.empty()) {
        folderName = s.folderNameOverride;
    } else {
        VerInfo v = ReadFileVersion(mainExe);
        const wchar_t* srSource = v.haveSr ? L"VERSIONINFO" : nullptr;
        // Fallback 1: scan readme files in the extracted root (e.g. !readme.txt).
        if (!v.haveSr) {
            int srFromReadme = FindSRInTextFiles(stageDir);
            if (srFromReadme > 0) { v.sr = srFromReadme; v.haveSr = true; srSource = L"readme"; }
        }
        // Fallback 2: scan the .exe's bytes directly. The Help → About dialog
        // text is baked in as a literal "21.7 SR-N" string somewhere in the
        // binary — most reliable when VERSIONINFO and readme don't expose it.
        if (!v.haveSr && v.major > 0) {
            int srFromBinary = ScanBinaryForSR(mainExe, v.major, v.minor);
            if (srFromBinary > 0) { v.sr = srFromBinary; v.haveSr = true; srSource = L"binary scan"; }
        }
        // Fallback 3: launch the staged binary with `Override:1` and parse
        // the session-start banner X-Ways writes to msglog.txt. Slow
        // (~6s — the second instance self-exits then) and side-effecty
        // (creates msglog.txt in the staging dir, which gets carried
        // along with the move into the final install dir) but reads
        // X-Ways' own runtime version string — the most authoritative
        // source. See [docs/xways-command-line.md] "Empirical findings"
        // for why Override:1 alone (no GetLicID:).
        //
        // Beta builds frequently ship with stale VERSIONINFO (a 21.8 beta may
        // still report FileVersion=21.7), so the banner is also our source
        // of truth for major/minor when present. We let it override v.major/
        // v.minor unconditionally.
        if ((!v.haveSr || s.chosenIsBeta) && v.major > 0) {
            Log(L"Detection: launching staged binary with Override:1 for the msglog banner...");
            BannerInfo b = GetBannerViaGetLicID(mainExe);
            if (b.ok) {
                if (b.major > 0) { v.major = b.major; v.minor = b.minor; }
                if (b.sr > 0)      { v.sr = b.sr; v.haveSr = true; srSource = L"msglog banner"; }
                if (b.betaNum > 0) { v.betaNum = b.betaNum; v.haveBeta = true; srSource = L"msglog banner (beta)"; }
            }
        }
        if (v.major == 0 && v.minor == 0) {
            wchar_t b[64]; swprintf_s(b, L"xwf_unknown_%lu", GetTickCount());
            folderName = b;
        } else {
            folderName = BuildAutoFolderName(v, isByod, s.chosenIsBeta);
        }
        wchar_t info[256];
        if (v.haveBeta) swprintf_s(info, L"Detected version: %d.%d Beta %d  (source: %s; raw VERSIONINFO: %s)",
                                   v.major, v.minor, v.betaNum, srSource, v.rawString.c_str());
        else if (v.haveSr) swprintf_s(info, L"Detected version: %d.%d SR-%d  (source: %s; raw VERSIONINFO: %s)",
                                      v.major, v.minor, v.sr, srSource, v.rawString.c_str());
        else            swprintf_s(info, L"Detected version: %d.%d  (no SR or Beta number found in VERSIONINFO, readme, binary scan, or msglog banner; raw: %s)",
                                   v.major, v.minor, v.rawString.c_str());
        Log(info);

    }

    finalInstallDir = JoinPath(base, folderName);
    if (!DestinationIsUnderBase(base, finalInstallDir)) {
        err = L"destination resolves outside the install base — refusing to extract: " + finalInstallDir;
        return false;
    }

    // Same-version guard — fires only when the proposed destination is
    // literally the running install's folder AND the staged version matches.
    // Earlier, this guard fired on any same-version install regardless of
    // path — that was overzealous: a fresh install in a new folder (e.g.
    // "C:\xwfb\xwb21-7sr3" alongside a running install at
    // "C:\Users\...\xwb217") is intentional, not a duplicate. The auto-name
    // collision suffix handles the "destination folder already exists" case
    // separately (see further down). What's left for this guard to catch is
    // the literal overwrite case: user about to install on top of the
    // currently-running X-Ways. Different folder => no prompt.
    //
    // Skip also when the user explicitly picked a beta: a beta is by
    // definition not the same build as a stable install, and re-running
    // the msglog fallback here just to disambiguate is wasteful (~6s).
    // Re-deriving from VERSIONINFO alone would also be unreliable since
    // beta builds can ship with stale FileVersion strings.
    if (s.folderNameOverride.empty() && !s.chosenIsBeta) {
        const RunningInstall& run = s.running;
        bool willClobber = !run.installDir.empty() &&
                           _wcsicmp(finalInstallDir.c_str(), run.installDir.c_str()) == 0;
        VerInfo vCheck;
        bool sameVer = false;
        if (willClobber) {
            vCheck = ReadFileVersion(mainExe);
            if (!vCheck.haveSr) {
                int srFromBinary = ScanBinaryForSR(mainExe, vCheck.major, vCheck.minor);
                if (srFromBinary > 0) { vCheck.sr = srFromBinary; vCheck.haveSr = true; }
            }
            bool sameProduct = (run.isByod == !s.pickedDongle);
            sameVer = sameProduct && run.major > 0 &&
                      run.major == vCheck.major && run.minor == vCheck.minor &&
                      run.haveSr == vCheck.haveSr &&
                      (!vCheck.haveSr || run.sr == vCheck.sr);
        }
        if (sameVer) {
            std::wstring summary = FormatRunningSummary(run);
            // Strip the leading "Detected current install: " prefix for cleaner text.
            const wchar_t* prefix = L"Detected current install: ";
            if (summary.rfind(prefix, 0) == 0) summary = summary.substr(wcslen(prefix));
            std::wstring prompt =
                L"You appear to already have this exact version installed:\n\n"
                L"   " + summary +
                L"\n   at: " + run.installDir +
                L"\n\nThe download is the same version. Install anyway to:\n\n"
                L"   " + finalInstallDir +
                L"\n\nYes = proceed (a second copy in a different folder).\n"
                L"No = cancel; pick a different version or folder name in the dialog.";
            int rc = MessageBoxW(g_hMainWnd, prompt.c_str(), L"xways-updater — same version detected",
                                 MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
            if (rc != IDYES) {
                err = L"cancelled — same version as currently running install";
                return false;
            }
        }
    }

    // If the auto-name collided (a previous failed run left a folder behind,
    // or SR detection couldn't disambiguate same major.minor across runs),
    // try numeric suffixes (-2, -3, ...). Only applies when the user is
    // letting us auto-name; if they typed a folder name, fail loudly so
    // they can pick something else themselves.
    if (DirExists(finalInstallDir) && s.folderNameOverride.empty()) {
        for (int i = 2; i < 100; ++i) {
            wchar_t suffix[16];
            swprintf_s(suffix, L"-%d", i);
            std::wstring candidate = JoinPath(base, folderName + suffix);
            if (!DirExists(candidate)) {
                Log(L"Auto-name '" + folderName + L"' collided; using '" + folderName + suffix + L"' instead.");
                folderName += suffix;
                finalInstallDir = candidate;
                break;
            }
        }
    }

    Log(L"[3/4] Install destination: " + finalInstallDir);
    if (DirExists(finalInstallDir)) {
        err = L"destination already exists: " + finalInstallDir + L"\nPick a different folder name.";
        return false;
    }

    // Full mode: move staged files into the final destination.
    // (App-only mode short-circuited earlier in this function.)
    Log(L"      moving staged files into destination...");
    if (!MoveFileW(stageDir.c_str(), finalInstallDir.c_str())) {
        // Cross-volume move failed; fall back to copy-then-delete.
        Log(L"      cross-volume; copying instead...");
        if (!CopyTreeShellApi(stageDir, finalInstallDir)) {
            err = L"failed to move/copy staged install to destination";
            return false;
        }
        RemoveTreeBestEffort(stageDir);
    }
    Log(L"      done.");

    // Optional resource downloads — extract into the new install folder so
    // each one ends up alongside the main exe (matches XWFIM behavior).
    Log(L"[4/4] Extras + post-install...");
    auto downloadAndExtract = [&](const wchar_t* url, const wchar_t* label,
                                  const std::wstring& destDir) -> bool {
        std::wstring urls = url;
        size_t slash = urls.find_last_of(L'/');
        std::wstring fname = (slash != std::wstring::npos) ? urls.substr(slash + 1) : urls;
        fname = UrlDecode(fname);
        std::wstring zip = JoinPath(tempDir, std::wstring(label) + L".zip");
        ProgressSetStatus(fname);
        Log(std::wstring(L"  Downloading ") + label + L" (" + fname + L")...");
        std::wstring derr;
        if (!DownloadUrlWithRetry(url, resUser, resPass, zip, fname, derr)) {
            Log(std::wstring(L"    ") + label + L" download failed: " + derr);
            return false;
        }
        ProgressFileDone(zip);
        Log(std::wstring(L"  Extracting ") + label + L" -> " + destDir);
        std::wstring eerr;
        if (!ExtractZip(zip, destDir, eerr)) {
            Log(std::wstring(L"    ") + label + L" extract failed: " + eerr);
            return false;
        }
        Log(std::wstring(L"  ") + label + L": done.");
        return true;
    };
    // main_only mode: skip ALL optional downloads regardless of the per-item
    // checkboxes. The checkboxes are also disabled in the UI; this is a
    // belt-and-suspenders guard against a stale cfg. (wantOptionals already
    // declared at the top of the function for the pre-flight size check.)
    if (wantOptionals) {
        if (s.cfg.dlViewer)    downloadAndExtract(URL_VIEWER,    L"Viewer",    finalInstallDir);
        if (s.cfg.dlTesseract) downloadAndExtract(URL_TESSERACT, L"Tesseract", finalInstallDir);
        if (s.cfg.dlExcire)    downloadAndExtract(URL_EXCIRE,    L"Excire",    finalInstallDir);
        if (s.cfg.dlAFF4) {
            // AFF4 ships as four DLLs that X-Ways looks for in fixed
            // locations under the install root:
            //   <install>\ImageIOAFF4.dll     (32-bit, paired with xwforensics.exe)
            //   <install>\libaff4lite.dll     (32-bit dependency)
            //   <install>\x64\ImageIOAFF4.dll (64-bit, paired with xwforensics64.exe)
            //   <install>\x64\libaff4lite.dll (64-bit dependency)
            // The DLLs must NOT live under xtensions\... — X-Ways resolves
            // ImageIOAFF4.dll by GetModuleFileName(NULL) + dirname (plus x64\
            // for the 64-bit build), not from the xtensions auto-load path.
            //
            // Extract to a scratch dir, then merge the tree into the install
            // dir. Handles both flat zips (DLLs at zip root + x64\ subdir)
            // and wrapped zips (everything inside a top-level aff4-xways-N/
            // folder).
            std::wstring aff4Scratch = JoinPath(tempDir, L"aff4-stage");
            if (downloadAndExtract(URL_AFF4, L"AFF4", aff4Scratch)) {
                std::wstring aff4Root = aff4Scratch;
                bool foundRoot = FileExists(JoinPath(aff4Root, L"ImageIOAFF4.dll"))
                              || DirExists (JoinPath(aff4Root, L"x64"));
                if (!foundRoot) {
                    // Try one level deeper for wrapped zips.
                    WIN32_FIND_DATAW fd{};
                    HANDLE hF = FindFirstFileW((aff4Root + L"\\*").c_str(), &fd);
                    if (hF != INVALID_HANDLE_VALUE) {
                        do {
                            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                            std::wstring cand = JoinPath(aff4Root, fd.cFileName);
                            if (FileExists(JoinPath(cand, L"ImageIOAFF4.dll"))
                                || DirExists(JoinPath(cand, L"x64"))) {
                                aff4Root = cand;
                                foundRoot = true;
                                break;
                            }
                        } while (FindNextFileW(hF, &fd));
                        FindClose(hF);
                    }
                }
                if (!foundRoot) {
                    Log(L"    AFF4: couldn't locate ImageIOAFF4.dll/x64 in extracted zip; skipping deploy.");
                } else {
                    Log(L"  AFF4: deploying to install root + x64\\ subdir...");
                    if (MergeTreeContents(aff4Root, finalInstallDir)) {
                        Log(L"    AFF4: done.");
                    } else {
                        Log(L"    AFF4: one or more files failed to copy.");
                    }
                }
            }
        }
    } else {
        Log(L"  Mode = main app only; skipping optional downloads.");
    }

    // Conditional Coloring.cfg (single file, no extraction). Independent
    // of copy_cfg — when both are on, this download wins because the .cfg
    // copy loop below skips Conditional Coloring.cfg.
    if (wantOptionals && s.cfg.dlCondColoring) {
        std::wstring dst = JoinPath(finalInstallDir, L"Conditional Coloring.cfg");
        ProgressSetStatus(L"Conditional Coloring.cfg");
        Log(L"  Downloading Conditional Coloring.cfg...");
        std::wstring derr;
        if (!DownloadUrlWithRetry(URL_COND_COLORING, resUser, resPass, dst, L"Conditional Coloring.cfg", derr)) {
            Log(L"    Conditional Coloring download failed: " + derr);
        } else {
            Log(L"    saved: " + dst);
            ProgressFileDone(dst);
        }
    }

    // All byte-tracked work (downloads) is done; the rest of the install
    // (copy configs, hash DBs, xtensions folder, shortcut, MOTW strip) has
    // no per-byte signal we can feed into the bar. Switch to marquee so the
    // bar visibly keeps moving while we work — without this it appears to
    // freeze for several seconds while SHFileOperationW copies finish.
    ProgressBeginMarquee(L"Finalizing install...");

    // Copy custom configs from the current install. Two policies:
    //   - cfg + investigator.ini + Passwords.txt + Programs.txt: OVERWRITE —
    //     these are the user's saved state and should win over upstream
    //     defaults.
    //   - *.tpl (hex-editor templates): KEEP UPSTREAM — the new install ships
    //     fresh upstream templates; only fill in templates that don't already
    //     exist in the destination (custom user templates carry forward).
    //
    // X-Tensions.txt is intentionally NOT copied: its absolute DLL paths
    // would reference the old install. Re-add via Tools -> Run X-Tensions
    // in the new install. The tooltip on the checkbox spells this out.
    std::wstring curInstall = GetXWaysInstallDir();
    if (s.cfg.copyCfg && DirExists(curInstall) &&
        _wcsicmp(curInstall.c_str(), finalInstallDir.c_str()) != 0) {
        Log(L"  Copying custom configs from current install: " + curInstall);
        for (const wchar_t* name : { L"investigator.ini", L"Passwords.txt", L"Programs.txt" }) {
            std::wstring src = JoinPath(curInstall, name);
            if (!FileExists(src)) continue;
            std::wstring dst = JoinPath(finalInstallDir, name);
            if (CopyFileW(src.c_str(), dst.c_str(), /*failIfExists=*/FALSE)) {
                Log(std::wstring(L"    copied: ") + name);
            } else {
                Log(std::wstring(L"    copy failed: ") + name);
            }
        }
        // *.cfg + *.dlg — overwrite (user's settings / saved dialog
        // selections win over upstream defaults; *.dlg files are written
        // by the "save dialog selection" feature, see xways-command-line.md
        // section on Dlg: parameter).
        for (const wchar_t* glob : { L"*.cfg", L"*.dlg" }) {
            WIN32_FIND_DATAW fd{};
            std::wstring pat = JoinPath(curInstall, glob);
            HANDLE h = FindFirstFileW(pat.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring src = JoinPath(curInstall, fd.cFileName);
                std::wstring dst = JoinPath(finalInstallDir, fd.cFileName);
                if (!CopyFileW(src.c_str(), dst.c_str(), /*failIfExists=*/FALSE)) {
                    Log(std::wstring(L"    copy failed: ") + fd.cFileName);
                } else {
                    Log(std::wstring(L"    copied: ") + fd.cFileName);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        // *.tpl — keep upstream (failIfExists=TRUE skips templates already in
        // the new install). Custom templates in the current install carry
        // forward; upstream-default templates aren't clobbered.
        WIN32_FIND_DATAW fdT{};
        std::wstring patTpl = JoinPath(curInstall, L"*.tpl");
        HANDLE hT = FindFirstFileW(patTpl.c_str(), &fdT);
        if (hT != INVALID_HANDLE_VALUE) {
            do {
                if (fdT.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring src = JoinPath(curInstall, fdT.cFileName);
                std::wstring dst = JoinPath(finalInstallDir, fdT.cFileName);
                if (CopyFileW(src.c_str(), dst.c_str(), /*failIfExists=*/TRUE)) {
                    Log(std::wstring(L"    copied tpl: ") + fdT.cFileName);
                } else if (GetLastError() == ERROR_FILE_EXISTS) {
                    LogVerbose(std::wstring(L"    tpl exists upstream, kept: ") + fdT.cFileName);
                } else {
                    Log(std::wstring(L"    tpl copy failed: ") + fdT.cFileName);
                }
            } while (FindNextFileW(hT, &fdT));
            FindClose(hT);
        }
    }

    // Copy hash DB folders.
    if (s.cfg.copyHashDb && DirExists(curInstall) &&
        _wcsicmp(curInstall.c_str(), finalInstallDir.c_str()) != 0) {
        for (const wchar_t* hd : { L"HashDB", L"HashDB 2" }) {
            std::wstring src = JoinPath(curInstall, hd);
            if (!DirExists(src)) {
                Log(std::wstring(L"  HashDB: ") + hd + L" not present in current install — skipping.");
                continue;
            }
            // SHFileOperation FO_COPY with src=...\HashDB and dst=<install>\
            // creates <install>\HashDB. (FO_COPY semantics: dst is the parent
            // of the new copy when src is a directory and dst is a directory.)
            Log(std::wstring(L"  Copying ") + hd + L" -> " + JoinPath(finalInstallDir, hd));
            if (!CopyTreeShellApi(src, finalInstallDir)) {
                Log(std::wstring(L"    ") + hd + L" copy failed.");
            } else {
                Log(std::wstring(L"    ") + hd + L": done.");
            }
        }
    }

    // Copy the xtensions\ folder forward — convenience for users who pin a
    // local set of X-Tension DLLs they want to follow each X-Ways upgrade.
    // We look only for `xtensions\` (X-Ways' canonical folder name).
    if (s.cfg.copyXtensions && DirExists(curInstall) &&
        _wcsicmp(curInstall.c_str(), finalInstallDir.c_str()) != 0) {
        std::wstring src = JoinPath(curInstall, L"xtensions");
        if (DirExists(src)) {
            Log(L"  Copying xtensions\\ -> " + JoinPath(finalInstallDir, L"xtensions"));
            if (!CopyTreeShellApi(src, finalInstallDir)) {
                Log(L"    xtensions copy failed.");
            } else {
                Log(L"    xtensions: done.");
                Log(L"    Note: review xtensions\\ in the new install — copy/move any per-version DLLs as needed.");
            }
        } else {
            Log(L"  xtensions\\ folder not present in current install — skipping.");
        }
    }

    // Desktop shortcut.
    if (s.cfg.createShortcut) {
        std::wstring desktop = GetDesktopPath();
        if (!desktop.empty()) {
            std::wstring lnk = JoinPath(desktop, folderName + L".lnk");
            std::wstring target = JoinPath(finalInstallDir, mainExeName);
            std::wstring desc   = std::wstring(L"X-Ways ") + (isByod ? L"BYOD " : L"Forensics ") + folderName;
            HRESULT hr = CreateAppShortcut(target, finalInstallDir, lnk, desc, s.cfg.shortcutAdmin);
            if (FAILED(hr)) {
                wchar_t b[64]; swprintf_s(b, L"  shortcut creation failed (HRESULT 0x%08lX)", hr);
                Log(b);
            } else {
                Log(L"  Created desktop shortcut: " + lnk);
                if (s.cfg.shortcutAdmin) {
                    Log(L"    SLDF_RUNAS_USER set on shortcut (Shortcut tab → Advanced → Run as administrator).");
                }
            }
        }
        // Compatibility tab "Run this program as administrator" — sets the
        // per-user AppCompatFlags\Layers entry on the target exe so direct
        // launches of the .exe also elevate. Tied to the same admin checkbox.
        if (s.cfg.shortcutAdmin) {
            std::wstring target = JoinPath(finalInstallDir, mainExeName);
            HKEY hKey = nullptr;
            LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
                0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
            if (rc == ERROR_SUCCESS && hKey) {
                const wchar_t* val = L"~ RUNASADMIN";
                rc = RegSetValueExW(hKey, target.c_str(), 0, REG_SZ,
                    (const BYTE*)val,
                    (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
                RegCloseKey(hKey);
            }
            if (rc == ERROR_SUCCESS)
                Log(L"  Compatibility flag set: HKCU\\...\\AppCompatFlags\\Layers RUNASADMIN on " + target);
            else
                Log(L"  Compatibility flag NOT set (registry write failed).");
        }
    }

    // Defensive Mark-of-the-Web strip: even though our download (WinHTTP) and
    // extract (tar.exe) shouldn't apply MOTW, walk the install dir once and
    // delete any :Zone.Identifier ADS so X-Ways' DLLs (Color.dll, DC.dll,
    // ImageIOAFF4.dll, etc.) load without the silent "blocked" failure. Cheap.
    StripMOTWRecursive(finalInstallDir);

    ProgressEndMarquee();  // pins bar back to 100%, stops animation
    // tempDir is auto-removed by TempDirGuard's destructor on return.
    return true;
}

// Cached running-install pointer used by ShowAboutDialog when invoked from
// the dialog's About button. The settings dialog populates this when it
// opens; XT_About also reaches it via this pointer.
static const RunningInstall* g_lastRunning = nullptr;

static std::wstring FormatDetectedLine(const RunningInstall* r) {
    if (!r || r->major == 0) return L"Detected host: (version unknown)";
    wchar_t b[120];
    if (r->haveSr) {
        swprintf_s(b, L"Detected host: X-Ways Forensics %s%d.%d SR-%d",
                   r->isByod ? L"BYOD " : L"", r->major, r->minor, r->sr);
    } else {
        swprintf_s(b, L"Detected host: X-Ways Forensics %s%d.%d",
                   r->isByod ? L"BYOD " : L"", r->major, r->minor);
    }
    return b;
}

// About-dialog state: holds the bold/larger title font + a bold-only font
// (for the "Author:" prefix) so we can free them on WM_DESTROY.
struct AboutDlgFonts {
    HFONT hTitleBold = nullptr;
    HFONT hPrefixBold = nullptr;
};

static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    AboutDlgFonts* fonts = (AboutDlgFonts*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
    switch (msg) {
    case WM_INITDIALOG: {
        fonts = new AboutDlgFonts;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)fonts);

        HFONT hf = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
        LOGFONTW lf{};
        if (hf) GetObjectW(hf, sizeof(lf), &lf);
        LOGFONTW lfTitle = lf; lfTitle.lfWeight = FW_BOLD; lfTitle.lfHeight = (LONG)(lf.lfHeight * 1.20);
        fonts->hTitleBold = CreateFontIndirectW(&lfTitle);
        LOGFONTW lfBold = lf; lfBold.lfWeight = FW_BOLD;
        fonts->hPrefixBold = CreateFontIndirectW(&lfBold);

        SetDlgItemTextW(hDlg, IDC_ABOUT_TITLE, (std::wstring(NAME) + L"  " + VERSION).c_str());
        SetDlgItemTextW(hDlg, IDC_ABOUT_DESC,  DESCRIPTION);
        SetDlgItemTextW(hDlg, IDC_ABOUT_LABEL_AUTHOR_PREFIX, L"Author:");
        SetDlgItemTextW(hDlg, IDC_ABOUT_AUTHOR, L"Kevin Stokes - Digital Detective and Cyber Sleuth");
        // U+2665 BLACK HEART SUIT on either side of the call-to-action.
        // Set programmatically (not in the .rc) so we don't depend on
        // rc.exe's input codepage to encode the character correctly.
        SetDlgItemTextW(hDlg, IDC_ABOUT_BTN_COFFEE,
            L"\u2665 Love this? How about a coffee \u2665");

        if (fonts->hTitleBold)
            SendDlgItemMessageW(hDlg, IDC_ABOUT_TITLE, WM_SETFONT, (WPARAM)fonts->hTitleBold, TRUE);
        if (fonts->hPrefixBold)
            SendDlgItemMessageW(hDlg, IDC_ABOUT_LABEL_AUTHOR_PREFIX, WM_SETFONT, (WPARAM)fonts->hPrefixBold, TRUE);

        // Tooltip on the "Buy me a coffee" button — shows the URL on hover so
        // visitors can preview before clicking.
        {
            INITCOMMONCONTROLSEX icc{};
            icc.dwSize = sizeof(icc);
            icc.dwICC  = ICC_BAR_CLASSES;
            InitCommonControlsEx(&icc);
            HWND hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, nullptr,
                WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                hDlg, nullptr, g_hSelf, nullptr);
            if (hTip) {
                static const wchar_t* kCoffeeTip = L"Opens https://buymeacoffee.com/dfirkev";
                TOOLINFOW ti{};
                ti.cbSize   = sizeof(ti);
                ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
                ti.hwnd     = hDlg;
                ti.uId      = (UINT_PTR)GetDlgItem(hDlg, IDC_ABOUT_BTN_COFFEE);
                ti.lpszText = (LPWSTR)kCoffeeTip;
                SendMessageW(hTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
                SendMessageW(hTip, TTM_SETMAXTIPWIDTH, 0, 360);
            }
        }
        return TRUE;
    }
    case WM_COMMAND: {
        WORD ctlId = LOWORD(wp);
        if (ctlId == IDC_ABOUT_LINK_GITHUB) {
            ShellExecuteW(hDlg, L"open", L"https://github.com/kev365/xways-updater",
                          nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (ctlId == IDC_ABOUT_LINK_LINKEDIN) {
            ShellExecuteW(hDlg, L"open", L"https://www.linkedin.com/in/dfir-kev",
                          nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (ctlId == IDC_ABOUT_BTN_COFFEE) {
            ShellExecuteW(hDlg, L"open", L"https://buymeacoffee.com/dfirkev",
                          nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (ctlId == IDOK || ctlId == IDCANCEL) {
            EndDialog(hDlg, ctlId);
            return TRUE;
        }
        break;
    }
    case WM_CLOSE:
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    case WM_DESTROY:
        if (fonts) {
            if (fonts->hTitleBold)  DeleteObject(fonts->hTitleBold);
            if (fonts->hPrefixBold) DeleteObject(fonts->hPrefixBold);
            delete fonts;
            SetWindowLongPtrW(hDlg, GWLP_USERDATA, 0);
        }
        break;
    }
    return FALSE;
}

static void ShowAboutDialog(HWND parent) {
    DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_ABOUT),
                    parent, AboutDlgProc, 0);
}

// =============================================================================
//  X-Tension entry points
// =============================================================================
extern "C" {

LONG __stdcall XT_Init(DWORD nVersion, DWORD /*nFlags*/, HWND hMainWnd, void* /*lpReserved*/) {
    g_hMainWnd = hMainWnd;
    int missing = RetrieveFunctionPointers();
    wchar_t buf[160];
    swprintf_s(buf, L"%s — X-Ways build %.2f (%d missing exports)",
               VERSION, nVersion / 100.0, missing);
    Log(buf);
    // Diagnostic: where did we load from, and where will the sidecar cfg
    // land? If you expected one path and see another, your X-Tensions.txt
    // probably points at a stale DLL location — re-add via Tools -> Run
    // X-Tensions and pick the canonical xtensions\xways-updater\xways-updater.dll.
    Log(L"DLL loaded from: " + GetSelfDirectory());
    return 1;
}

LONG __stdcall XT_About(HWND hParentWnd, void* /*lpReserved*/) {
    // Mirror the in-dialog About button. Also dump a short line to the
    // Messages window so it's recorded in msglog.txt.
    std::wstring m = NAME; m += L" "; m += VERSION; m += L" - "; m += DESCRIPTION;
    if (XWF_OutputMessage) XWF_OutputMessage(m.c_str(), 0);
    ShowAboutDialog(hParentWnd ? hParentWnd : g_hMainWnd);
    return 0;
}

LONG __stdcall XT_Prepare(HANDLE /*hVolume*/, HANDLE /*hEvidence*/, LONG nOpType, void* /*lpReserved*/) {
    if (nOpType != XT_ACTION_RUN) {
        // Only act when the user invoked us via Tools -> Run X-Tensions...
        return -1;
    }

    Settings s;
    s.cfg = LoadCfg();
    s.running = DetectRunningInstall();
    g_lastRunning = &s.running;

    // Always anchor the dialog's license-type radio to the currently-running
    // X-Ways flavor, overriding whatever was saved in cfg from a prior
    // session. Rationale: the running install IS the user's license, so
    // defaulting to the matching download type is what they want 99% of the
    // time. If they want to download the OTHER flavor for testing, they
    // toggle the radio for that session — saved cfg gets overwritten on
    // next load anyway. Falls through to "dongle" if no running install is
    // detected (e.g. if isByod is false for any reason).
    s.cfg.licenseType = s.running.isByod ? L"byod" : L"dongle";

    {
        // Note: "Effective install base" is logged AFTER the dialog closes
        // so it reflects the user's actual choice (which may differ from
        // the default if they typed a path or toggled license type).
        bool defaultByod = (s.cfg.licenseType == L"byod");
        std::wstring xwDir = GetXWaysInstallDir();
        std::wstring fallback = GetDefaultInstallBase(defaultByod);
        if (s.cfg.installBase.empty()) s.cfg.installBase = fallback;
        Log(L"X-Ways install dir: " + xwDir);
        Log(L"Default install base: " + fallback);
    }
    Log(FormatRunningSummary(s.running));

    // The dialog now hosts the install worker itself: clicking Install spawns
    // a worker thread that posts WM_APP_PROGRESS / WM_APP_DONE to the dialog
    // as it runs. On success the dialog returns IDOK after a final summary
    // box; on failure it stays open so the user can retry without losing
    // their selections.
    DlgState ds;
    ds.s = &s;
    ds.running = s.running;
    s.okPressed = false;

    INT_PTR rc = DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_SETTINGS),
                                 g_hMainWnd ? g_hMainWnd : GetActiveWindow(),
                                 SettingsDlgProc, (LPARAM)&ds);
    if (rc != IDOK || !s.okPressed) {
        Log(L"User cancelled.");
        return -1;
    }
    // Log the install base the user actually committed to. With the
    // "stay open" success prompt, multiple installs may have run during
    // this dialog session; this reflects the value of the field at close.
    Log(L"Effective install base: " + s.cfg.installBase);
    return -1;  // Done; we don't want X-Ways to invoke ProcessItem.
}

LONG __stdcall XT_Finalize(HANDLE, HANDLE, LONG, void*) { return 0; }
LONG __stdcall XT_Done    (void*)                       { return 0; }

} // extern "C"

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hSelf = h;
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}
