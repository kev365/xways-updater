# xways-updater — command-line reference

Reference / brainstorm doc for command-line driven use of the X-Tension. Most
of this is **proposed**, not implemented yet — see "Status" against each
parameter. Real CLI parsing entry points are in
[xways-updater.cpp](xways-updater.cpp) once wired.

## Why this exists

Today the X-Tension is dialog-driven: analyst goes through Tools → Run
X-Tensions, fills the dialog, clicks Install. That works for interactive use
but leaves three workflows on the table:

- **Scheduled runs** — Task Scheduler or `schtasks` launches X-Ways with
  XTParam args; xways-updater self-executes (full install of latest, or
  tools-only refresh) and exits without analyst input.
- **CI / lab provisioning** — pre-baked Windows image runs an installer
  step that points X-Ways at a known username/password (or pre-deployed
  `xways-updater.cfg`) and a target install base.
- **Repeatable analyst workflow** — analyst keeps a `.cmd` shortcut next
  to X-Ways with their preferred upgrade flow burned in.

## How XTParam: works

Documented at <https://www.x-ways.net/forensics/x-tensions/api.html>. Verbatim:

> as of v19.4 SR-6, it is defined that parameters starting with the
> characters "XTParam:" are ignored by X-Ways Forensics, so that no message
> box about a "file not found" error condition or so pops up. Such
> parameters can be used by X-Tensions. They may retrieve the entire
> command line with the Windows GetCommandLine function, parse it, and
> look for a parameter with the above-mentioned prefix.

Format (X-Ways enforces only the first two colons):

```
XTParam:<id>:<value>
```

- `<id>` — short identifier per X-Tension. Ours is `xways-updater`. May not
  contain a colon. Case-insensitive (we lowercase on parse).
- `<value>` — anything after the second colon, including more colons.
  Quote the whole `XTParam:...` token if it contains spaces.

## Our convention

One parameter per `XTParam:` token, `<key>=<value>` format inside:

```
XTParam:xways-updater:<key>=<value>
```

Multiple keys = multiple `XTParam:` tokens. This avoids inner delimiters
clashing with paths and quoting:

```
xwforensics64.exe ^
  "XTParam:xways-updater:run=full" ^
  "XTParam:xways-updater:base=D:\xwf" ^
  "XTParam:xways-updater:version=latest"
```

Reading from C++:

```cpp
int argc = 0;
LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
if (argv) {
    static const wchar_t kPrefix[] = L"XTParam:xways-updater:";
    constexpr size_t kPrefixLen = (sizeof(kPrefix) / sizeof(wchar_t)) - 1;
    for (int i = 1; i < argc; ++i) {
        if (_wcsnicmp(argv[i], kPrefix, kPrefixLen) != 0) continue;
        std::wstring kv = argv[i] + kPrefixLen;     // e.g. "base=D:\xwf"
        size_t eq = kv.find(L'=');
        std::wstring key = (eq == std::wstring::npos) ? kv : kv.substr(0, eq);
        std::wstring val = (eq == std::wstring::npos) ? L"" : kv.substr(eq + 1);
        // dispatch on key...
    }
    LocalFree(argv);
}
```

## Parameters

Status: ⚪ proposed · 🟡 partial · 🟢 implemented

| Key | Values | Status | Notes |
|---|---|---|---|
| `run` | `full` · `main_only` · `extras_only` · `dialog` (default) | ⚪ | Maps to the dialog's tri-state mode. `dialog` = open the settings dialog as today. Anything else = unattended (skip dialog when all required keys provided). |
| `license` | `dongle` · `byod` | ⚪ | Picks the radio. Default = whatever the running install is. |
| `version` | `<filename>` · `latest` · `current` | ⚪ | `latest` resolves via the index. `current` uses the unversioned alias (`xw_forensics.zip` / `xwb.zip`). `<filename>` (e.g. `xw_forensics217.zip`) is matched verbatim against the index. |
| `beta` | `on` · `off` | ⚪ | Include beta entries in the version index lookup. |
| `base` | `<path>` | ⚪ | Install base directory. Default = parent of running install. |
| `folder` | `<name>` | ⚪ | Folder name override. Default = auto-name from detected version. |
| `dl` | `viewer,tesseract,excire,cond_coloring,aff4,all,none` | ⚪ | Comma-separated tool list. `all` = every tool, `none` = nothing. Defaults match the dialog defaults (Viewer + Cond Coloring + AFF4). |
| `copy` | `cfg,hashdb,xtensions,all,none` | ⚪ | Same convention. Overrides the cfg-version-gate when explicitly listed. |
| `shortcut` | `on` · `off` | ⚪ | Create desktop shortcut. Default = on. |
| `unattended` | `1` · `0` | ⚪ | When `1`, skip the dialog entirely and run with provided keys. Required keys: `run` + `license` + creds (or a present `xways-updater.cfg`). |
| `creds` | `cfg` · `prompt` | ⚪ | `cfg` (default) = use whatever's in the sidecar; `prompt` = always show the dialog even with `unattended=1`. |
| `auto-confirm-same-version` | `1` · `0` | ⚪ | Skip the "you already have this version installed" prompt. Default = `0` (prompt as today). |
| `dry-run` | `1` · `0` | ⚪ | Run pre-flight (HEAD requests, free-space check, version detection) without downloading or installing. Logs what *would* happen. |
| `log-file` | `<path>` | ⚪ | Mirror the Messages-window output to a text file. Useful for scheduled runs where the Messages window is gone by the time the analyst checks. |

## Notes / unsettled

- **Quoting**: `CommandLineToArgvW` handles standard MSVCRT quoting, so
  paths with spaces work as long as the *whole* `XTParam:...` token is
  quoted. Inside the value, no further escaping is needed.
- **Case sensitivity**: keys lowercase, values lowercase except for paths
  and filenames.
- **Conflict with the dialog**: if `unattended=1` and dialog is required
  (e.g. credentials missing), we should fall back to opening the dialog
  with whatever keys we did get pre-filled, rather than failing silently.
- **Where parsing lives**: probably `XT_Init` — we can stash a parsed
  struct in a global and consult it from `XT_Prepare`. `XT_Init` runs once
  per session, so re-parsing per run isn't needed.
- **Cred passthrough on the cmdline**: explicitly NOT supporting
  `user=` / `pass=` — credentials should come from the DPAPI sidecar
  (or the dialog), never from a process command line where they end up
  in `tasklist`/`Get-CimInstance Win32_Process` output.

## Example invocations

### Open the dialog with mode + base preset

```cmd
xwforensics64.exe ^
  "XTParam:xways-updater:run=dialog" ^
  "XTParam:xways-updater:base=D:\xwf"
```

### Unattended full install of latest dongle build

```cmd
xwforensics64.exe ^
  "XTParam:xways-updater:unattended=1" ^
  "XTParam:xways-updater:run=full" ^
  "XTParam:xways-updater:license=dongle" ^
  "XTParam:xways-updater:version=latest"
```

(Requires a present, valid `xways-updater.cfg` next to the DLL.)

### Unattended tools-only refresh, all tools, log file

```cmd
xwforensics64.exe ^
  "XTParam:xways-updater:unattended=1" ^
  "XTParam:xways-updater:run=extras_only" ^
  "XTParam:xways-updater:dl=all" ^
  "XTParam:xways-updater:log-file=D:\xwf\logs\refresh-%DATE%.log"
```

### Dry-run pre-flight only

```cmd
xwforensics64.exe ^
  "XTParam:xways-updater:dry-run=1" ^
  "XTParam:xways-updater:run=full" ^
  "XTParam:xways-updater:version=xw_forensics217.zip"
```

## Future ideas

Things worth exploring once the basic CLI lands:

- **Profiles**: `XTParam:xways-updater:profile=lab1` reads a
  `xways-updater-lab1.profile` file (key=value) for any keys not given on
  the command line. Lets analysts keep multiple presets.
- **Exit code policy**: define stable exit codes (0 = ok, 1 = pre-flight
  fail, 2 = download fail, 3 = extract fail, 4 = copy fail) so scheduled
  runs can react meaningfully. X-Ways' own exit-code contract is
  undocumented (see [docs/xways-command-line.md](../../docs/xways-command-line.md)),
  but our X-Tension can return a code from `XT_Init` that XWB respects on
  exit when invoked unattended.
- **Inventory mode**: `XTParam:xways-updater:inventory=<path>` writes a
  JSON describing current install + available versions on x-ways.net,
  without doing anything else. Useful for fleet-state collection.
- **Self-update notifications**: `XTParam:xways-updater:check-updates=1`
  exits non-zero (with a Messages-window note) when a newer version
  exists, so a daily scheduled task can email the analyst.
- **Verify mode**: `XTParam:xways-updater:verify=<install-folder>` walks
  an existing install and reports SHA256 mismatches against what we
  *would* download — useful for tampering checks on dongle hosts.
- **JSON output**: alongside `log-file`, a structured `json-output=<path>`
  that emits one JSON line per phase. Drops nicely into ELK/Splunk if a
  shop is forwarding logs.
- **Config bake**: `XTParam:xways-updater:save-as=<profile-name>` saves
  the *current* dialog state to a profile file rather than running the
  install — lets the analyst capture their interactive choices for later
  unattended re-use.

## See also

- [docs/xways-command-line.md](../../docs/xways-command-line.md) — X-Ways' own
  CLI parameters (Override:, GetLicID:, etc.). XTParam: is documented there
  too.
- [docs/xtension-invocation.md](../../docs/xtension-invocation.md) — XT_Init
  / XT_Prepare entry points and where `GetCommandLine` parsing fits.
- X-Ways API page: <https://www.x-ways.net/forensics/x-tensions/api.html>
