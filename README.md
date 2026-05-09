# xways-updater

X-Tension installer/updater for X-Ways Forensics, inspired by Eric Zimmerman's
[XWFIM](https://ericzimmerman.github.io/) but living inside an existing
X-Ways install.

## What it does

- Downloads the requested version of the **main app** (Dongle or BYOD).
- Extracts it into a sibling folder named after the **detected** version (e.g.
  `xwf21-7sr3`, `xwb21-8-beta5` — read from the binary's VERSIONINFO and/or
  the session-start banner X-Ways writes to `msglog.txt`).
- Optionally pulls **Viewer Component**, **Tesseract**, **Excire**,
  **AFF4 X-Tension**, and **Conditional Coloring.cfg**.
- Optionally **copies** `*.cfg`, `*.dlg`, `*.tpl`, `investigator.ini`, and
  `Passwords.txt` from the current install (per-policy: cfg/ini/Passwords
  overwrite; tpl is keep-upstream so user-only templates carry forward).
- Optionally copies the `HashDB` / `HashDB 2` folders.
- Optionally copies the current install's `xtensions\` folder forward.
- Optionally **creates a desktop shortcut** to the new install (with optional
  "Run as administrator" flag and matching `AppCompatFlags\Layers RUNASADMIN`
  registry entry on the target exe).

## Requirements

- **Windows 10/11 x64.**
- **X-Ways Forensics 21.0 or newer** as the host. Older majors aren't
  supported (the version-detection paths and resource layouts diverge before
  21.x).
- **A valid X-Ways license** with credentials for `x-ways.net` /
  `x-ways.com`. The X-Tension does not provide credentials; you supply your
  own. Without a valid license, downloads will return HTTP 401.

## Authentication

Every download uses **HTTP Basic** auth on `x-ways.net` (resources, dongle
app) and `x-ways.com` (BYOD app). The realm is _"Latest password from
x-ways.net/license.html"_ — the same username/password X-Ways prompts you for
in a browser.

- **Dongle creds** — used for the dongle app (`/xwf/`) AND every resource
  (`/res/...`).
- **BYOD creds** — used only for the BYOD app (`/xwb/`). Resources still go
  through the dongle creds. The BYOD username/password fields are enabled
  whenever the BYOD radio is selected.

Credentials can be remembered next to the DLL via DPAPI (per-Windows-user
ciphertext). Toggle off to avoid persisting. The sidecar file
(`xways-updater.cfg`) is gitignored by default — even DPAPI ciphertext is
yours, not something to redistribute.

## Integrity / Mark-of-the-Web

Every downloaded artifact (zips and loose files) is hashed and the SHA256 is
written to the X-Ways Messages window — easy to verify against a peer or a
trusted record.

Eric Zimmerman warns about Windows Explorer extracting downloaded zips:
Explorer propagates the `Zone.Identifier` ADS ("Mark of the Web") to every
extracted file, and Windows then silently blocks `LoadLibrary` on those DLLs
(X-Ways' `Color.dll`, `DC.dll`, `ImageIOAFF4.dll`, etc.). xways-updater avoids
this two ways:

- **Download** uses WinHTTP + `CreateFile`/`WriteFile`. Browsers apply MOTW
  via `IAttachmentExecute`; WinHTTP does not.
- **Extract** uses `tar.exe` (libarchive). Libarchive doesn't know about
  `Zone.Identifier` ADS, so MOTW is not propagated to extracted files.

As cheap defense, the install dir is walked once after extraction and any
`:Zone.Identifier` ADS is deleted via `DeleteFile`.

## Install

The recommended layout matches X-Ways' built-in `xtensions\` auto-load
convention with a per-X-Tension subfolder:

```text
<X-Ways install>\
├── xwforensics64.exe
└── xtensions\
    └── xways-updater\
        ├── xways-updater.dll
        ├── xways-updater.ico
        └── xways-updater.cfg     (auto-created if you tick "Remember credentials")
```

After building, the project's `build.bat` produces this layout under
`xtensions\xways-updater\` next to the source. Copy that whole subfolder into
your X-Ways install's `xtensions\`.

## Run

X-Ways → **Tools → Run X-Tensions...** → select
`xtensions\xways-updater\xways-updater.dll`. Pick your settings, click
**Install**.

> Note: "Run X-Tensions..." requires a volume to be open in X-Ways. Any case
> will do — this X-Tension doesn't read the volume.

The "Test" buttons next to each credential pair do a HEAD request to the
relevant `.zip` URL — quick way to verify creds before kicking off a long
download.

After a successful install, the dialog asks whether to keep itself open so
you can install or download something else without reloading the X-Tension.

## Build

Run from a "x64 Native Tools Command Prompt for VS 2019/2022", or any plain
shell — `build.bat` auto-bootstraps `vcvars64.bat` if needed:

```cmd
cd x-tensions\xways-updater
build.bat
```

Output: `xways-updater.dll`, deployed to
`xtensions\xways-updater\xways-updater.dll` next to the source.

## Files

- `xways-updater.cpp` — single-file implementation (dialog + downloader +
  extractor + copy/shortcut steps).
- `xways-updater.rc`, `resource.h` — Win32 dialog template.
- `xways-updater.def` — DLL exports.
- `xways-updater.ico` — title-bar icon.
- `build.bat` — MSVC build script.
- `xways-updater.cfg` — sidecar config, written next to the DLL when the
  dialog's "Remember credentials" is ticked. Passwords are DPAPI ciphertext
  (base64 in plain-text key=value lines). **Never commit this file.**
- [`CLI.md`](CLI.md) — reference / brainstorm for the planned `XTParam:`
  command-line interface (unattended runs, scheduled installs, dry-run, etc.).

## Disclaimer

This is a community-developed X-Tension. It is **not** affiliated with,
endorsed by, or supported by X-Ways AG. Use at your own risk in compliance
with your X-Ways license agreement.

## License

Released under the MIT License. See [LICENSE](LICENSE).
