# xways-updater

X-Tension installer/updater for X-Ways Forensics, inspired by Eric Zimmerman's
[XWFIM](https://ericzimmerman.github.io/) but living inside an existing
X-Ways install as an X-tension.

<img src="https://github.com/kev365/xways-updater/blob/main/xways-updater.png" alt="xways-updater" style="width:70%; height:auto;">

## What it does

- Downloads the requested version of the **main app** (Dongle or BYOD).
- Extracts it into a sibling folder named after the **detected** version (e.g.
  `xwf21-7sr3`, `xwb21-8-beta5` — read from the binary's VERSIONINFO and/or
  the session-start banner X-Ways writes to `msglog.txt`).
- Optionally pulls **Viewer Component**, **Tesseract**, **Excire**,
  **AFF4 X-Tension**, and a **Conditional Coloring.cfg** — tri-state checkbox
  picks the source: checked = SANS FOR500 build by Michael Yasumoto
  ([`peacekeeper0/X-Ways-Forensics`](https://github.com/peacekeeper0/X-Ways-Forensics));
  indeterminate = upstream `x-ways.net`; unchecked = skip. When **Copy custom
  configs** is on and the current install already has a `Conditional Coloring.cfg`,
  the freshly downloaded one wins — the old copy is preserved as
  `Conditional Coloring.cfg.old` (or `.old2`, `.old3`, ...) when its SHA-256
  differs (identical copies are silently skipped).
- Optionally **copies** `*.cfg`, `*.dlg`, `*.tpl`, `investigator.ini`, and
  `Passwords.txt` from the current install (per-policy: cfg/ini/Passwords
  overwrite; tpl is keep-upstream so user-only templates carry forward).
- Optionally copies the `HashDB` / `HashDB 2` folders.
- Optionally copies the current install's `xtensions\` folder forward.
- Optionally **creates a desktop shortcut** to the new install (with optional
  "Run as administrator" flag and matching `AppCompatFlags\Layers RUNASADMIN`
  registry entry on the target exe).

## Requirements

- **Windows (x64).** Should work on any 64-bit Windows that runs X-Ways
  (Win 10, Win 11, Windows Server). Only x64 is tested.
- **X-Ways Forensics** - only tested for 21.0 or newer.
- **A valid X-Ways license** - Dongle or BYOD license.

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
            └── xways-updater.cfg
```

## Run

X-Ways → **Tools → Run X-Tensions...** → select
`xtensions\xways-updater\xways-updater.dll`. Pick your settings, click
**Install**.

## To Do:
- Add downloading of the NSRL Hash DBs, they seem to have disappeared as of this update, so I don't have the links.
- I'd like to find an easier way to detect downloaded service release versions.

## Disclaimer

This is a community-developed X-Tension. It is **not** affiliated with,
endorsed by, or supported by X-Ways AG. Use at your own risk in compliance
with your X-Ways license agreement.

## License

Released under the MIT License. See [LICENSE](LICENSE).
