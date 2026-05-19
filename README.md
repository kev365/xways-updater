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
  mid-check = upstream `x-ways.net` config; unchecked = skip. When **Copy custom
  configs** is on and the current install already has a `Conditional Coloring.cfg`,
  the freshly downloaded one wins — the old copy is preserved as
  `Conditional Coloring.cfg.old` when its SHA-256 differs.
- Optionally **copies** `*.cfg`, `*.dlg`, `*.tpl`, `investigator.ini`, and
  `Passwords.txt` from the current install (per-policy: cfg/ini/Passwords
  overwrite; tpl is keep-upstream so user-only templates carry forward).
- Optionally copies the `HashDB` / `HashDB 2` folders.
- Optionally copies the current install's `xtensions\` folder forward.
- Optionally **creates a desktop shortcut** to the new install (with 
  "Run as administrator" flag and matching `AppCompatFlags\Layers RUNASADMIN`
  registry entry on the target exe).

## Requirements

- **Windows (x64).** Should work on any 64-bit Windows that runs X-Ways
  (Win 10, Win 11, Windows Server). Only x64 is tested.
- **X-Ways Forensics x64** - only tested for 21.0 or newer, x64 only.
- **A valid X-Ways license** - Dongle or BYOD license.

## Authentication

Every download uses **HTTP Basic** auth on `x-ways.net` (resources, dongle
app, BYOD-app metadata via `.net` too where applicable) and `x-ways.com`
(BYOD app zip). The realm is _"Latest password from x-ways.net/license.html"_
— the same username/password X-Ways prompts you for in a browser.

Either license can fetch everything on its own credentials. The dialog
shows a **single** Username + Password row; the License Type radio above it
picks which set you're editing:

- Select **Dongle** → fields show your saved Dongle credentials. They drive
  the dongle main app (`/xwf/...`) and every resource (`/res/...`).
- Select **BYOD** → fields show your saved BYOD credentials. They drive the
  BYOD main app (`/xwb/...`) and every resource — the BYOD set works against
  `/res/` too.

The group title rewrites to "Dongle credentials" / "BYOD credentials" so
the active slot is always clear. Switching the License radio mid-dialog
auto-loads the saved creds for that license, or clears the row when
nothing is saved for it. Typed-but-not-saved input in the previous
license's row is discarded on swap — only **Install** and **Test with
Remember on** commit the visible row to disk.

### When are creds saved?

| Action | Creds saved? |
| --- | --- |
| **Test** (Remember off) | No — diagnostic only |
| **Test** (Remember on, 200) | Yes — captured into the active slot and written to `xways-updater.cfg` immediately |
| **Test** (Remember on, 4xx/5xx) | No — invalid creds aren't persisted |
| **Install** (successful) | Yes — the active slot's typed creds are written before the worker runs |
| **Shift+Install** | Yes — writes the current dialog state to `xways-updater.cfg` without running the install |

Credentials can be remembered next to the DLL via DPAPI (per-Windows-user
ciphertext). Both slots are persisted independently — if you have only one
license, the other slot just stays empty. Toggle Remember off to avoid
persisting either. The sidecar file (`xways-updater.cfg`) is gitignored by
default — even DPAPI ciphertext is yours, not something to redistribute.

Empty username/password fields trigger the same "Credentials needed"
prompt + field flash across **Test**, **Install**, and the version
**Refresh** button — short-circuits the HTTP call so the server isn't
asked to authenticate a blank request.

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
endorsed by, or supported by X-Ways AG. It's also vibe coded, use at your 
own risk. The code is here to review, please submit an issue if you find one.

## License

Released under the MIT License. See [LICENSE](LICENSE).
