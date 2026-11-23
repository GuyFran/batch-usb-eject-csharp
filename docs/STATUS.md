# Status — USB Batch Ejector

Checked against the code on 2026-11-24.

> **`AGENTS.md` is out of date and could not be edited in this pass** (backlog B1). Where it disagrees with this
> file, this file is right. In particular: the version constant exists, the 2025-12-11 uncommitted work is gone,
> and the docs below exist.

| Item | State |
|---|---|
| Version | **1.0.2**, `AppVersion` in `MainWindow.xaml.cs`. No mirror in `.csproj` |
| Where it shows | Window title only. There is no status bar yet (B2) |
| Project state | Dormant, no active work stream |
| Build | **Not run in this pass.** Last recorded: 2026-11-04, 0 errors and 6 CS8632 warnings, on a commit before 1.0.1 |
| Tests | None, there is no test project |
| Real-device check | **Never recorded.** Ejection is unconfirmed on real drives (B3) |
| Elevation | No `app.manifest`, so the app runs unelevated. Whether eject works that way is unconfirmed (B4) |
| Window layout | Saved and restored since 1.0.1 (window placement, column widths and order) |
| Icon | `Assets/usb-ejector.ico`, on the exe and the window |
| Olympus | Not onboarded, no `olympus-app.json` |

## Identity and authority

- Owner: GuyFran — guynemerp@free.fr.
- Authority order: `~/.claude/CLAUDE.md` → `Documents\Projects\AGENTS.md` → this project's `AGENTS.md` and `docs/`.
- Display name: **USB Batch Ejector**. Repo: `batch-usb-eject-csharp`. Assembly: `UsbEjector`.

## Build

```powershell
dotnet build UsbEjector.csproj
```

Launching follows the global Verification rule (last resort). Ejection can only be verified with real drives.

## Docs

| Doc | Holds |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Code layout, enumeration and eject flows, stored data |
| [UI_UX.md](UI_UX.md) | The window as built, behaviour and known gaps |
| [BACKLOG.md](BACKLOG.md) | Open and done items |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
