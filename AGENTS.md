# AGENTS.md — USB Ejector

Root entry point. Global rules in `~/.claude/CLAUDE.md` and the portfolio rules in `../AGENTS.md`
apply.

**Owner:** GuyFran — guynemerp@free.fr

## What this is

A WPF (.NET 8) utility that safely removes several USB drives at once. It enumerates removable
drives, shows their mount paths, detects NTFS folder mounts, and performs the Windows safe-removal
sequence.

## Status — 2026-08-09

| | |
|---|---|
| Version | **none — no version constant** (backlog #1) |
| Worktree | Clean |
| Build / tests | **Not run this pass.** No test project. |
| State | Dormant — works, no active work stream. |

Full commit history, newest first: an application icon; *"eject fix ?"* — a fix committed with an
open question in its own message; show mount path; NTFS folder detected; normal detection fixed;
initial. That is the whole history.

## Backlog

| # | Item | Notes |
|---|---|---|
| 1 | **No version constant** | The global rule requires one in `MainWindow.xaml.cs`, displayed in the status bar, never from `.csproj`. |
| 2 | **Confirm the eject fix actually works** | The commit message *"eject fix ?"* records genuine doubt and nothing since has confirmed it. `UsbSafeRemoval.cs` is where to look. This needs a real device to verify — a drive that fails to eject cleanly can lose writes, so it matters. |
| 3 | README is a scaffold note | `README.md` still reads as generated setup text ("Full Project (Option B)"). Replace it with what the tool does and the NTFS-folder-mount caveat. |

## Build / run / verify

```bash
dotnet build UsbEjector.csproj
```

Windows-only WPF, .NET 8. Launching and screen-testing are permitted — capture the application
window, not the desktop. Meaningful verification needs real removable drives; safe removal cannot
be honestly tested without them.

## Layout

```
MainWindow.xaml(.cs)   the shell
UsbDriveInfo.cs        drive enumeration and model
UsbSafeRemoval.cs      the safe-removal sequence — the load-bearing file
Assets/
```

## Versioning

Per the global rule: `x.x.x`, constant in `MainWindow.xaml.cs`, shown in the status bar, never read
from `.csproj`. Not yet implemented here — backlog #1.
