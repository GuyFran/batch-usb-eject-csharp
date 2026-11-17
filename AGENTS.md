# AGENTS.md — USB Batch Ejector

Single entry point for any AI agent or human working on this repo.

**Authority order:** `~/.claude/CLAUDE.md` (global rules) → portfolio index `Documents\Projects\AGENTS.md`
(when present — it does not exist on FILESERVER1, 2026-11-04) → this file. There is no project `CLAUDE.md`.

**Commit identity:** GuyFran — guynemerp@free.fr (git `user.name` GuyFran). Commit `8e5c85d` was authored with a
typo (`guynemep@free.fr`) and `9c78ca5`/earlier as "Guy Dev"; history is not rewritten.

**Display name:** **USB Batch Ejector** (the window title in `MainWindow.xaml`). Repo folder:
`batch-usb-eject-csharp`; project/assembly: `UsbEjector`.

## What this is

A Windows WPF (.NET 8) utility that safely removes several USB mass-storage drives at once. It lists `USBSTOR`
drives (drive letter, NTFS folder mount path, label, VID/PID), lets you tick several, and asks Windows to eject
each one with `CM_Request_Device_Eject`.

## Read order

1. This file — status, version, build, backlog.
2. [`README.md`](README.md) — short user-facing description.

No other docs. No historical docs.

## Version

**None yet.** There is no version constant and no status bar. Per the global rule it must be an `x.x.x` constant in
`MainWindow.xaml.cs`, shown in a status bar, never read from `.csproj` (backlog #1). It was not added in the
2026-11-04 docs pass because `MainWindow.xaml.cs` holds uncommitted work that is not the pass's (see Status).

## Build / test

```bash
dotnet build UsbEjector.csproj
```

- Target `net8.0-windows`, WPF, single project (`UsbEjector.csproj`, solution `UsbEjector.sln`).
- **Tests: none** — there is no test project.
- Launching the app follows the global Verification rule (last resort only). Real verification of ejection needs
  real removable drives.

## Status — 2026-11-04

| Item | State |
|---|---|
| Committed code (`HEAD`) | Builds: 0 errors, 6 nullable warnings (CS8632) — observed 2026-11-04 on a clean export of `HEAD` |
| Working tree | **Does not compile.** `MainWindow.xaml.cs` and `UsbSafeRemoval.cs` have uncommitted edits dated 2025-12-11 (a "show blocking processes" attempt). `UsbSafeRemoval.cs` contains hundreds of literal `<<EJECT_BLOCK>>` placeholders and `MainWindow.xaml.cs` has escaped `\"` outside strings: `dotnet build` fails with 13 525 errors. Left untouched — owner decides (backlog #2) |
| Version constant | missing (backlog #1) |
| App icon | done — `Assets/usb-ejector.ico`, embedded via `ApplicationIcon` (2026-08-09) |
| State | dormant — works at `HEAD`, no active work stream |

## Layout

```
App.xaml(.cs)          WPF application, starts MainWindow
MainWindow.xaml(.cs)   the window: drive list, Refresh, Eject Selected
UsbDriveInfo.cs        drive model (letter, mount path, label, VID/PID, DevInst)
UsbSafeRemoval.cs      SetupAPI/CfgMgr32 enumeration and the eject call — the load-bearing file
Assets/usb-ejector.ico application icon
UsbEjector.csproj/.sln project and solution
```

## Backlog (unfinished)

| # | Item | State | Notes |
|---|---|---|---|
| 1 | Version constant + status bar | blocked by #2 | 2026-08-09: global rule, `MainWindow.xaml.cs`. That file is dirty (2026-11-04) |
| 2 | Uncommitted 2025-12-11 WIP (blocking-process report) | blocked — owner | 2026-11-04: working tree does not compile (`<<EJECT_BLOCK>>` placeholders, `\"` escapes). Owner: finish it or discard it (`git restore MainWindow.xaml.cs UsbSafeRemoval.cs`) |
| 3 | Confirm the eject fix works | todo | 2025-12-11: commit `9c78ca5` "eject fix ?" records doubt; needs a real device. A drive that fails to eject cleanly can lose writes |
| 4 | Administrator requirement | todo | 2026-11-04: the old README said eject needs admin, but there is no `app.manifest` requesting elevation; confirm, then add one or drop the claim |
| 5 | Surface the eject veto reason | todo | 2026-11-04: on failure the UI only says "Failed to eject"; the CfgMgr veto reason is not shown |
| 6 | Nullable warnings (CS8632) | todo | 2026-11-04: `UsbDriveInfo.cs` uses `string?` without `<Nullable>enable</Nullable>` |

## Done

| Item | Date |
|---|---|
| Normal + NTFS folder-mount detection, mount path shown | 2025-12-11 |
| Application icon | 2026-08-09 |
| README rewritten from scaffold text to a real description | 2026-11-04 |
