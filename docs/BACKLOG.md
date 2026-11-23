# Backlog — USB Batch Ejector

Items dated 2026-11-24 come from reading the code in the docs pass. None was reproduced on a real drive.

## Open

| # | Item | State | Source | Notes |
|---|---|---|---|---|
| B1 | Refresh `AGENTS.md` | blocked — owner | 2026-11-24 docs pass | The local checkout has an uncommitted "Global Rules First" block in it (portfolio open conflict #1). Until the owner keeps or discards it, `AGENTS.md` stays stale and `git pull` is refused. [STATUS.md](STATUS.md) carries the correct facts |
| B2 | Status bar showing the version | todo | Global rule; 2026-08-09 | The constant exists, shown in the title only |
| B3 | Confirm eject works on real drives | todo | Commit `9c78ca5` "eject fix ?", 2025-12-11 | A drive that does not eject cleanly can lose writes |
| B4 | Administrator requirement | todo | 2026-11-04 | No `app.manifest`. Confirm, then add one or state it is not needed |
| B5 | Show the veto reason on failure | todo | 2026-11-04 | Known only inside `RequestDeviceEject`, which returns a plain `bool` |
| B6 | Eject target may be too low in the device tree | todo | 2026-11-24 | `GetEjectableUsbDevInst` stops at the `USBSTOR` disk node, though its log and comment describe a USB parent. Possible cause of B3 |
| B7 | Same device can appear on several rows | todo | 2026-11-24 | A volume with a letter and a folder mount, or a disk with two partitions. Ticking both ejects the device, then reports a false failure for the second row |
| B8 | Listing can be wrong in both directions | todo | 2026-11-24 | A folder mount hosted on a lettered USB drive is hidden. The `USB` substring test could match a non-USB device whose ID contains those letters |
| B9 | Batch flow blocks the UI | todo | 2026-11-24 | Eject runs on the UI thread with one modal box per drive. One summary would suit a batch tool |
| B10 | Selection and empty state | todo | 2026-11-24 | Highlighted rows are ignored by Eject, and an empty list shows no message |
| B11 | No diagnostics in Release | todo | 2026-11-24 | `Debug.WriteLine` is compiled out. `GetLastWin32Error` is also logged after a CfgMgr call that does not set it |
| B12 | Nullable warnings (CS8632) | todo | 2026-11-04 | `UsbDriveInfo.cs` uses `string?` without nullable enabled |
| B13 | Unused code | todo | 2026-11-24 | `DisplayName`, `NtfsVolumeName`, `ShowRestored` |

## Done

| Item | Version / date |
|---|---|
| Docs reorganized under `docs/`, written from the code | 1.0.2, 2026-11-24 |
| Version constant, shown in the window title | 1.0.1, 2026-11-17 |
| Window and column layout persisted | 1.0.1, 2026-11-17 |
| 2025-12-11 uncommitted blocking-process work no longer in the tree | Confirmed 2026-11-24 |
| README rewritten from scaffold text | 2026-11-04 |
| Application icon | 2026-08-09 |
| Normal and NTFS folder-mount detection, mount path shown | 2025-12-11 |
