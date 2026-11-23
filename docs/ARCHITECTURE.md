# Architecture — USB Batch Ejector

WPF, `net8.0-windows`, one project (`UsbEjector.csproj`), no NuGet packages. Written from the code on 2026-11-24.

## Files

| File | Role |
|---|---|
| `App.xaml(.cs)` | WPF application, starts `MainWindow` |
| `MainWindow.xaml(.cs)` | The window, `AppVersion`, Refresh and Eject handlers |
| `UsbDriveInfo.cs` | One row: mount, label, VID/PID, `DevInst`, `IsSelected` |
| `UsbSafeRemoval.cs` | Win32 enumeration and eject (kernel32, SetupAPI, CfgMgr32). The load-bearing file |
| `UiLayout.cs` | Saves and restores window placement and list columns |
| `Assets/usb-ejector.ico` | App and window icon |

## Enumeration — `GetUsbStorageDrives`

1. **Lettered drives.** For each ready `Fixed` or `Removable` drive, get the disk number with
   `IOCTL_STORAGE_GET_DEVICE_NUMBER`.
2. Find the disk's device node by matching that number across `GUID_DEVINTERFACE_DISK` interfaces.
3. Keep it if `IsDeviceUsbBacked` is true: the node or an ancestor has an ID containing `USB` or `VID_`. This is
   wider than `USBSTOR`, so USB disks using other drivers can qualify.
4. Read VID/PID from the nearest node that has them.
5. **Folder mounts.** For every volume, list its mount paths and repeat steps 1–4. Bare drive-letter paths are
   skipped, and so are paths whose root is a USB drive already listed.

## Eject — `RequestDeviceEject`

1. `GetEjectableUsbDevInst` walks up from the disk node and stops at the first ID that starts with `USB\` or contains
   `VID_` or `USBSTOR`.
2. It logs the ancestry and VID/PID.
3. It calls `CM_Request_Device_Eject` with a veto buffer.
4. It returns `true` only when the result is 0 and the veto type is 0. The veto reason goes to the debug log only.

`MainWindow.Eject_Click` runs this for each ticked row in turn on the UI thread, shows one message box per drive,
then refreshes the list.

## Logging

`LOG` uses `Debug.WriteLine` with the `[USBDEBUG]` prefix. That call is compiled out of Release builds, so a Release
build has no eject diagnostics. There is no log file.

## Stored data

`%APPDATA%\UsbEjector\layout.json` (schema 1), written 600 ms after the last change and at once on close, through a
temp file.

| Section | Used by this app |
|---|---|
| `Windows["Main"]` | Normal bounds, maximized, monitor, DPI |
| `Grids["DrivesList"]` | Column width and order, keyed by header text |
| `Tabs` | Unused, the app has no tabs |

On restore, a window is rescaled for DPI changes and clamped to the visible work area. Minimized is never restored.

## Unused code

`UsbDriveInfo.DisplayName`, `UsbDriveInfo.NtfsVolumeName` (filled, never shown) and `WindowGeometry.ShowRestored`.
