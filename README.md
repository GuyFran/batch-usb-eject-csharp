# UsbEjector (.NET 8 WPF) - Full Project (Option B)

## What you got
- Visual Studio solution and project targeting **.NET 8** (WPF)
- UI to select multiple USB Mass Storage drives and safely remove them
- Shows Drive Letter, Volume Label, NTFS Name, Vendor ID (VID) and Product ID (PID)
- Uses `CM_Request_Device_Eject` to request safe removal (requires Admin)

## Build
```bash
dotnet build -c Release
```

## Run
- Run the executable as **Administrator** (required to request eject)
- Or open `UsbEjector.sln` in Visual Studio 2022/2023 and run

## Notes
- The app filters to `USBSTOR` devices (typical USB mass storage)
- If a drive cannot be ejected, the system may show a veto reason (not surfaced in UI)
