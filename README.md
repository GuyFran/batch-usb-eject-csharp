# USB Batch Ejector

A small Windows tool (WPF, .NET 8) that safely removes several USB drives in one go.

- Lists USB mass-storage (`USBSTOR`) drives: drive letter, NTFS folder mount path (drives mounted into a folder
  instead of a letter), volume label, vendor and product IDs.
- Tick the drives to remove and click **Eject Selected**; each one gets a Windows safe-removal request
  (`CM_Request_Device_Eject`).
- If Windows refuses (a file is open on the drive, for example), the tool reports "Failed to eject"; the reason is
  not shown yet.

Build, status, version and backlog: see [`AGENTS.md`](AGENTS.md).
