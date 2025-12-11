using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace UsbEjector
{
    /// <summary>
    /// UsbSafeRemoval: DeviceNumber matching + SetupAPI (x86/x64 safe)
    /// Debug level: Full verbose (3)
    /// Adds detection of volumes mounted to NTFS folders (no drive letter).
    /// </summary>
    public static class UsbSafeRemoval
    {
        private const int DEBUG_LEVEL = 3;
        private static void LOG(string msg)
        {
            if (DEBUG_LEVEL >= 1) Debug.WriteLine("[USBDEBUG] " + msg);
        }

        // SetupAPI flags
        private const int DIGCF_PRESENT = 0x00000002;
        private const int DIGCF_DEVICEINTERFACE = 0x00000010;

        // Disk class GUID - copy to local before passing to APIs
        private static readonly Guid GUID_DEVINTERFACE_DISK =
            new Guid("53f56307-b6bf-11d0-94f2-00a0c91efb8b");

        private const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080;

        // -------------------- Native structs --------------------

        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_DEVICE_NUMBER
        {
            public uint DeviceType;
            public uint DeviceNumber;
            public uint PartitionNumber;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVICE_INTERFACE_DATA
        {
            public int cbSize;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        // -------------------- P/Invoke --------------------

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, int nInBufferSize,
            out STORAGE_DEVICE_NUMBER lpOutBuffer,
            int nOutBufferSize, out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GetVolumeInformation(
            string rootPathName,
            StringBuilder volumeNameBuffer,
            int volumeNameSize,
            IntPtr serialNumber,
            IntPtr maxComponentLen,
            IntPtr fileSystemFlags,
            StringBuilder fileSystemNameBuffer,
            int fileSystemNameSize);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInterfaces(
            IntPtr DeviceInfoSet, IntPtr DeviceInfoData,
            ref Guid InterfaceClassGuid, uint MemberIndex,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        // Use Unicode explicit entry and IntPtr for the last parameter to avoid ref/out binding issues
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiGetDeviceInterfaceDetailW")]
        private static extern bool SetupDiGetDeviceInterfaceDetail_IntPtr(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            IntPtr DeviceInterfaceDetailData,
            uint DeviceInterfaceDetailDataSize,
            out uint RequiredSize,
            IntPtr DeviceInfoData);

        [DllImport("setupapi.dll")]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Auto)]
        private static extern int CM_Get_Device_ID(
            uint devInst, StringBuilder Buffer, int BufferLen, int ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Auto)]
        private static extern int CM_Get_Parent(out uint pdnDevInst, uint dnDevInst, int ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Auto)]
        private static extern uint CM_Request_Device_Eject(
            uint devInst, out int pVetoType,
            StringBuilder pszVetoName, int ulNameLength, uint ulFlags);

        // -------------------- Volume enumeration P/Invoke --------------------

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstVolumeW([Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextVolumeW(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindVolumeClose(IntPtr hFindVolume);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            string lpszVolumeName,
            [Out] char[] lpszVolumePathNames,
            uint cchBufferLength,
            out uint lpcchReturnLength);

        // -------------------- Public API --------------------

        /// <summary>
        /// Get all USB storage drives including:
        /// - drive letters (existing behavior)
        /// - volumes mounted to NTFS folders (no drive letter) — displays mount folder path
        /// </summary>
        public static List<UsbDriveInfo> GetUsbStorageDrives()
        {
            LOG("============== ENUM START ==============");
            var result = new List<UsbDriveInfo>();

            // track drive letters we've already added (uppercase like "E:\")
            var seenRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1) Existing logic: drives with letters
            foreach (var d in DriveInfo.GetDrives())
            {
                LOG($"> Drive {d.Name} Ready={d.IsReady} Type={d.DriveType}");

                if (!d.IsReady)
                    continue;

                if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable)
                {
                    LOG("  Skipped: unsupported drive type");
                    continue;
                }

                if (!TryGetDeviceNumber(d.Name, out var deviceNumber))
                {
                    LOG("  IOCTL_STORAGE_GET_DEVICE_NUMBER FAILED");
                    continue;
                }

                LOG($"  DeviceNumber={deviceNumber.DeviceNumber}");

                uint devInst = FindDevInstFromDeviceNumber(deviceNumber.DeviceNumber, out string instanceId);
                LOG($"  DevInst={devInst}, InstanceId={instanceId}");

                if (devInst == 0)
                    continue;

                bool usb = IsDeviceUsbBacked(devInst);
                LOG($"  USB-backed={usb}");

                if (!usb)
                    continue;

                ExtractVidPidFromDevInst(devInst, out string vid, out string pid);

                var drive = new UsbDriveInfo
                {
                    IsSelected = false,
                    DriveLetter = d.Name,                // e.g. "E:\"
                    VolumeLabel = d.VolumeLabel,
                    NtfsVolumeName = GetNtfsLabel(d.Name),
                    VendorId = vid,
                    ProductId = pid,
                    DevInst = devInst,
                    MountedPath = null
                };

                result.Add(drive);
                seenRoots.Add(d.Name.TrimEnd('\\').ToUpperInvariant() + @"\");
                LOG("  Added USB DRIVE (letter)");
            }

            // 2) New logic: enumerate all volumes and find mount points that are NTFS folder mount points (no single-root drive letter)
            foreach (var vol in EnumerateAllVolumes())
            {
                // get mount paths for this volume
                var mounts = GetVolumeMountPoints(vol);
                if (mounts == null || mounts.Count == 0)
                    continue;

                // find mount paths that are *not* simple root drive letters (e.g. "C:\Mounts\USB1\")
                foreach (var mp in mounts)
                {
                    // Normalize trailing backslash
                    string mount = mp;
                    if (!mount.EndsWith("\\"))
                        mount = mount + "\\";

                    // skip if this is a root drive letter like "E:\"
                    if (mount.Length == 3 && mount[1] == ':' && mount[2] == '\\')
                    {
                        // this volume is already represented by a drive letter - skip (or it was added above)
                        LOG($"  Volume {vol} mount {mount} is root drive letter - skipped");
                        continue;
                    }

                    // if mount path's root was already added as a drive letter representing the same volume, skip
                    string rootOfMount = Path.GetPathRoot(mount) ?? "";
                    if (!string.IsNullOrEmpty(rootOfMount) && seenRoots.Contains(rootOfMount.TrimEnd('\\').ToUpperInvariant() + @"\"))
                    {
                        LOG($"  Mount {mount} root {rootOfMount} already seen - skipped");
                        continue;
                    }

                    // Now open the volume (volume name like "\\?\Volume{GUID}\")
                    if (!TryGetDeviceNumber(vol, out var sdnum))
                    {
                        LOG($"  Could not get device number for volume {vol} (mount {mount})");
                        continue;
                    }

                    LOG($"  Volume {vol} DeviceNumber={sdnum.DeviceNumber}");

                    uint devInst = FindDevInstFromDeviceNumber(sdnum.DeviceNumber, out string instanceId);
                    LOG($"  DevInst={devInst}, InstanceId={instanceId}");

                    if (devInst == 0)
                        continue;

                    bool usb = IsDeviceUsbBacked(devInst);
                    LOG($"  USB-backed={usb}");

                    if (!usb)
                        continue;

                    // Extract VID/PID
                    ExtractVidPidFromDevInst(devInst, out string vid2, out string pid2);

                    // Build entry showing the mount folder path (user asked for A: show mount folder paths)
                    var driveInfo = new UsbDriveInfo
                    {
                        IsSelected = false,
                        DriveLetter = null,               // no drive letter
                        VolumeLabel = GetVolumeLabelFromMount(mount), // try get volume label via GetVolumeInformation using mount path
                        NtfsVolumeName = GetNtfsLabel(mount),
                        VendorId = vid2,
                        ProductId = pid2,
                        DevInst = devInst,
                        MountedPath = mount               // custom field; ensure your UsbDriveInfo contains it (or store mount in VolumeLabel/NtfsVolumeName)
                    };

                    result.Add(driveInfo);
                    LOG($"  Added USB DRIVE (mount) {mount}");
                }
            }

            LOG("============== ENUM END ================");
            return result;
        }

        // -------------------- Volume enumeration helpers --------------------

        /// <summary>
        /// Enumerate all volumes (\\?\Volume{GUID}\)
        /// </summary>
        private static IEnumerable<string> EnumerateAllVolumes()
        {
            const int initialBuffer = 1024;
            StringBuilder sb = new StringBuilder(initialBuffer);
            IntPtr findHandle = FindFirstVolumeW(sb, (uint)sb.Capacity);
            if (findHandle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                LOG($"FindFirstVolumeW failed lastErr={err}");
                yield break;
            }

            try
            {
                string vol = sb.ToString();
                if (!string.IsNullOrEmpty(vol))
                    yield return vol;

                while (true)
                {
                    sb = new StringBuilder(initialBuffer);
                    bool ok = FindNextVolumeW(findHandle, sb, (uint)sb.Capacity);
                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 18 /* ERROR_NO_MORE_FILES */)
                            break;
                        LOG($"FindNextVolumeW failed lastErr={err}");
                        break;
                    }

                    string next = sb.ToString();
                    if (!string.IsNullOrEmpty(next))
                        yield return next;
                }
            }
            finally
            {
                FindVolumeClose(findHandle);
            }
        }

        /// <summary>
        /// Get all mount points for a volume (drive letters and NTFS mount folders).
        /// Returns paths with trailing backslash, e.g. "C:\Mounts\USB1\"
        /// </summary>
        private static List<string> GetVolumeMountPoints(string volumeName)
        {
            // initial buffer
            uint bufLen = 1024;
            char[] buffer = new char[bufLen];
            bool ok = GetVolumePathNamesForVolumeNameW(volumeName, buffer, bufLen, out uint returnLen);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == 234 /* ERROR_MORE_DATA */)
                {
                    // allocate required size
                    bufLen = returnLen;
                    buffer = new char[bufLen];
                    ok = GetVolumePathNamesForVolumeNameW(volumeName, buffer, bufLen, out returnLen);
                    if (!ok)
                    {
                        LOG($"GetVolumePathNamesForVolumeNameW retry failed lastErr={Marshal.GetLastWin32Error()} volume={volumeName}");
                        return new List<string>();
                    }
                }
                else
                {
                    LOG($"GetVolumePathNamesForVolumeNameW failed lastErr={err} volume={volumeName}");
                    return new List<string>();
                }
            }

            // buffer contains multiple null-terminated strings end in double-null
            var mounts = new List<string>();
            int i = 0;
            var sb = new StringBuilder();
            while (i < returnLen && i < buffer.Length)
            {
                char c = buffer[i++];
                if (c == '\0')
                {
                    if (sb.Length == 0)
                    {
                        // consecutive null => end
                        break;
                    }

                    string path = sb.ToString();
                    // ensure trailing backslash
                    if (!path.EndsWith("\\"))
                        path += "\\";
                    mounts.Add(path);
                    sb.Clear();
                }
                else
                {
                    sb.Append(c);
                }
            }

            return mounts;
        }

        private static string GetVolumeLabelFromMount(string mountPath)
        {
            try
            {
                var vol = new StringBuilder(256);
                var fs = new StringBuilder(256);
                bool ok = GetVolumeInformation(mountPath, vol, vol.Capacity, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, fs, fs.Capacity);
                if (ok) return vol.ToString();
            }
            catch { }
            return string.Empty;
        }

        // -------------------- IOCTL and SetupAPI helpers --------------------

        /// <summary>
        /// Get device number for a root path.
        /// Handles:
        ///  - drive root like "E:\"
        ///  - volume GUID like "\\?\Volume{GUID}\"
        /// This avoids blindly prefixing "\\.\" to strings that already start with "\\?\" or "\\.\"
        /// </summary>
        private static bool TryGetDeviceNumber(string root, out STORAGE_DEVICE_NUMBER dev)
        {
            dev = new STORAGE_DEVICE_NUMBER();

            if (string.IsNullOrEmpty(root))
                return false;

            // Normalization: if root already starts with \\?\ or \\.\, use it directly.
            // Otherwise prefix with \\.\ to open the volume/drive.
            string path;
            if (root.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ||
                root.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
            {
                // Trim trailing backslash for CreateFile compatibility
                path = root.TrimEnd('\\');
            }
            else
            {
                // root like "E:\" -> prefix to "\\.\E:"
                path = @"\\.\" + root.TrimEnd('\\');
            }

            LOG($"  CreateFile({path})");

            IntPtr h = CreateFile(path, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                LOG($"  CreateFile failed for {path} handle={h} lastErr={err}");
                return false;
            }

            bool ok = DeviceIoControl(
                h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                IntPtr.Zero, 0,
                out dev, Marshal.SizeOf<STORAGE_DEVICE_NUMBER>(),
                out _, IntPtr.Zero);

            int ioctlErr = Marshal.GetLastWin32Error();
            LOG($"  DeviceIoControl ok={ok} lastErr={ioctlErr} DeviceNumber={dev.DeviceNumber}");

            CloseHandle(h);
            return ok;
        }

        // Normalize and open device-interface or volume paths; works with:
        //  - device interface strings like "?\scsi#disk&ven_...#{GUID}"
        //  - full volume names like "\\?\Volume{GUID}\"
        private static bool TryGetDeviceNumberFromPath(string deviceInterfacePath, out STORAGE_DEVICE_NUMBER dev)
        {
            dev = new STORAGE_DEVICE_NUMBER();

            if (string.IsNullOrEmpty(deviceInterfacePath))
                return false;

            // Normalize: remove leading backslashes and '?' then prefix with \\?\
            string trimmed = deviceInterfacePath.TrimStart('\\');
            trimmed = trimmed.TrimStart('?');
            trimmed = trimmed.TrimStart('\\');

            string normalized = @"\\?\" + trimmed;

            LOG($"    Normalized interface path='{normalized}'");

            IntPtr h = CreateFile(normalized, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                LOG($"    CreateFile(normalized) FAILED handle={h} lastErr={err} path='{normalized}'");
                return false;
            }

            LOG($"    CreateFile(normalized) succeeded handle={h}");

            bool ok = DeviceIoControl(
                h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                IntPtr.Zero, 0,
                out dev, Marshal.SizeOf<STORAGE_DEVICE_NUMBER>(),
                out _, IntPtr.Zero);

            int ioctlErr = Marshal.GetLastWin32Error();
            LOG($"    DeviceIoControl IOCTL_STORAGE_GET_DEVICE_NUMBER ok={ok} lastErr={ioctlErr} DeviceNumber={dev.DeviceNumber}");

            CloseHandle(h);
            return ok;
        }

        // Use a local copy of GUID to avoid passing static readonly by ref
        private static uint FindDevInstFromDeviceNumber(uint targetDeviceNumber, out string instanceId)
        {
            instanceId = string.Empty;
            Guid localGuid = GUID_DEVINTERFACE_DISK;

            IntPtr deviceInfoSet = SetupDiGetClassDevs(ref localGuid, IntPtr.Zero, IntPtr.Zero,
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

            if (deviceInfoSet == IntPtr.Zero || deviceInfoSet == new IntPtr(-1))
            {
                LOG("  SetupDiGetClassDevs failed");
                return 0;
            }

            try
            {
                uint memberIndex = 0;

                while (true)
                {
                    var ifData = new SP_DEVICE_INTERFACE_DATA
                    {
                        cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>()
                    };

                    bool enumOk = SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref localGuid, memberIndex, ref ifData);
                    if (!enumOk)
                    {
                        LOG("  No more interfaces");
                        break;
                    }

                    // First ask for required size
                    bool reqOk = SetupDiGetDeviceInterfaceDetail_IntPtr(deviceInfoSet, ref ifData, IntPtr.Zero, 0, out uint requiredSize, IntPtr.Zero);
                    int reqErr = Marshal.GetLastWin32Error();
                    LOG($"    SetupDiGetDeviceInterfaceDetail(required) ok={reqOk} requiredSize={requiredSize} lastErr={reqErr}");

                    if (requiredSize == 0)
                    {
                        memberIndex++;
                        continue;
                    }

                    IntPtr detailBuffer = IntPtr.Zero;
                    IntPtr devInfoUnmanaged = IntPtr.Zero;
                    try
                    {
                        detailBuffer = Marshal.AllocHGlobal((int)requiredSize);

                        int cbSize = (IntPtr.Size == 8) ? 8 : (4 + Marshal.SystemDefaultCharSize);
                        Marshal.WriteInt32(detailBuffer, cbSize);

                        devInfoUnmanaged = Marshal.AllocHGlobal(Marshal.SizeOf<SP_DEVINFO_DATA>());
                        Marshal.WriteInt32(devInfoUnmanaged, Marshal.SizeOf<SP_DEVINFO_DATA>());

                        bool gotDetail = SetupDiGetDeviceInterfaceDetail_IntPtr(
                            deviceInfoSet, ref ifData, detailBuffer, requiredSize, out requiredSize, devInfoUnmanaged);

                        int detailErr = Marshal.GetLastWin32Error();
                        LOG($"    SetupDiGetDeviceInterfaceDetail(fill) gotDetail={gotDetail} lastErr={detailErr}");

                        if (!gotDetail)
                        {
                            memberIndex++;
                            continue;
                        }

                        IntPtr pathPtr = IntPtr.Add(detailBuffer, cbSize);
                        string devicePath = Marshal.PtrToStringUni(pathPtr);
                        LOG($"    Interface path='{(devicePath ?? "<null>")}'");

                        SP_DEVINFO_DATA filledDevInfo = Marshal.PtrToStructure<SP_DEVINFO_DATA>(devInfoUnmanaged);

                        if (!string.IsNullOrEmpty(devicePath) && TryGetDeviceNumberFromPath(devicePath, out var sdnum))
                        {
                            LOG($"      Interface DeviceNumber={sdnum.DeviceNumber}");
                            if (sdnum.DeviceNumber == targetDeviceNumber)
                            {
                                var sb = new StringBuilder(512);
                                if (CM_Get_Device_ID(filledDevInfo.DevInst, sb, sb.Capacity, 0) == 0)
                                    instanceId = sb.ToString();

                                LOG("    MATCH FOUND");
                                return filledDevInfo.DevInst;
                            }
                        }
                        else
                        {
                            LOG("      Could not get device number from interface path");
                        }
                    }
                    finally
                    {
                        if (detailBuffer != IntPtr.Zero) Marshal.FreeHGlobal(detailBuffer);
                        if (devInfoUnmanaged != IntPtr.Zero) Marshal.FreeHGlobal(devInfoUnmanaged);
                    }

                    memberIndex++;
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }

            LOG("  No matching DevInst found");
            return 0;
        }

        // -------------------- USB ancestry & VID/PID --------------------

        private static bool IsDeviceUsbBacked(uint devInst)
        {
            LOG($"  IsDeviceUsbBacked start devInst={devInst}");
            uint cur = devInst;

            for (int depth = 0; depth < 50; depth++)
            {
                var sb = new StringBuilder(512);
                if (CM_Get_Device_ID(cur, sb, sb.Capacity, 0) != 0)
                {
                    LOG($"    CM_Get_Device_ID returned nonzero for devInst={cur}");
                    break;
                }

                string id = sb.ToString();
                LOG($"    ancestor[{depth}] = {id}");

                if (id.IndexOf("USB", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    id.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    id.IndexOf("VID_", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    LOG("    Found USB ancestor");
                    return true;
                }

                if (CM_Get_Parent(out uint parent, cur, 0) != 0 || parent == 0)
                {
                    LOG("    No parent or CM_Get_Parent failed");
                    break;
                }

                cur = parent;
            }

            return false;
        }

        private static void ExtractVidPidFromDevInst(uint devInst, out string vid, out string pid)
        {
            vid = string.Empty;
            pid = string.Empty;

            uint cur = devInst;
            for (int depth = 0; depth < 50; depth++)
            {
                var sb = new StringBuilder(512);
                if (CM_Get_Device_ID(cur, sb, sb.Capacity, 0) != 0) break;

                string id = sb.ToString();
                LOG($"    VID/PID node[{depth}] = {id}");

                string[] parts = id.Split(new[] { '\\', '&' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var p in parts)
                {
                    if (p.StartsWith("VID_", StringComparison.OrdinalIgnoreCase) && p.Length >= 8)
                        vid = p.Substring(4);
                    if (p.StartsWith("PID_", StringComparison.OrdinalIgnoreCase) && p.Length >= 8)
                        pid = p.Substring(4);
                }

                if (!string.IsNullOrEmpty(vid) || !string.IsNullOrEmpty(pid)) return;

                if (CM_Get_Parent(out uint parent, cur, 0) != 0 || parent == 0) break;
                cur = parent;
            }
        }

        // -------------------- NTFS label --------------------

        private static string GetNtfsLabel(string root)
        {
            try
            {
                var vol = new StringBuilder(256);
                var fs = new StringBuilder(256);

                bool ok = GetVolumeInformation(root, vol, vol.Capacity,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    fs, fs.Capacity);

                LOG($"    GetVolumeInformation ok={ok} label='{vol}' fs='{fs}'");
                return ok ? vol.ToString() : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        // -------------------- Eject --------------------

        public static bool RequestDeviceEject(uint devInst)
        {
            var vetoName = new StringBuilder(512);
            uint code = CM_Request_Device_Eject(devInst, out int vetoType, vetoName, vetoName.Capacity, 0);
            LOG($"  RequestDeviceEject devInst={devInst} code={code} vetoType={vetoType} veto='{vetoName}'");
            return code == 0 && vetoType == 0;
        }
    }
}
