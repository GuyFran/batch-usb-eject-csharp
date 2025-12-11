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

        // Disk class GUID - keep as readonly but DO NOT pass it by ref directly
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

        // Use explicit Unicode entrypoint and IntPtr for the last parameter to avoid ref/out on managed struct
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

        // -------------------- Public API --------------------

        public static List<UsbDriveInfo> GetUsbStorageDrives()
        {
            LOG("============== ENUM START ==============");
            var result = new List<UsbDriveInfo>();

            foreach (var d in DriveInfo.GetDrives())
            {
                LOG($"> Drive {d.Name} Ready={d.IsReady} Type={d.DriveType}");

                if (!d.IsReady)
                    continue;

                // Include Fixed because many USB HDDs show as Fixed; include Removable for sticks
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
                    DriveLetter = d.Name,
                    VolumeLabel = d.VolumeLabel,
                    NtfsVolumeName = GetNtfsLabel(d.Name),
                    VendorId = vid,
                    ProductId = pid,
                    DevInst = devInst
                };

                result.Add(drive);
                LOG("  Added USB DRIVE");
            }

            LOG("============== ENUM END ================");
            return result;
        }

        // -------------------- Helpers --------------------

        private static bool TryGetDeviceNumber(string root, out STORAGE_DEVICE_NUMBER dev)
        {
            dev = new STORAGE_DEVICE_NUMBER();
            string path = @"\\.\" + root.TrimEnd('\\');

            LOG($"  CreateFile({path})");

            // dwDesiredAccess = 0, dwShareMode = FILE_SHARE_READ|FILE_SHARE_WRITE = 3, OPEN_EXISTING = 3
            IntPtr h = CreateFile(path, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
                return false;

            bool ok = DeviceIoControl(
                h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                IntPtr.Zero, 0,
                out dev, Marshal.SizeOf<STORAGE_DEVICE_NUMBER>(),
                out _, IntPtr.Zero);

            CloseHandle(h);
            return ok;
        }

        // Use localGuid to avoid passing static readonly by ref
        private static uint FindDevInstFromDeviceNumber(uint targetDeviceNumber, out string instanceId)
        {
            instanceId = string.Empty;

            // copy GUID into a local variable to avoid passing a static readonly field by ref
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

                    // First ask for the required buffer size (pass IntPtr.Zero for detail & devinfo)
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
                        // allocate both buffers
                        detailBuffer = Marshal.AllocHGlobal((int)requiredSize);

                        // cbSize for SP_DEVICE_INTERFACE_DETAIL_DATA structure:
                        // On x64 the cbSize is 8 (DWORD + padding); on x86 it's 4 + char size
                        int cbSize = (IntPtr.Size == 8) ? 8 : (4 + Marshal.SystemDefaultCharSize);
                        Marshal.WriteInt32(detailBuffer, cbSize);

                        // allocate unmanaged SP_DEVINFO_DATA and write its cbSize
                        devInfoUnmanaged = Marshal.AllocHGlobal(Marshal.SizeOf<SP_DEVINFO_DATA>());
                        Marshal.WriteInt32(devInfoUnmanaged, Marshal.SizeOf<SP_DEVINFO_DATA>());

                        // Now call the fill variant passing pointers
                        bool gotDetail = SetupDiGetDeviceInterfaceDetail_IntPtr(
                            deviceInfoSet, ref ifData, detailBuffer, requiredSize, out requiredSize, devInfoUnmanaged);

                        int detailErr = Marshal.GetLastWin32Error();
                        LOG($"    SetupDiGetDeviceInterfaceDetail(fill) gotDetail={gotDetail} lastErr={detailErr}");

                        if (!gotDetail)
                        {
                            memberIndex++;
                            continue;
                        }

                        // Extract device path from the detailBuffer at offset cbSize
                        IntPtr pathPtr = IntPtr.Add(detailBuffer, cbSize);
                        string devicePath = Marshal.PtrToStringUni(pathPtr);
                        LOG($"    Interface path='{(devicePath ?? "<null>")}'");

                        // Marshal filled SP_DEVINFO_DATA back to managed struct
                        SP_DEVINFO_DATA filledDevInfo = Marshal.PtrToStructure<SP_DEVINFO_DATA>(devInfoUnmanaged);

                        // Query interface device number and compare
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

        /// <summary>
        /// Normalize device-interface path and call CreateFile + IOCTL_STORAGE_GET_DEVICE_NUMBER.
        /// Handles paths like:
        ///    "?\scsi#disk&ven_...#...#{GUID}"
        ///    "\\?\scsi#disk&..."
        ///    "\?\scsi#..."
        /// and ensures we pass a path CreateFile accepts (\\?\...)
        /// </summary>
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

                // split on typical separators
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

        private static string GetNtfsLabel(string root)
        {
            var vol = new StringBuilder(256);
            var fs = new StringBuilder(256);

            bool ok = GetVolumeInformation(root, vol, vol.Capacity,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                fs, fs.Capacity);

            LOG($"    GetVolumeInformation ok={ok} label='{vol}' fs='{fs}'");
            return ok ? vol.ToString() : string.Empty;
        }

        public static bool RequestDeviceEject(uint devInst)
        {
            var vetoName = new StringBuilder(512);
            uint code = CM_Request_Device_Eject(devInst, out int vetoType, vetoName, vetoName.Capacity, 0);
            LOG($"  RequestDeviceEject devInst={devInst} code={code} vetoType={vetoType} veto='{vetoName}'");
            return code == 0 && vetoType == 0;
        }
    }
}
