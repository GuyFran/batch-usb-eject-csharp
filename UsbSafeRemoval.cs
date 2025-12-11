using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace UsbEjector
{
    public static class UsbSafeRemoval
    {
        // ---------------------------------------------------------
        // Windows API structures and constants
        // ---------------------------------------------------------

        private const int DIGCF_PRESENT = 0x02;
        private const int DIGCF_DEVICEINTERFACE = 0x10;

        private static readonly Guid GUID_DEVINTERFACE_DISK =
            new Guid("53f56307-b6bf-11d0-94f2-00a0c91efb8b");

        private const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080;

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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            public int cbSize;

            // Allow large device path
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
            public string DevicePath;
        }

        // ---------------------------------------------------------
        // P/Invoke
        // ---------------------------------------------------------

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            out STORAGE_DEVICE_NUMBER lpOutBuffer,
            int nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
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
            ref Guid ClassGuid,
            IntPtr Enumerator,
            IntPtr hwndParent,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInterfaces(
            IntPtr DeviceInfoSet,
            IntPtr DeviceInfoData,
            ref Guid InterfaceClassGuid,
            uint MemberIndex,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiGetDeviceInterfaceDetail(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
            uint DeviceInterfaceDetailDataSize,
            ref uint RequiredSize,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll")]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Auto)]
        private static extern uint CM_Request_Device_Eject(
            uint devInst,
            out int pVetoType,
            StringBuilder pszVetoName,
            int ulNameLength,
            uint ulFlags);


        // =====================================================================
        // PUBLIC API: Enumerate USB Mass Storage Devices
        // =====================================================================

        public static List<UsbDriveInfo> GetUsbStorageDrives()
        {
            List<UsbDriveInfo> result = new();

            foreach (var d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) continue;
                if (d.DriveType != DriveType.Removable) continue;

                // Step 1: Drive letter → DeviceNumber
                if (!TryGetDeviceNumber(d.Name, out var devNum))
                    continue;

                // Step 2: Match DeviceNumber → DevInst & PNP ID
                uint devInst = FindDevInstFromDeviceNumber(devNum.DeviceNumber, out string pnpId);
                if (devInst == 0) continue;

                // Step 3: Ensure it's USB mass storage
                if (!pnpId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Step 4: Extract VID/PID
                ExtractVidPid(pnpId, out string vid, out string pid);

                // Step 5: NTFS label via Win32
                string ntfsName = GetNtfsVolumeName(d.Name);

                result.Add(new UsbDriveInfo
                {
                    DriveLetter = d.Name,
                    VolumeLabel = d.VolumeLabel,
                    NtfsVolumeName = ntfsName,
                    VendorId = vid,
                    ProductId = pid,
                    DevInst = devInst
                });
            }

            return result;
        }


        // =====================================================================
        // Device Number helper
        // =====================================================================

        private static bool TryGetDeviceNumber(string root, out STORAGE_DEVICE_NUMBER devNum)
        {
            devNum = new STORAGE_DEVICE_NUMBER();

            string path = @"\\.\" + root.TrimEnd('\\');

            IntPtr h = CreateFile(path, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h.ToInt64() == -1)
                return false;

            bool ok = DeviceIoControl(
                h,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                IntPtr.Zero,
                0,
                out devNum,
                Marshal.SizeOf(typeof(STORAGE_DEVICE_NUMBER)),
                out _,
                IntPtr.Zero);

            CloseHandle(h);
            return ok;
        }


        // =====================================================================
        // DeviceNumber → DevInst mapping (SetupAPI)
        // =====================================================================

        private static uint FindDevInstFromDeviceNumber(uint targetNum, out string pnpId)
        {
            pnpId = "";

            Guid g = GUID_DEVINTERFACE_DISK;
            IntPtr h = SetupDiGetClassDevs(ref g, IntPtr.Zero, IntPtr.Zero,
                                           DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

            if (h == IntPtr.Zero || h.ToInt64() == -1)
                return 0;

            uint index = 0;

            try
            {
                while (true)
                {
                    SP_DEVICE_INTERFACE_DATA ifData = new();
                    ifData.cbSize = Marshal.SizeOf(ifData);

                    Guid g2 = GUID_DEVINTERFACE_DISK;

                    if (!SetupDiEnumDeviceInterfaces(h, IntPtr.Zero,
                                                     ref g2, index, ref ifData))
                        break;

                    SP_DEVICE_INTERFACE_DETAIL_DATA detail = new();
                    detail.cbSize = IntPtr.Size == 8 ? 8 : 6;

                    SP_DEVINFO_DATA info = new();
                    info.cbSize = Marshal.SizeOf(info);

                    uint req = 0;

                    SetupDiGetDeviceInterfaceDetail(h, ref ifData,
                        ref detail,
                        (uint)Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DETAIL_DATA)),
                        ref req,
                        ref info);

                    if (TryGetDeviceNumberFromPath(detail.DevicePath, out var num))
                    {
                        if (num.DeviceNumber == targetNum)
                        {
                            pnpId = detail.DevicePath;
                            return info.DevInst;
                        }
                    }

                    index++;
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(h);
            }

            return 0;
        }

        private static bool TryGetDeviceNumberFromPath(string path, out STORAGE_DEVICE_NUMBER devNum)
        {
            devNum = new STORAGE_DEVICE_NUMBER();

            IntPtr h = CreateFile(path, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h.ToInt64() == -1)
                return false;

            bool ok = DeviceIoControl(
                h,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                IntPtr.Zero,
                0,
                out devNum,
                Marshal.SizeOf(typeof(STORAGE_DEVICE_NUMBER)),
                out _,
                IntPtr.Zero);

            CloseHandle(h);
            return ok;
        }


        // =====================================================================
        // Extract VID/PID from PNP ID string
        // =====================================================================

        private static void ExtractVidPid(string pnpId, out string vid, out string pid)
        {
            vid = "";
            pid = "";

            string[] parts = pnpId.Split('\\', '&');

            foreach (string p in parts)
            {
                if (p.StartsWith("VID_", StringComparison.OrdinalIgnoreCase))
                    vid = p.Substring(4);
                if (p.StartsWith("PID_", StringComparison.OrdinalIgnoreCase))
                    pid = p.Substring(4);
            }
        }


        // =====================================================================
        // NTFS Label (Volume Name)
        // =====================================================================

        private static string GetNtfsVolumeName(string root)
        {
            var vol = new StringBuilder(256);
            var fs = new StringBuilder(256);

            bool ok = GetVolumeInformation(
                root,
                vol,
                vol.Capacity,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                fs,
                fs.Capacity);

            return ok ? vol.ToString() : "";
        }


        // =====================================================================
        // SAFE EJECT
        // =====================================================================

        public static bool RequestDeviceEject(uint devInst)
        {
            int veto;
            var sb = new StringBuilder(256);

            uint code = CM_Request_Device_Eject(devInst, out veto, sb, sb.Capacity, 0);

            return (code == 0 && veto == 0);
        }
    }
}
