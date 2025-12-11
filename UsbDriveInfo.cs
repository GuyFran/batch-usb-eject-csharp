namespace UsbEjector
{
    public class UsbDriveInfo
    {
        /// <summary>
        /// Whether user selected this drive in the UI.
        /// </summary>
        public bool IsSelected { get; set; }

        /// <summary>
        /// Drive letter (e.g. "E:\"), or null if mounted to folder only.
        /// </summary>
        public string DriveLetter { get; set; }

        /// <summary>
        /// Volume label from filesystem.
        /// </summary>
        public string VolumeLabel { get; set; }

        /// <summary>
        /// NTFS volume label OR mount name.
        /// </summary>
        public string NtfsVolumeName { get; set; }

        /// <summary>
        /// Vendor ID (VID).
        /// </summary>
        public string VendorId { get; set; }

        /// <summary>
        /// Product ID (PID).
        /// </summary>
        public string ProductId { get; set; }

        /// <summary>
        /// Config Manager devInst for eject operation.
        /// </summary>
        public uint DevInst { get; set; }

        /// <summary>
        /// Folder mount path (e.g. "C:\Mounts\USB1\"), null for letter drives.
        /// </summary>
        public string MountedPath { get; set; }
    }
}
