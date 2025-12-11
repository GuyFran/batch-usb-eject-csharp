namespace UsbEjector
{
    public class UsbDriveInfo
    {
        public bool IsSelected { get; set; }

        public string? DriveLetter { get; set; }       // E:\ or null
        public string? MountedPath { get; set; }        // C:\MOUNTS\ANIME1\ or null

        public string? VolumeLabel { get; set; }
        public string? NtfsVolumeName { get; set; }

        public string? VendorId { get; set; }
        public string? ProductId { get; set; }

        public uint DevInst { get; set; }

        public string DisplayName
        {
            get
            {
                string mount = DriveLetter ?? MountedPath ?? "<no mount>";
                string label = !string.IsNullOrEmpty(VolumeLabel) ? $" ({VolumeLabel})" : "";
                string pidvid = $" [{VendorId}:{ProductId}]";
                return mount + label + pidvid;
            }
        }
    }
}
