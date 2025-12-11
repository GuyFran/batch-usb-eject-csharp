namespace UsbEjector
{
    public class UsbDriveInfo
    {
        public string DriveLetter { get; set; } = "";
        public string VolumeLabel { get; set; } = "";
        public string NtfsVolumeName { get; set; } = "";
        public string VendorId { get; set; } = "";
        public string ProductId { get; set; } = "";
        public uint DevInst { get; set; }
        public bool IsSelected { get; set; }
    }
}
