using System.Collections.Generic;
using System.Linq;
using System.Windows;
using UsbEjector;

namespace UsbEjector
{
    public partial class MainWindow : Window
    {
        private List<UsbDriveInfo> Drives = new();

        public MainWindow()
        {
            InitializeComponent();
            RefreshDriveList();
        }

        private void RefreshDriveList()
        {
            Drives = UsbSafeRemoval.GetUsbStorageDrives();
            DrivesList.ItemsSource = Drives;
            DrivesList.Items.Refresh();
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            RefreshDriveList();
        }

        private void Eject_Click(object sender, RoutedEventArgs e)
        {
            var selected = Drives.Where(d => d.IsSelected).ToList();

            if (selected.Count == 0)
            {
                MessageBox.Show("No drives selected.");
                return;
            }

            foreach (var drv in selected)
            {
                bool ok = UsbSafeRemoval.RequestDeviceEject(drv.DevInst);

                string mount = drv.DriveLetter ?? drv.MountedPath ?? "<unknown>";

                MessageBox.Show(ok
                    ? $"Safely removed: {mount}"
                    : $"Failed to eject: {mount}");
            }

            RefreshDriveList();
        }
    }
}
