using System.Collections.Generic;
using System.Linq;
using System.Windows;
using UsbEjector;

namespace UsbEjector
{
    public partial class MainWindow : Window
    {
        public const string AppVersion = "1.0.2";

        private List<UsbDriveInfo> Drives = new();
        private readonly LayoutPersistence layout;

        public MainWindow()
        {
            InitializeComponent();
            Title = $"USB Batch Ejector v{AppVersion}";

            layout = new LayoutPersistence(UiLayoutStore.PathFor("UsbEjector"), Dispatcher);
            WindowGeometry.Track(this, "Main", layout);
            GridViewLayout.Track(DrivesGridView, "DrivesList", layout);

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
