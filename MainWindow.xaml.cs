using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;

namespace UsbEjector
{
    public partial class MainWindow : Window
    {
        public ObservableCollection<UsbDriveInfo> Drives { get; set; }
            = new ObservableCollection<UsbDriveInfo>();

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            RefreshDriveList();
        }

        private void RefreshDriveList()
        {
            Drives.Clear();
            foreach (var d in UsbSafeRemoval.GetUsbStorageDrives())
                Drives.Add(d);
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

            foreach (var drive in selected)
            {
                bool ok = UsbSafeRemoval.RequestDeviceEject(drive.DevInst);

                MessageBox.Show(ok
                    ? $"✔ Ejected {drive.DriveLetter}"
                    : $"✖ Failed to eject {drive.DriveLetter}");
            }

            RefreshDriveList();
        }
    }
}
