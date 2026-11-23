# UI / UX — USB Batch Ejector

The window as built, from `MainWindow.xaml(.cs)` on 2026-11-24. There is no design file or theme: controls use the
default WPF look.

## Window

Title `USB Batch Ejector v<version>`, default size 700 × 480, reopens where it was left.

| Row | Content |
|---|---|
| Top | **Refresh Drives** button, centered |
| Middle | Drive list, fills the space |
| Bottom | **Eject Selected** button, right-aligned |

## Drive list columns

Widths and order are remembered.

| Column | Shows | Default width |
|---|---|---|
| Select | Checkbox | 60 |
| Mount | Drive letter, such as `E:\` | 80 |
| NTFS Mount Path | Folder mount, such as `C:\MOUNTS\DISK1\` | 200 |
| Label | Volume label | 120 |
| VID | USB vendor ID | 60 |
| PID | USB product ID | 60 |

## Behaviour

| Action | Result |
|---|---|
| Open the app, or **Refresh Drives** | The list is rebuilt and all ticks are cleared |
| **Eject Selected**, nothing ticked | "No drives selected." |
| **Eject Selected**, drives ticked | Ejects in order. Each drive shows a box, "Safely removed: …" or "Failed to eject: …", which must be closed before the next one |
| After the batch | The list refreshes |

## Known gaps

Tracked in [BACKLOG.md](BACKLOG.md).

| Gap | Item |
|---|---|
| No status bar, version in the title only | B2 |
| Failure gives no reason | B5 |
| One modal box per drive interrupts the batch | B9 |
| Highlighted rows are not ejected, only ticked ones | B10 |
| No empty-state message when no drive is found | B10 |
