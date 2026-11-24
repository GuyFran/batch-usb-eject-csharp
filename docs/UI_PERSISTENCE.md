# UI persistence — inventory

Proof of completeness for the global rule "persist ALL UI geometry and layout". Inventoried from the code
(`MainWindow.xaml, MainWindow.xaml.cs`) on 2026-11-25, version 1.0.3. A new window or adjustable element is added here in the same change.

Store: `%APPDATA%\UsbEjector\layout.json` (`UiLayout` / `UiLayoutStore` in `UiLayout.cs`), written by `LayoutPersistence`
shortly after the last change and at once on close. Window placement is restored in `SourceInitialized`
(before first show) with `Get/SetWindowPlacement`, clamped / rescaled to the monitors present now
(`WindowPlacementMath.Fit`), never minimized; maximized keeps its normal bounds.

| Element | What is kept | Key | Status |
| --- | --- | --- | --- |
| Main window | Normal bounds, maximized, monitor, DPI | `Windows["Main"]` | persisted (1.0.1) |
| Drives list (GridView) | Column widths, order | `Grids["DrivesList"]` | persisted (1.0.1) |
| Drives list | Scroll position | `Scroll["DrivesList"]` | persisted (1.0.3) |
| Drive check boxes | Which drives to eject: action targets re-read from the system on each refresh | — | not layout |
| Buttons, row heights | Fixed, nothing adjustable | — | nothing to keep |
| Result / error message boxes | Windows `MessageBox`, centred by the OS | — | nothing to keep |
