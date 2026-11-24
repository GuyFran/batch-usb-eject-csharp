#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;

namespace UsbEjector;

// Window and UI layout restored on start: window placement (normal bounds, maximized, monitor),
// DataGrid / GridView columns (width, order, sort) and selected tabs. Stored per machine in
// %APPDATA%\UsbEjector\layout.json. Pattern from claude-syncer-csharp (WindowGeometry, UiLayoutStore,
// WindowPlacementMath), trimmed into one file.
public sealed class UiLayout
{
    public const int CurrentSchema = 1;

    public int Schema { get; set; } = CurrentSchema;
    public Dictionary<string, WindowGeometryState> Windows { get; set; } = new();
    public Dictionary<string, GridLayoutState> Grids { get; set; } = new();
    public Dictionary<string, int> Tabs { get; set; } = new();
    /// <summary>Scroll offsets [vertical, horizontal] per scroll area (1.0.3).</summary>
    public Dictionary<string, double[]> Scroll { get; set; } = new();
    /// <summary>On / off view toggles and picked view values per key (1.0.3).</summary>
    public Dictionary<string, string> Values { get; set; } = new();
}

public sealed class WindowGeometryState
{
    public int Left { get; set; }
    public int Top { get; set; }
    public int Width { get; set; }
    public int Height { get; set; }
    public bool Maximized { get; set; }
    public string? Monitor { get; set; }
    public int Dpi { get; set; }

    public PxRect Bounds => new(Left, Top, Width, Height);
}

public sealed class GridLayoutState
{
    public List<ColumnLayoutState> Columns { get; set; } = new();
    public string? SortColumn { get; set; }
    public ListSortDirection? SortDirection { get; set; }
}

public sealed class ColumnLayoutState
{
    public string Key { get; set; } = "";
    public double Width { get; set; }
    public string? Unit { get; set; }
    public int DisplayIndex { get; set; }
}

public static class UiLayoutStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static string PathFor(string appFolder) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appFolder, "layout.json");

    public static UiLayout Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return new UiLayout();
            var layout = JsonSerializer.Deserialize<UiLayout>(File.ReadAllText(path), Options);
            if (layout is null || layout.Schema != UiLayout.CurrentSchema) return new UiLayout();
            layout.Windows ??= new();
            layout.Grids ??= new();
            layout.Tabs ??= new();
            layout.Scroll ??= new();
            layout.Values ??= new();
            foreach (var key in layout.Scroll.Where(p => p.Value is not { Length: 2 } v || v.Any(x => !double.IsFinite(x) || x < 0)).Select(p => p.Key).ToList())
                layout.Scroll.Remove(key);
            foreach (var key in layout.Windows.Where(p => p.Value is null || !IsSane(p.Value)).Select(p => p.Key).ToList())
                layout.Windows.Remove(key);
            return layout;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new UiLayout();
        }
    }

    public static void Save(string path, UiLayout layout)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            layout.Schema = UiLayout.CurrentSchema;
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(layout, Options));
            File.Move(temp, path, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException)
        {
        }
    }

    private static bool IsSane(WindowGeometryState s) =>
        s.Width is > 0 and < 100_000 && s.Height is > 0 and < 100_000 &&
        Math.Abs((long)s.Left) < 1_000_000 && Math.Abs((long)s.Top) < 1_000_000;
}

// Holds the loaded layout and writes it a short while after the last change, and at once on close.
public sealed class LayoutPersistence
{
    private readonly string _path;
    private readonly DispatcherTimer _timer;

    public LayoutPersistence(string path, Dispatcher dispatcher)
    {
        _path = path;
        Layout = UiLayoutStore.Load(path);
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(600), DispatcherPriority.Background, (_, _) => Flush(), dispatcher);
        _timer.Stop();
    }

    public UiLayout Layout { get; }

    public void Changed()
    {
        _timer.Stop();
        _timer.Start();
    }

    public void Flush()
    {
        _timer.Stop();
        UiLayoutStore.Save(_path, Layout);
    }
}

public readonly record struct PxRect(int Left, int Top, int Width, int Height)
{
    public int Right => Left + Width;
    public int Bottom => Top + Height;
    public long Area => (long)Width * Height;

    public PxRect Intersect(PxRect other)
    {
        var l = Math.Max(Left, other.Left);
        var t = Math.Max(Top, other.Top);
        var r = Math.Min(Right, other.Right);
        var b = Math.Min(Bottom, other.Bottom);
        return r > l && b > t ? new PxRect(l, t, r - l, b - t) : default;
    }
}

public sealed record MonitorArea(string Device, PxRect WorkArea, int Dpi, bool Primary);

// Decides where a saved window goes on the monitors present now: same monitor if it is still there,
// rescaled on a DPI change, clamped into the work area when it would be off-screen or too big.
public static class WindowPlacementMath
{
    private const int MinVisibleWidth = 120;
    private const int TitleStrip = 32;

    public static PxRect Fit(WindowGeometryState saved, IReadOnlyList<MonitorArea> monitors)
    {
        var rect = saved.Bounds;
        if (monitors.Count == 0) return rect;

        var target = monitors
            .Select(m => (Monitor: m, Overlap: rect.Intersect(m.WorkArea).Area))
            .Where(x => x.Overlap > 0)
            .OrderByDescending(x => x.Overlap)
            .Select(x => x.Monitor)
            .FirstOrDefault()
            ?? monitors.FirstOrDefault(m => string.Equals(m.Device, saved.Monitor, StringComparison.OrdinalIgnoreCase))
            ?? monitors.FirstOrDefault(m => m.Primary)
            ?? monitors[0];

        if (saved.Dpi > 0 && target.Dpi > 0 && saved.Dpi != target.Dpi)
        {
            var scale = (double)target.Dpi / saved.Dpi;
            rect = rect with { Width = (int)Math.Round(rect.Width * scale), Height = (int)Math.Round(rect.Height * scale) };
        }

        var area = target.WorkArea;
        var fits = rect.Width <= area.Width && rect.Height <= area.Height;
        return IsReachable(rect, monitors) && fits ? rect : ClampInto(rect, area);
    }

    private static bool IsReachable(PxRect rect, IReadOnlyList<MonitorArea> monitors)
    {
        var strip = rect with { Height = Math.Min(TitleStrip, rect.Height) };
        return monitors.Any(m =>
        {
            var hit = strip.Intersect(m.WorkArea);
            return hit.Width >= Math.Min(MinVisibleWidth, rect.Width) && hit.Top == strip.Top;
        });
    }

    private static PxRect ClampInto(PxRect rect, PxRect area)
    {
        var w = Math.Min(rect.Width, area.Width);
        var h = Math.Min(rect.Height, area.Height);
        var l = Math.Clamp(rect.Left, area.Left, area.Right - w);
        var t = Math.Clamp(rect.Top, area.Top, area.Bottom - h);
        return new PxRect(l, t, w, h);
    }
}

// Saves and restores a window's placement with Get/SetWindowPlacement. Restored in SourceInitialized,
// so the window is already in place when it first shows. Minimized is never restored.
public static class WindowGeometry
{
    public static void Track(Window window, string key, LayoutPersistence persistence)
    {
        var restored = false;
        if (persistence.Layout.Windows.ContainsKey(key))
            window.WindowStartupLocation = WindowStartupLocation.Manual;

        window.SourceInitialized += (_, _) =>
        {
            if (persistence.Layout.Windows.TryGetValue(key, out var saved))
                Apply(new WindowInteropHelper(window).Handle, saved);
            restored = true;
        };

        void Capture()
        {
            if (!restored) return;
            var state = Read(new WindowInteropHelper(window).Handle);
            if (state is null) return;
            persistence.Layout.Windows[key] = state;
            persistence.Changed();
        }

        window.LocationChanged += (_, _) => Capture();
        window.SizeChanged += (_, _) => Capture();
        window.StateChanged += (_, _) => Capture();
        window.Closing += (_, e) =>
        {
            if (e.Cancel) return;
            Capture();
            persistence.Flush();
        };
    }

    // Brings a minimized or hidden window back to the state it had before (maximized or normal).
    public static void ShowRestored(Window window)
    {
        window.Show();
        var hwnd = new WindowInteropHelper(window).Handle;
        var wp = WINDOWPLACEMENT.Create();
        if (window.WindowState == WindowState.Minimized)
        {
            var toMax = hwnd != IntPtr.Zero && GetWindowPlacement(hwnd, ref wp) && (wp.flags & WPF_RESTORETOMAXIMIZED) != 0;
            window.WindowState = toMax ? WindowState.Maximized : WindowState.Normal;
        }
        window.Activate();
    }

    private static WindowGeometryState? Read(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return null;
        var wp = WINDOWPLACEMENT.Create();
        if (!GetWindowPlacement(hwnd, ref wp)) return null;

        var maximized = wp.showCmd == SW_SHOWMAXIMIZED
            || (wp.showCmd == SW_SHOWMINIMIZED && (wp.flags & WPF_RESTORETOMAXIMIZED) != 0);

        var (dx, dy) = WorkspaceOffset();
        var r = wp.rcNormalPosition;
        var screen = new RECT { left = r.left + dx, top = r.top + dy, right = r.right + dx, bottom = r.bottom + dy };
        var info = Describe(MonitorFromRect(ref screen, MONITOR_DEFAULTTONEAREST));

        return new WindowGeometryState
        {
            Left = screen.left,
            Top = screen.top,
            Width = screen.right - screen.left,
            Height = screen.bottom - screen.top,
            Maximized = maximized,
            Monitor = info?.Device,
            Dpi = info?.Dpi ?? 0
        };
    }

    private static void Apply(IntPtr hwnd, WindowGeometryState saved)
    {
        if (hwnd == IntPtr.Zero) return;
        var fit = WindowPlacementMath.Fit(saved, Monitors());
        var (dx, dy) = WorkspaceOffset();

        var wp = WINDOWPLACEMENT.Create();
        if (!GetWindowPlacement(hwnd, ref wp)) return;
        wp.flags = 0;
        wp.showCmd = saved.Maximized ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
        wp.rcNormalPosition = new RECT { left = fit.Left - dx, top = fit.Top - dy, right = fit.Right - dx, bottom = fit.Bottom - dy };
        SetWindowPlacement(hwnd, ref wp);
    }

    private static List<MonitorArea> Monitors()
    {
        var list = new List<MonitorArea>();
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (h, _, _, _) =>
        {
            var m = Describe(h);
            if (m is not null) list.Add(m);
            return true;
        }, IntPtr.Zero);
        return list;
    }

    private static MonitorArea? Describe(IntPtr monitor)
    {
        if (monitor == IntPtr.Zero) return null;
        var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>() };
        if (!GetMonitorInfo(monitor, ref mi)) return null;
        var dpi = 96;
        try
        {
            if (GetDpiForMonitor(monitor, 0, out var x, out _) == 0) dpi = (int)x;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        var w = mi.rcWork;
        return new MonitorArea(mi.szDevice, new PxRect(w.left, w.top, w.right - w.left, w.bottom - w.top), dpi,
            (mi.dwFlags & MONITORINFOF_PRIMARY) != 0);
    }

    // WINDOWPLACEMENT uses workspace coordinates: screen coordinates shifted by the primary work area's origin.
    private static (int dx, int dy) WorkspaceOffset()
    {
        var primary = MonitorFromPoint(new POINT(), MONITOR_DEFAULTTOPRIMARY);
        var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>() };
        if (primary == IntPtr.Zero || !GetMonitorInfo(primary, ref mi)) return (0, 0);
        return (mi.rcWork.left - mi.rcMonitor.left, mi.rcWork.top - mi.rcMonitor.top);
    }

    private const int SW_SHOWNORMAL = 1;
    private const int SW_SHOWMINIMIZED = 2;
    private const int SW_SHOWMAXIMIZED = 3;
    private const int WPF_RESTORETOMAXIMIZED = 2;
    private const int MONITOR_DEFAULTTOPRIMARY = 1;
    private const int MONITOR_DEFAULTTONEAREST = 2;
    private const int MONITORINFOF_PRIMARY = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int left, top, right, bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINDOWPLACEMENT
    {
        public int length;
        public int flags;
        public int showCmd;
        public POINT ptMinPosition;
        public POINT ptMaxPosition;
        public RECT rcNormalPosition;

        public static WINDOWPLACEMENT Create() => new() { length = Marshal.SizeOf<WINDOWPLACEMENT>() };
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MONITORINFOEX
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public int dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }

    private delegate bool MonitorEnumProc(IntPtr monitor, IntPtr hdc, IntPtr rect, IntPtr data);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromRect(ref RECT lprc, int dwFlags);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(POINT pt, int dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFOEX lpmi);

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    [DllImport("shcore.dll")]
    private static extern int GetDpiForMonitor(IntPtr hmonitor, int dpiType, out uint dpiX, out uint dpiY);
}

// Saves and restores a GridView's column widths and order. Columns are keyed by their header text
// as declared, so a reordered column keeps its key.
public static class GridViewLayout
{
    private static readonly DependencyPropertyDescriptor WidthDescriptor =
        DependencyPropertyDescriptor.FromProperty(GridViewColumn.WidthProperty, typeof(GridViewColumn));

    public static void Track(GridView view, string key, LayoutPersistence persistence)
    {
        var keys = new Dictionary<GridViewColumn, string>();
        for (var i = 0; i < view.Columns.Count; i++)
        {
            var header = view.Columns[i].Header?.ToString()?.Trim();
            var k = string.IsNullOrEmpty(header) ? $"#{i}" : header;
            keys[view.Columns[i]] = keys.ContainsValue(k) ? $"{k}#{i}" : k;
        }

        var applying = false;

        void Capture()
        {
            if (applying) return;
            var state = new GridLayoutState();
            for (var i = 0; i < view.Columns.Count; i++)
            {
                var c = view.Columns[i];
                if (!keys.TryGetValue(c, out var k)) continue;
                state.Columns.Add(new ColumnLayoutState
                {
                    Key = k,
                    Width = double.IsNaN(c.Width) ? 0 : c.Width,
                    DisplayIndex = i
                });
            }
            persistence.Layout.Grids[key] = state;
            persistence.Changed();
        }

        if (persistence.Layout.Grids.TryGetValue(key, out var saved))
        {
            applying = true;
            try
            {
                var byKey = saved.Columns.GroupBy(c => c.Key).ToDictionary(g => g.Key, g => g.First());
                foreach (var (column, k) in keys)
                    if (byKey.TryGetValue(k, out var s))
                        column.Width = s.Width is > 0 and < 100_000 ? s.Width : double.NaN;

                var ordered = view.Columns
                    .Select((c, i) => (Column: c, Index: i))
                    .OrderBy(x => byKey.TryGetValue(keys[x.Column], out var s) ? s.DisplayIndex : int.MaxValue)
                    .ThenBy(x => x.Index)
                    .Select(x => x.Column)
                    .ToList();
                for (var d = 0; d < ordered.Count; d++)
                {
                    var current = view.Columns.IndexOf(ordered[d]);
                    if (current != d) view.Columns.Move(current, d);
                }
            }
            finally
            {
                applying = false;
            }
        }

        foreach (var column in keys.Keys)
            WidthDescriptor.AddValueChanged(column, (_, _) => Capture());
        view.Columns.CollectionChanged += (_, _) => Capture();
    }
}

// Saves and restores a scroll position (1.0.3): a ScrollViewer itself, or the one inside a DataGrid /
// ListView / ListBox / TreeView. Only a scroll the user made is saved; the saved offset is put back once
// the content is long enough to reach it (lists fill a moment after start), and given up after 8 s.
public static class ScrollLayout
{
    public static void Track(FrameworkElement element, string key, LayoutPersistence persistence)
    {
        ScrollViewer? sv = null;
        double[]? pending = null;
        var since = DateTime.UtcNow;
        var applying = false;

        void TryApply()
        {
            if (sv is null || pending is null) return;
            if (DateTime.UtcNow - since > TimeSpan.FromSeconds(8)) { pending = null; return; }
            if (sv.ScrollableHeight + 0.5 < pending[0] || sv.ScrollableWidth + 0.5 < pending[1]) return;
            var want = pending;
            pending = null;
            applying = true;
            sv.ScrollToVerticalOffset(want[0]);
            sv.ScrollToHorizontalOffset(want[1]);
            sv.Dispatcher.InvokeAsync(() => applying = false, DispatcherPriority.Background);
        }

        element.Loaded += (_, _) =>
        {
            if (sv is not null) return;
            sv = element as ScrollViewer ?? FindScrollViewer(element);
            if (sv is null) return;
            if (persistence.Layout.Scroll.TryGetValue(key, out var saved) && saved is { Length: 2 } && (saved[0] > 0 || saved[1] > 0))
                pending = saved;
            since = DateTime.UtcNow;
            TryApply();
            sv.ScrollChanged += (_, e) =>
            {
                if (!ReferenceEquals(e.OriginalSource, sv)) return;
                if (pending is not null)
                {
                    // the user scrolled before the saved place could be reached: theirs wins
                    if ((e.VerticalChange != 0 || e.HorizontalChange != 0) && e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0)
                        pending = null;
                    else { TryApply(); return; }
                }
                if (applying || (e.VerticalChange == 0 && e.HorizontalChange == 0)) return;
                if (e.ExtentHeightChange != 0 || e.ViewportHeightChange != 0 || e.ExtentWidthChange != 0 || e.ViewportWidthChange != 0) return;
                persistence.Layout.Scroll[key] = new[] { sv.VerticalOffset, sv.HorizontalOffset };
                persistence.Changed();
            };
        };
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject root)
    {
        if (root is ScrollViewer s) return s;
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
            if (FindScrollViewer(System.Windows.Media.VisualTreeHelper.GetChild(root, i)) is { } found) return found;
        return null;
    }
}
