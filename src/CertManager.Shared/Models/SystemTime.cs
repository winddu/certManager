using System.Runtime.InteropServices;

namespace CertManager.Shared.Models;

public static class SystemTime
{
    [DllImport("kernel32.dll")]
    private static extern void GetSystemTime(out SYSTEMTIME lpSystemTime);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEMTIME
    {
        public ushort wYear;
        public ushort wMonth;
        public ushort wDayOfWeek;
        public ushort wDay;
        public ushort wHour;
        public ushort wMinute;
        public ushort wSecond;
        public ushort wMilliseconds;
    }

    public static DateTime UtcNow
    {
        get
        {
            GetSystemTime(out var st);
            return new DateTime(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, DateTimeKind.Utc);
        }
    }

    public static DateTime Now => UtcNow.ToLocalTime();
}
