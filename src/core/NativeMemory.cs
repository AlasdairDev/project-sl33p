using System.Runtime.InteropServices;

namespace Sl33p;

/// <summary>
/// The only three Win32 memory calls the project needs. Everything else is .NET.
/// Only three calls. No injection, no remote handles, no thread APIs.
/// </summary>
internal static class Win32Memory
{
    public const uint MemCommit = 0x1000;
    public const uint MemReserve = 0x2000;
    public const uint MemRelease = 0x8000;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFree(IntPtr lpAddress, nuint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualProtect(IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);
}
