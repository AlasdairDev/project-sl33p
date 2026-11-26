using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sl33p;

internal enum MemoryProtection : uint
{
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
}

internal static class ProtectionMap
{
    public static MemoryProtection Parse(string name) => name switch
    {
        "rw" => MemoryProtection.ReadWrite,
        "noaccess" => MemoryProtection.NoAccess,
        "rx" => MemoryProtection.ExecuteRead,
        _ => throw new ArgumentException($"unknown protection '{name}' (want rw, noaccess or rx)"),
    };

    public static string Name(MemoryProtection protection) => protection switch
    {
        MemoryProtection.NoAccess => "NOACCESS",
        MemoryProtection.ReadOnly => "R",
        MemoryProtection.ReadWrite => "RW",
        MemoryProtection.ExecuteRead => "RX",
        MemoryProtection.ExecuteReadWrite => "RWX",
        _ => "UNKNOWN",
    };
}

/// <summary>
/// One self-owned committed region. The whole project exists inside this class:
/// allocate, fill, encrypt, change protection, decrypt, verify, wipe.
/// There is no target-process handle anywhere in this codebase.
/// </summary>
internal sealed unsafe class MemoryRegion : IDisposable
{
    private bool _disposed;

    private MemoryRegion(IntPtr address, int size)
    {
        Address = address;
        Size = size;
        Protection = MemoryProtection.ReadWrite;
    }

    public IntPtr Address { get; }
    public int Size { get; }
    public MemoryProtection Protection { get; private set; }
    public string ProtectionName => ProtectionMap.Name(Protection);

    private Span<byte> Span => new((void*)Address, Size);

    public static MemoryRegion Allocate(int size)
    {
        if (size < 4096 || size > 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(size), "region size must be 4 KiB..1 MiB");
        }

        var address = Win32Memory.VirtualAlloc(
            IntPtr.Zero,
            (nuint)size,
            Win32Memory.MemCommit | Win32Memory.MemReserve,
            (uint)MemoryProtection.ReadWrite);

        if (address == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc failed");
        }

        return new MemoryRegion(address, size);
    }

    /// <summary>
    /// Low-entropy ASCII so the encrypted state is obviously different:
    /// the marker appears exactly once, the rest is numbered filler.
    /// Shared with `--selftest`, which runs the same code without Win32.
    /// </summary>
    public void FillPlaintext() => RegionCipher.Fill(Span);

    public string Sha256Hex() => Convert.ToHexStringLower(SHA256.HashData(Span));

    public void SetProtection(MemoryProtection protection)
    {
        if (Protection == protection)
        {
            return;
        }

        if (!Win32Memory.VirtualProtect(Address, (nuint)Size, (uint)protection, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtect failed");
        }

        Protection = protection;
    }

    public void EncryptInPlace(AesGcm aes, CryptoHeader header)
    {
        Span<byte> tag = stackalloc byte[CryptoHeader.TagSize];
        RegionCipher.SealInPlace(Span, aes, header.Nonce, tag);
        header.SetTag(tag);
    }

    public void DecryptInPlace(AesGcm aes, CryptoHeader header)
        => RegionCipher.OpenInPlace(Span, aes, header.Nonce, header.Tag);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(Span);

        // dwSize must be 0 when freeing a whole reservation.
        Win32Memory.VirtualFree(Address, 0, Win32Memory.MemRelease);
    }
}
