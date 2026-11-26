using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Sl33p;

/// <summary>
/// Nonce | tag | key, in a separate 4 KiB private allocation.
///
/// This is intentionally the weak point of the technique and the basis of
/// detector D6: the key has to stay somewhere while the payload is encrypted.
/// A detector that finds this block can decrypt the dormant region and prove
/// what it was. That finding is a feature of the lab, not a bug to hide.
/// </summary>
internal sealed unsafe class CryptoHeader : IDisposable
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int PayloadSize = NonceSize + TagSize + KeySize; // 60 bytes
    public const int AllocationSize = 4096;                     // one page

    private const int NonceOffset = 0;
    private const int TagOffset = NonceSize;
    private const int KeyOffset = NonceSize + TagSize;

    private bool _disposed;

    private CryptoHeader(IntPtr address) => Address = address;

    public IntPtr Address { get; }
    public int Size => AllocationSize;

    private Span<byte> Span => new((void*)Address, AllocationSize);

    public static CryptoHeader Allocate()
    {
        var address = Win32Memory.VirtualAlloc(
            IntPtr.Zero,
            AllocationSize,
            Win32Memory.MemCommit | Win32Memory.MemReserve,
            (uint)MemoryProtection.ReadWrite);

        if (address == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc (header) failed");
        }

        return new CryptoHeader(address);
    }

    public ReadOnlySpan<byte> Nonce => Span.Slice(NonceOffset, NonceSize);
    public ReadOnlySpan<byte> Tag => Span.Slice(TagOffset, TagSize);

    public void SetNonce(ReadOnlySpan<byte> nonce)
    {
        if (nonce.Length != NonceSize) throw new ArgumentException("nonce must be 12 bytes");
        nonce.CopyTo(Span[NonceOffset..]);
    }

    public void SetTag(ReadOnlySpan<byte> tag)
    {
        if (tag.Length != TagSize) throw new ArgumentException("tag must be 16 bytes");
        tag.CopyTo(Span[TagOffset..]);
    }

    public void SetKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize) throw new ArgumentException("key must be 32 bytes");
        key.CopyTo(Span[KeyOffset..]);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span);
        Win32Memory.VirtualFree(Address, 0, Win32Memory.MemRelease);
    }
}
