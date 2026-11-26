using System.Security.Cryptography;
using System.Text;

namespace Sl33p;

/// <summary>
/// The platform-independent part: fill a buffer with the marker, seal it in
/// place, open it in place. `--selftest` runs this path without Win32.
/// </summary>
internal static class RegionCipher
{
    // "SL33P_LAB_MARKER_9f2c1d7e" XOR 0x5A. Stored only encoded: a plaintext
    // marker literal in the managed heap would let D1 find the marker outside
    // the region, which is exactly the false positive the live Linux run caught.
    private const byte MarkerMask = 0x5A;

    private static readonly byte[] Encoded =
    {
        0x09, 0x16, 0x69, 0x69, 0x0A, 0x05, 0x16, 0x1B, 0x18, 0x05, 0x17, 0x1B, 0x08, 0x11, 0x1F, 0x08, 0x05, 0x63, 0x3C, 0x68, 0x39, 0x6B, 0x3E, 0x6D, 0x3F
    };

    internal static ReadOnlySpan<byte> EncodedMarker => Encoded;

    public static void Fill(Span<byte> buffer)
    {
        buffer.Clear();

        var encoded = EncodedMarker;
        for (var i = 0; i < encoded.Length; i++)
        {
            buffer[i] = (byte)(encoded[i] ^ MarkerMask);
        }

        var offset = encoded.Length;
        buffer[offset++] = (byte)'\n';

        var slot = 0;
        while (offset < buffer.Length)
        {
            var line = Encoding.ASCII.GetBytes($"sl33p lab benign region slot {slot:D5}\n");
            var count = Math.Min(line.Length, buffer.Length - offset);
            line.AsSpan(0, count).CopyTo(buffer[offset..]);
            offset += count;
            slot++;
        }
    }

    /// <summary>Marker search that never materialises the marker.</summary>
    internal static bool ContainsMarker(ReadOnlySpan<byte> haystack)
    {
        var encoded = EncodedMarker;
        for (var i = 0; i + encoded.Length <= haystack.Length; i++)
        {
            var match = true;
            for (var j = 0; j < encoded.Length; j++)
            {
                if (haystack[i + j] != (byte)(encoded[j] ^ MarkerMask))
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// AES-GCM will not encrypt a buffer onto itself, so a scratch copy is
    /// unavoidable. It is zeroed before returning: a lingering plaintext copy
    /// would break the whole demonstration.
    /// </summary>
    public static void SealInPlace(
        Span<byte> buffer,
        AesGcm aes,
        ReadOnlySpan<byte> nonce,
        Span<byte> tag)
    {
        var scratch = new byte[buffer.Length];
        try
        {
            buffer.CopyTo(scratch);
            aes.Encrypt(nonce, scratch, buffer, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    public static void OpenInPlace(
        Span<byte> buffer,
        AesGcm aes,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag)
    {
        var scratch = new byte[buffer.Length];
        try
        {
            buffer.CopyTo(scratch);
            aes.Decrypt(nonce, scratch, tag, buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    /// <summary>Shannon entropy in bits per byte, for the self-test digest.</summary>
    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> histogram = stackalloc int[256];
        foreach (var value in data)
        {
            histogram[value]++;
        }

        double result = 0.0;
        foreach (var count in histogram)
        {
            if (count == 0)
            {
                continue;
            }

            var p = (double)count / data.Length;
            result -= p * Math.Log2(p);
        }

        return result;
    }
}
