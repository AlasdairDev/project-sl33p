using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sl33p;

/// <summary>
/// Runs the real fill/seal/open path on a plain managed buffer, with no Win32
/// calls, so the crypto half of Phase 2 can be verified on Linux.
///
/// It does not prove page-protection behaviour, the hunter, or anything about
/// a live process. It proves that a sealed region opens to a byte-identical
/// original and that the marker disappears while sealed.
/// </summary>
internal static class SelfTest
{
    public static int Run(int size, int cycles)
    {
        if (size < 4096 || size > 1024 * 1024)
        {
            Console.Error.WriteLine("error: --size must be 4096..1048576");
            return 2;
        }

        var key = RandomNumberGenerator.GetBytes(CryptoHeader.KeySize);
        var buffer = new byte[size];
        var results = new List<object>();
        var passed = 0;
        var markerHidden = 0;

        RegionCipher.Fill(buffer);
        var expected = Convert.ToHexStringLower(SHA256.HashData(buffer));
        var plaintextEntropy = RegionCipher.Entropy(buffer);

        using var aes = new AesGcm(key, CryptoHeader.TagSize);
        Span<byte> tag = stackalloc byte[CryptoHeader.TagSize];

        for (var cycle = 1; cycle <= cycles; cycle++)
        {
            var nonce = RandomNumberGenerator.GetBytes(CryptoHeader.NonceSize);
            RegionCipher.SealInPlace(buffer, aes, nonce, tag);

            var hidden = !RegionCipher.ContainsMarker(buffer);
            var sealedEntropy = RegionCipher.Entropy(buffer);
            if (hidden)
            {
                markerHidden++;
            }

            RegionCipher.OpenInPlace(buffer, aes, nonce, tag);

            var actual = Convert.ToHexStringLower(SHA256.HashData(buffer));
            var match = string.Equals(actual, expected, StringComparison.Ordinal);
            if (match)
            {
                passed++;
            }

            results.Add(new
            {
                cycle,
                marker_hidden = hidden,
                sha256_match = match,
                entropy_sealed = Math.Round(sealedEntropy, 4),
            });

            if (!match)
            {
                break;
            }
        }

        CryptographicOperations.ZeroMemory(key);

        var payload = new
        {
            tool = "sl33p-selftest",
            framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            region_size = size,
            cycles_requested = cycles,
            cycles_passed = passed,
            marker_hidden_cycles = markerHidden,
            entropy_plaintext = Math.Round(plaintextEntropy, 4),
            sha256_plaintext = expected,
            ok = passed == cycles && markerHidden == cycles,
            results,
        };

        Console.Out.WriteLine(JsonSerializer.Serialize(payload));
        return payload.ok ? 0 : 1;
    }
}
