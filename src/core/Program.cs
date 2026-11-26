using System.Security.Cryptography;

namespace Sl33p;

internal static class Program
{
    private static int Main(string[] args)
    {
        Options options;
        try
        {
            options = Options.Parse(args);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            Console.Error.WriteLine();
            Console.Error.Write(HelpText);
            return 2;
        }

        if (options.ShowHelp)
        {
            Console.Out.Write(HelpText);
            return 0;
        }

        if (options.SelfTest)
        {
            return SelfTest.Run(options.Size, options.Cycles);
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("error: sl33p-core is Windows-only (VirtualAlloc/VirtualProtect).");
            Console.Error.WriteLine("       Build here, run it inside the Windows 11 lab VM. See lab/vm-setup.md.");
            return 3;
        }

        if (!options.LabAck)
        {
            Console.Error.WriteLine("error: this is a lab-only tool and requires --lab-ack.");
            Console.Error.WriteLine("       Read docs/scope.md, then re-run with --lab-ack.");
            return 2;
        }

        try
        {
            if (options.SignalName is not null)
            {
                Sleeper.Signal(options.SignalName);
                return 0;
            }

            return Run(options);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int Run(Options options)
    {
        var targetProtection = ProtectionMap.Parse(options.Protect);

        using var region = MemoryRegion.Allocate(options.Size);
        region.FillPlaintext();

        var expectedHash = region.Sha256Hex();

        CryptoHeader? header = null;
        AesGcm? aes = null;

        try
        {
            if (options.Mode == "encrypt")
            {
                header = CryptoHeader.Allocate();
                var key = RandomNumberGenerator.GetBytes(CryptoHeader.KeySize);
                header.SetKey(key);
                aes = new AesGcm(key, CryptoHeader.TagSize);
                CryptographicOperations.ZeroMemory(key);
            }

            StatusWriter.Write("ready", options, region, header, expectedHash, cycle: 0);

            // Detection needs a baseline taken while the payload is still awake.
            // This window exists for the hunter (and for the demo), not for the
            // technique: real implants do not wait politely.
            if (options.AwakeSeconds > 0)
            {
                Thread.Sleep(TimeSpan.FromSeconds(options.AwakeSeconds));
            }

            for (var cycle = 1; cycle <= options.Cycles; cycle++)
            {
                if (aes is not null && header is not null)
                {
                    header.SetNonce(RandomNumberGenerator.GetBytes(CryptoHeader.NonceSize));
                    region.EncryptInPlace(aes, header);
                }

                region.SetProtection(targetProtection);
                StatusWriter.Write("asleep", options, region, header, expectedHash, cycle);

                Sleeper.Wait(TimeSpan.FromSeconds(options.SleepSeconds), options.EventName);

                region.SetProtection(MemoryProtection.ReadWrite);

                if (aes is not null && header is not null)
                {
                    region.DecryptInPlace(aes, header);
                }

                var actualHash = region.Sha256Hex();
                if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                {
                    Console.Error.WriteLine($"error: region verification failed on cycle {cycle}");
                    Console.Error.WriteLine($"       expected {expectedHash}");
                    Console.Error.WriteLine($"       actual   {actualHash}");
                    return 4;
                }

                StatusWriter.Write("awake", options, region, header, actualHash, cycle);
            }

            StatusWriter.Write("exit", options, region, header, expectedHash, options.Cycles);
            return 0;
        }
        finally
        {
            aes?.Dispose();
            header?.Dispose();
        }
    }

    private const string HelpText = """
        sl33p-core - lab-only self-process sleep obfuscation simulation

        Usage:
          sl33p-core --lab-ack [options]
          sl33p-core --lab-ack --signal <event-name>

        Options:
          --mode <plain|encrypt>   plain: marker left in clear (baseline)
                                   encrypt: AES-256-GCM in place (default)
          --protect <rw|noaccess|rx>
                                   page protection while asleep (default rw)
          --sleep <seconds>        sleep duration per cycle (default 30)
          --awake <seconds>        stay plaintext this long before sleeping (default 0)
          --cycles <n>             number of sleep/wake cycles (default 1)
          --size <bytes>           region size, 4096..1048576 (default 65536)
          --event <name>           wait on a named event instead of sleeping
          --signal <name>          set an existing named event and exit
          --lab-ack                required: confirms you read docs/scope.md
          --selftest               run the fill/seal/open path in managed memory (no Win32,
                                   works on Linux) and print a JSON result
          -h, --help               this text

        Output: one JSON status object per line on stdout (ready/asleep/awake/exit).
        Exit codes: 0 ok, 1 runtime error, 2 usage, 3 wrong platform, 4 verify failed.

        Lab only. No injection, no remote process, no persistence, no network.
        """;
}
