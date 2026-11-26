namespace Sl33p;

/// <summary>
/// Small and target-free. There is no --pid, --target or --inject flag.
/// </summary>
internal sealed record Options
{
    public string Mode { get; init; } = "encrypt";
    public string Protect { get; init; } = "rw";
    public int SleepSeconds { get; init; } = 30;
    public int AwakeSeconds { get; init; } = 0;
    public int Cycles { get; init; } = 1;
    public int Size { get; init; } = 65536;
    public string? EventName { get; init; }
    public string? SignalName { get; init; }
    public bool LabAck { get; init; }
    public bool SelfTest { get; init; }
    public bool ShowHelp { get; init; }

    public static Options Parse(string[] args)
    {
        var options = new Options();
        var seenProtect = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            string Next(string name)
            {
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException($"{name} requires a value");
                }

                return args[++i];
            }

            switch (arg)
            {
                case "-h":
                case "--help":
                    options = options with { ShowHelp = true };
                    break;
                case "--lab-ack":
                    options = options with { LabAck = true };
                    break;
                case "--selftest":
                    options = options with { SelfTest = true };
                    break;
                case "--mode":
                    options = options with { Mode = Next(arg).ToLowerInvariant() };
                    break;
                case "--protect":
                    var protect = Next(arg).ToLowerInvariant();
                    if (protect is not ("rw" or "noaccess" or "rx"))
                    {
                        throw new ArgumentException("--protect must be rw, noaccess or rx");
                    }

                    options = options with { Protect = protect };
                    seenProtect = true;
                    break;
                case "--sleep":
                    options = options with { SleepSeconds = ParseInt(arg, Next(arg), 1, 86400) };
                    break;
                case "--awake":
                    options = options with { AwakeSeconds = ParseInt(arg, Next(arg), 0, 600) };
                    break;
                case "--cycles":
                    options = options with { Cycles = ParseInt(arg, Next(arg), 1, 1000) };
                    break;
                case "--size":
                    options = options with { Size = ParseInt(arg, Next(arg), 4096, 1024 * 1024) };
                    break;
                case "--event":
                    options = options with { EventName = Next(arg) };
                    break;
                case "--signal":
                    options = options with { SignalName = Next(arg) };
                    break;
                default:
                    throw new ArgumentException($"unknown argument '{arg}'");
            }
        }

        if (options.Mode is not ("plain" or "encrypt"))
        {
            throw new ArgumentException("--mode must be plain or encrypt");
        }

        if (options.Mode == "plain" && seenProtect && options.Protect != "rw")
        {
            throw new ArgumentException("plain mode is the no-obfuscation baseline; it cannot change protection");
        }

        return options;
    }

    private static int ParseInt(string name, string raw, int min, int max)
    {
        if (!int.TryParse(raw, out var value) || value < min || value > max)
        {
            throw new ArgumentException($"{name} must be an integer in {min}..{max}");
        }

        return value;
    }
}
