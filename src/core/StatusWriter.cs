using System.Text.Json;

namespace Sl33p;

/// <summary>
/// One JSON object per line on stdout. This is the only interface between the
/// core and the hunter, and the hunter is not allowed to trust it: it is used
/// for timing and for the demo, never as evidence of detection.
/// </summary>
internal static class StatusWriter
{
    public static void Write(
        string eventName,
        Options options,
        MemoryRegion region,
        CryptoHeader? header,
        string markerSha256,
        int cycle)
    {
        var state = eventName switch
        {
            "asleep" => "asleep",
            "awake" => "awake",
            _ => "awake",
        };

        var payload = new Dictionary<string, object?>
        {
            ["ts"] = DateTimeOffset.UtcNow.ToString("O"),
            ["event"] = eventName,
            ["pid"] = Environment.ProcessId,
            ["mode"] = options.Mode,
            ["state"] = state,
            ["cycle"] = cycle,
            ["sleep_seconds"] = options.SleepSeconds,
            ["awake_seconds"] = options.AwakeSeconds,
            ["protect_mode"] = options.Protect,
            ["region"] = new Dictionary<string, object?>
            {
                ["address"] = Hex(region.Address),
                ["size"] = region.Size,
                ["protection"] = region.ProtectionName,
            },
            ["header"] = header is null
                ? null
                : new Dictionary<string, object?>
                {
                    ["address"] = Hex(header.Address),
                    ["size"] = header.Size,
                },
            ["marker_sha256"] = markerSha256,
        };

        Console.Out.WriteLine(JsonSerializer.Serialize(payload));
        Console.Out.Flush();
    }

    private static string Hex(IntPtr value) => "0x" + value.ToString("X");
}
