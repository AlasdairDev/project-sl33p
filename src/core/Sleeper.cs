namespace Sl33p;

/// <summary>
/// A plain blocking wait. No timer queues, no APCs, no call-stack rewriting:
/// that technique class is explicitly out of scope (docs/scope.md).
/// </summary>
internal static class Sleeper
{
    public static void Wait(TimeSpan timeout, string? eventName)
    {
        if (string.IsNullOrEmpty(eventName))
        {
            Thread.Sleep(timeout);
            return;
        }

        using var handle = new EventWaitHandle(
            initialState: false,
            EventResetMode.ManualReset,
            name: eventName);

        handle.WaitOne(timeout);
    }

    public static void Signal(string eventName)
    {
        using var handle = EventWaitHandle.OpenExisting(eventName);
        handle.Set();
    }
}
