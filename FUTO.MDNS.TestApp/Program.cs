using FUTO.MDNS;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, _) => cts.Cancel();
        using var listener = new MDNSListener();
        await listener.RunAsync(cts.Token);
    }
}