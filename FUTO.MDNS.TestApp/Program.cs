using System.Text;
using FUTO.MDNS;

internal class Program
{
    public class ServiceDiscoverer
    {
        private readonly string[] _names;

        public ServiceDiscoverer(params string[] names)
        {
            if (names.Length < 1)
                throw new ArgumentException("At least one name must be specified.");

            _names = names;
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            using var listener = new MDNSListener();
            listener.OnServicesUpdated += (services) =>
            {
                var builder = new StringBuilder();
                foreach (var service in services)
                {
                    builder.Clear();
                    builder.AppendLine($"Service {service.Name} ({string.Join(", ", service.Pointers)}) on port {service.Port}:");
                    foreach (var address in service.Addresses)
                        builder.AppendLine($"  - {address}");
                    Console.Write(builder.ToString());
                }
            };

            await listener.BroadcastServiceAsync("SomeDevice", "_googlecast._tcp.local", 8009);

            _ = listener.RunAsync(cancellationToken);
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
                await listener.QueryServicesAsync(_names, cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
                await listener.QueryAllQuestionsAsync(_names, cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }
    }

    private static async Task Main(string[] args)
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, _) => cts.Cancel();

        var serviceDiscoverer = new ServiceDiscoverer("_googlecast._tcp.local", "_airplay._tcp.local", "_fcast._tcp.local");
        await serviceDiscoverer.RunAsync(cts.Token);
    }
}