namespace FUTO.MDNS;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;

public class MDNSListener : IDisposable
{
    public static readonly int MulticastPort = 5353;
    private static readonly IPAddress MulticastAddressIp4 = IPAddress.Parse("224.0.0.251");
    private static readonly IPAddress MulticastAddressIp6 = IPAddress.Parse("FF02::FB");

    private readonly object _lockObject = new object();
    private UdpClient? _receiver4;
    private UdpClient? _receiver6;
    private readonly List<UdpClient> _senders = new List<UdpClient>();
    private readonly NICMonitor _nicMonitor = new NICMonitor();
    private CancellationTokenSource? _cts;
    public readonly ServiceRecordAggregator ServiceRecordAggregator = new ServiceRecordAggregator();

    public MDNSListener()
    {
        _nicMonitor.Added += OnNicsAdded;
        _nicMonitor.Removed += OnNicsRemoved;
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        Console.WriteLine("Starting");

        lock (_lockObject)
        {
            if (_cts != null)
                throw new Exception("Already started.");

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var receiver4 = new UdpClient(AddressFamily.InterNetwork);
            receiver4.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            receiver4.Client.Bind(new IPEndPoint(IPAddress.Any, MulticastPort));
            _receiver4 = receiver4;

            var receiver6 = new UdpClient(AddressFamily.InterNetworkV6);
            receiver6.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            receiver6.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, MulticastPort));
            _receiver6 = receiver6;

            var ct = _cts.Token;
            _nicMonitor.Start();
            ServiceRecordAggregator.Start();
            OnNicsAdded(_nicMonitor.Current);
        }

        await Task.WhenAll(
            ReceiveLoopAsync(_receiver4, _cts.Token), 
            ReceiveLoopAsync(_receiver6, _cts.Token)
        );
    }

    private void OnNicsAdded(List<NetworkInterface> nics)
    {
        lock (_lockObject)
        {
            if (_cts?.IsCancellationRequested == true)
                return;

            var addresses = nics.SelectMany(v => v.GetIPProperties()
                .UnicastAddresses
                .Select(x => x.Address)
                .Where(x => x.AddressFamily != AddressFamily.InterNetworkV6 || x.IsIPv6LinkLocal));

            foreach (var address in addresses)
            {
                Console.WriteLine($"New address discovered {address}");

                var localEndpoint = new IPEndPoint(address, MulticastPort);
                var sender = new UdpClient(address.AddressFamily);

                try
                {
                    switch (address.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            _receiver4?.Client?.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIp4, address));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIp4));
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
                            break;
                        case AddressFamily.InterNetworkV6:
                            _receiver6?.Client?.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIp6, address.ScopeId));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIp6));
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, true);
                            break;
                        default:
                            throw new NotSupportedException($"Address family {address.AddressFamily}.");
                    }
                }
                catch
                {
                    //Ignored
                }
                finally
                {
                    sender.Dispose();
                }
            }
        }
    }

    private void OnNicsRemoved(List<NetworkInterface> nics)
    {
        lock (_lockObject)
        {
            if (_cts?.IsCancellationRequested == true)
                return;

            //TODO: Cleanup?
        }
    }

    private async Task ReceiveLoopAsync(UdpClient client, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                Console.WriteLine("Waiting for data...");
                var result = await client.ReceiveAsync(cancellationToken);
                HandleResult(result);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An exception occurred while handling UDP result: '{e.Message}': {e.StackTrace}");
            }
        }
    }

    private void HandleResult(UdpReceiveResult result)
    {
        //Console.WriteLine($"Received packet ({result.Buffer.Length} bytes) from {result.RemoteEndPoint}:\n{result.Buffer.ToByteDump()}");
        File.AppendAllLines("log.txt", [ $"Received packet ({result.Buffer.Length} bytes) from {result.RemoteEndPoint}:\n{result.Buffer.ToByteDump()}" ]);

        try
        {
            var packet = DnsPacket.Parse(result.Buffer);
            ServiceRecordAggregator.Add(packet);            
        }
        catch
        {

        }
    }

    public void Stop()
    {
        lock (_lockObject)
        {
            _cts?.Cancel();
            _cts = null;

            _nicMonitor.Stop();
            ServiceRecordAggregator.Stop();

            _receiver4?.Dispose();
            _receiver4 = null;

            _receiver6?.Dispose();
            _receiver6 = null;

            foreach (var sender in _senders)
                sender.Dispose();
                
            _senders.Clear();
        }
    }
    
    public void Dispose()
    {
        Stop();
    }
}