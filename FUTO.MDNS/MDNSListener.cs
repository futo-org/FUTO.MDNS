namespace FUTO.MDNS;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

public class MDNSListener : IDisposable
{
    public static readonly int MulticastPort = 5353;
    private static readonly IPAddress MulticastAddressIPv4 = IPAddress.Parse("224.0.0.251");
    private static readonly IPAddress MulticastAddressIPv6 = IPAddress.Parse("FF02::FB");
    private static readonly IPEndPoint MdnsEndpointIPv6 = new IPEndPoint(MulticastAddressIPv6, MulticastPort);
    private static readonly IPEndPoint MdnsEndpointIPv4 = new IPEndPoint(MulticastAddressIPv4, MulticastPort);

    private readonly object _lockObject = new object();
    private UdpClient? _receiver4;
    private UdpClient? _receiver6;
    private readonly List<UdpClient> _senders = new List<UdpClient>();
    private readonly NICMonitor _nicMonitor = new NICMonitor();
    private CancellationTokenSource? _cts;
    private readonly ServiceRecordAggregator _serviceRecordAggregator = new ServiceRecordAggregator();

    public event Action<DnsPacket>? OnPacket;
    public event Action<List<DnsService>>? OnServicesUpdated;

    public MDNSListener()
    {
        _nicMonitor.Added += OnNicsAdded;
        _nicMonitor.Removed += OnNicsRemoved;
        _serviceRecordAggregator.ServicesUpdated += (services) => OnServicesUpdated?.Invoke(services);
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
            _serviceRecordAggregator.Start();
            OnNicsAdded(_nicMonitor.Current);
        }

        await Task.WhenAll(
            ReceiveLoopAsync(_receiver4, _cts.Token), 
            ReceiveLoopAsync(_receiver6, _cts.Token)
        );
    }

    public async Task QueryServicesAsync(string[] names, CancellationToken cancellationToken = default)
    {
        if (names.Length < 1)
            throw new ArgumentException("At least one name must be specified.");

        var writer = new DnsWriter();
        writer.WritePacket
        (
            header: new DnsPacketHeader()
            {
                Identifier = 0,
                QueryResponse = QueryResponse.Query,
                Opcode = DnsOpcode.StandardQuery,
                Truncated = false,
                NonAuthenticatedData = false,
                RecursionDesired = false,
                AnswerAuthenticated = false,
                AuthorativeAnswer = false,
                RecursionAvailable = false,
                ResponseCode = 0,
            }, 
            questionCount: names.Length,
            questionWriter: (w, i) => 
            {
                w.Write(new DnsQuestion()
                {
                    Name = names[i],
                    Type = QuestionType.PTR,
                    Class = QuestionClass.IN,
                    QueryUnicast = false
                });
            }
        );

        await SendAsync(writer.ToArray(), cancellationToken);
    }

    private async Task SendAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        Task[] tasks;
        lock (_lockObject)
        {
            tasks = _senders.Select(async s => 
            {
                try
                {
                    var endPoint = s.Client.AddressFamily == AddressFamily.InterNetwork ? MdnsEndpointIPv4 : MdnsEndpointIPv6;
                    await s.SendAsync(new ReadOnlyMemory<byte>(data, 0, data.Length), endPoint, cancellationToken);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Failed to send on {s.Client.LocalEndPoint}: {e.Message}.");
                }
            }).ToArray();
        }

        await Task.WhenAll(tasks);
    }

    public async Task QueryAllQuestionsAsync(string[] names, CancellationToken cancellationToken = default)
    {
        if (names.Length < 1)
            throw new ArgumentException("At least one name must be specified.");

        var questions = names.SelectMany(n => _serviceRecordAggregator.GetAllQuestions(n)).ToList();
        foreach (var questionsPerHost in questions.GroupBy(q => q.Name))
        {
            var questionsForHost = questionsPerHost.ToList();

            var writer = new DnsWriter();
            writer.WritePacket
            (
                header: new DnsPacketHeader()
                {
                    Identifier = 0,
                    QueryResponse = QueryResponse.Query,
                    Opcode = DnsOpcode.StandardQuery,
                    Truncated = false,
                    NonAuthenticatedData = false,
                    RecursionDesired = false,
                    AnswerAuthenticated = false,
                    AuthorativeAnswer = false,
                    RecursionAvailable = false,
                    ResponseCode = 0,
                }, 
                questionCount: questionsForHost.Count,
                questionWriter: (w, i) => w.Write(questionsForHost[i])
            );

            await SendAsync(writer.ToArray(), cancellationToken);
        }
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
                            _receiver4?.Client?.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIPv4, address));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIPv4));
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
                            break;
                        case AddressFamily.InterNetworkV6:
                            _receiver6?.Client?.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIPv6, address.ScopeId));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIPv6));
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, true);
                            break;
                        default:
                            throw new NotSupportedException($"Address family {address.AddressFamily}.");
                    }

                    _senders.Add(sender);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Exception occurred when processing added address {address}: {e.Message}, {e.StackTrace}");
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
            _serviceRecordAggregator.Add(packet);
            OnPacket?.Invoke(packet);
        }
        catch (Exception e)
        {
            Console.WriteLine("Failed to handle packet: " + e.Message + "\n" + e.StackTrace);
        }
    }

    public void Stop()
    {
        lock (_lockObject)
        {
            _cts?.Cancel();
            _cts = null;

            _nicMonitor.Stop();
            _serviceRecordAggregator.Stop();

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