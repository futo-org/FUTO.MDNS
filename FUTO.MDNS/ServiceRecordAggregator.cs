using System.Net;
using System.Text.Json;
using static FUTO.MDNS.DnsReader;

namespace FUTO.MDNS;

public class DnsService
{
    public required string Name;
    public required string Target;
    public ushort Port;
    public readonly List<IPAddress> Addresses = new();
    public readonly List<string> Pointers = new();
    public readonly List<string> Texts = new();
}

public class CachedDnsAddressRecord
{
    public DateTime ExpirationTime { get; init; }
    public required IPAddress Address { get; init; }
}

public class CachedDnsTxtRecord
{
    public DateTime ExpirationTime { get; init; }
    public required List<string> Texts { get; init; }
}

public class CachedDnsPtrRecord
{
    public DateTime ExpirationTime { get; init; }
    public required string Target { get; init; }
}

public class CachedDnsSrvRecord
{
    public DateTime ExpirationTime { get; init; }
    public required SRVRecord Service { get; init; }
}

public class ServiceRecordAggregator
{
    private readonly object _lockObject = new object();
    private readonly Dictionary<string, List<CachedDnsAddressRecord>> _cachedAddressRecords = new();
    private readonly Dictionary<string, CachedDnsTxtRecord> _cachedTxtRecords = new();
    private readonly Dictionary<string, List<CachedDnsPtrRecord>> _cachedPtrRecords = new();
    private readonly Dictionary<string, CachedDnsSrvRecord> _cachedSrvRecords = new();
    private CancellationTokenSource? _cts;

    public event Action<List<DnsService>>? ServicesUpdated;

    public void Start()
    {
        lock (_lockObject)
        {
            if (_cts != null)
                throw new Exception("Already started.");

            _cts = new CancellationTokenSource();
        }

        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                var now = DateTime.Now;

                lock (_cachedAddressRecords)
                {
                    foreach (var pair in _cachedAddressRecords)
                        pair.Value.RemoveAll(v => now > v.ExpirationTime);
                }

                lock (_cachedTxtRecords)
                {
                    var expiredRecords = new List<string>();
                    foreach (var pair in _cachedTxtRecords)
                    {
                        if (now > pair.Value.ExpirationTime)
                            expiredRecords.Add(pair.Key);
                    }

                    foreach (var expiredRecord in expiredRecords)
                        _cachedTxtRecords.Remove(expiredRecord);
                }

                lock (_cachedSrvRecords)
                {
                    var expiredRecords = new List<string>();
                    foreach (var pair in _cachedSrvRecords)
                    {
                        if (now > pair.Value.ExpirationTime)
                            expiredRecords.Add(pair.Key);
                    }

                    foreach (var expiredRecord in expiredRecords)
                        _cachedSrvRecords.Remove(expiredRecord);
                }

                lock (_cachedPtrRecords)
                {
                    foreach (var pair in _cachedPtrRecords)
                        pair.Value.RemoveAll(v => now > v.ExpirationTime);
                }

                await Task.Delay(TimeSpan.FromSeconds(5));
            }
        });
    }

    public void Stop()
    {
        lock (_lockObject)
        {
            _cts?.Cancel();
            _cts = null;
        }
    }

    public void Add(DnsPacket packet)
    {
        var dnsResourceRecords = packet.Answers.Concat(packet.Additionals).Concat(packet.Authorities).ToList();
        var txtRecords = dnsResourceRecords.Where(r => r.Type == ResourceRecordType.TXT).Select(r => new { Record = r, Content = r.GetDataReader().ReadTXTRecord() }).ToList();
        var aRecords = dnsResourceRecords.Where(r => r.Type == ResourceRecordType.A).Select(r => new { Record = r, Content = r.GetDataReader().ReadARecord() }).ToList();
        var aaaaRecords = dnsResourceRecords.Where(r => r.Type == ResourceRecordType.AAAA).Select(r => new { Record = r, Content = r.GetDataReader().ReadAAAARecord() }).ToList();
        var srvRecords = dnsResourceRecords.Where(r => r.Type == ResourceRecordType.SRV).Select(r => new { Record = r, Content = r.GetDataReader().ReadSRVRecord() }).ToList();
        var ptrRecords = dnsResourceRecords.Where(r => r.Type == ResourceRecordType.PTR).Select(r => new { Record = r, Content = r.GetDataReader().ReadPTRRecord() }).ToList();

        lock (_cachedPtrRecords)
        {
            foreach (var record in ptrRecords)
            {
                List<CachedDnsPtrRecord>? l;
                if (!_cachedPtrRecords.TryGetValue(record.Record.Name, out l) || l == null)
                {
                    l = new List<CachedDnsPtrRecord>();
                    _cachedPtrRecords[record.Record.Name] = l;
                }

                bool found = false;
                for (var i = 0; i < l.Count; i++)
                {
                    if (l[i].Target == record.Content.DomainName)
                    {
                        found = true;
                        l[i] = new CachedDnsPtrRecord()
                        {
                            Target = record.Content.DomainName,
                            ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                        };
                    }
                }

                if (!found)
                {
                    //If watching for services (i.e. record.Record.Name == '_airplay._tcp.local'), query for record.Content.DomainName 'Homepod A._airplay._tcp.local' to get more information about the airplay device?

                    File.AppendAllLines("ptr-records.txt", ["New ptr record found " + record.Content.DomainName + " -> " + record.Record.Name]);

                    l.Add(new CachedDnsPtrRecord()
                    {
                        Target = record.Content.DomainName,
                        ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                    });
                }
            }
        }

        lock (_cachedAddressRecords)
        {
            foreach (var record in aRecords)
            {
                List<CachedDnsAddressRecord>? l;
                if (!_cachedAddressRecords.TryGetValue(record.Record.Name, out l) || l == null)
                {
                    l = new List<CachedDnsAddressRecord>();
                    _cachedAddressRecords[record.Record.Name] = l;
                }

                var newRecord = new CachedDnsAddressRecord()
                {
                    Address = record.Content.Address,
                    ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                };

                bool found = false;
                for (var i = 0; i < l.Count; i++)
                {
                    if (l[i].Address.Equals(newRecord.Address))
                    {
                        found = true;
                        l[i] = newRecord;
                    }
                }

                if (!found)
                    l.Add(newRecord);
            }

            foreach (var record in aaaaRecords)
            {
                List<CachedDnsAddressRecord>? l;
                if (!_cachedAddressRecords.TryGetValue(record.Record.Name, out l) || l == null)
                {
                    l = new List<CachedDnsAddressRecord>();
                    _cachedAddressRecords[record.Record.Name] = l;
                }

                var newRecord = new CachedDnsAddressRecord()
                {
                    Address = record.Content.Address,
                    ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                };

                bool found = false;
                for (var i = 0; i < l.Count; i++)
                {
                    if (l[i].Address.Equals(newRecord.Address))
                    {
                        found = true;
                        l[i] = newRecord;
                    }
                }

                if (!found)
                    l.Add(newRecord);
            }
        }

        lock (_cachedTxtRecords)
        {
            foreach (var record in txtRecords)
            {
                _cachedTxtRecords[record.Record.Name] = new CachedDnsTxtRecord()
                {
                    Texts = record.Content.Texts,
                    ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                };
            }
        }

        lock (_cachedSrvRecords)
        {
            foreach (var record in srvRecords)
            {
                _cachedSrvRecords[record.Record.Name] = new CachedDnsSrvRecord()
                {
                    Service = record.Content,
                    ExpirationTime = DateTime.Now.AddSeconds(record.Record.TimeToLive)
                };
            }
        }

        UpdateServices();
    }

    private void UpdateServices()
    {
        List<DnsService> services;
        lock (_cachedSrvRecords)
        {
            services = _cachedSrvRecords.Select(v => new DnsService
            {
                Name = v.Key,
                Target = v.Value.Service.Target,
                Port = v.Value.Service.Port
            }).ToList();
        }

        lock (_cachedAddressRecords)
        {
            foreach (var service in services)
            {
                //TODO: Recursively resolve PTRs?
                if (_cachedAddressRecords.TryGetValue(service.Target, out var cachedRecords))
                    service.Addresses.AddRange(cachedRecords.Select(v => v.Address).ToList());
            }
        }

        lock (_cachedPtrRecords)
        {
            foreach (var service in services)
            {
                //TODO: Recursively resolve PTRs?
                service.Pointers.AddRange(_cachedPtrRecords.Where(w => w.Value.Any(x => x.Target == service.Name)).Select(w => w.Key).ToList());
            }
        }

        lock (_cachedTxtRecords)
        {
            foreach (var service in services)
            {
                if (_cachedTxtRecords.TryGetValue(service.Name, out var cachedRecords))
                    service.Texts.AddRange(cachedRecords.Texts);
            }
        }

        ServicesUpdated?.Invoke(services);
    }
}