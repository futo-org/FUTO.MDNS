namespace FUTO.MDNS;

using System.Buffers.Binary;

public enum QuestionType : ushort
{
    /// <summary>
    /// A qrequest for a transfer of an entire zone
    /// </summary>
    AXFR = 252,
    /// <summary>
    /// A request for mailbox-related records (MB, MG or MR)
    /// </summary>
    MAILB = 253,
    /// <summary>
    /// A request for mail agent RRs (Obsolete - see MX)
    /// </summary>
    MALA = 254,
    /// <summary>
    /// A request for all records
    /// </summary>
    All = 252
}

public enum QuestionClass : ushort
{
    /// <summary>
    /// A request for all records
    /// </summary>
    All = 255
}

public class DnsQuestion : DnsResourceRecordBase<QuestionType, QuestionClass> 
{ 
    public static DnsQuestion Parse(byte[] data, ref int position)
    {
        var span = data.AsSpan();
        var qname = data.ReadDomainName(ref position);
        var qtype = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(position, 2));
        position += 2;
        var qclass = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(position, 2));
        position += 2;

        return new DnsQuestion
        {
            Name = qname,
            Type = (QuestionType)qtype,
            CacheFlush = ((qclass >> 15) & 0b1) != 0,
            Class = (QuestionClass)(qclass & 0b111111111111111)
        };
    }
}
public class DnsResourceRecordBase<TType, TClass>
{
    /// <summary>
    /// A domain name to which this resource record pertains.
    /// </summary>
    public required string Name { get; init; }
    /// <summary>
    /// Specificies the type.
    /// </summary>
    public required TType Type { get; init; }
    /// <summary>
    /// Specifies if cache should be flushed.
    /// </summary>
    public bool CacheFlush { get; init; }
    /// <summary>
    /// Specifies the class.
    /// </summary>
    public required TClass Class { get; init; }
}