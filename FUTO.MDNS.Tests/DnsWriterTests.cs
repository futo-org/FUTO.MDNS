namespace FUTO.MDNS.Tests;

[TestClass]
public class DnsWriterTests
{
    [TestMethod]
    public void BasicOperation()
    {
        byte[] expectedData = [
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        ];

        var writer = new DnsWriter();
        writer.Write((ushort)1);
        writer.Write((uint)2);
        writer.Write((ulong)3);
        writer.Write((short)1);
        writer.Write((int)2);
        writer.Write((long)3);
        CollectionAssert.AreEqual(expectedData, writer.ToArray());
    }
}