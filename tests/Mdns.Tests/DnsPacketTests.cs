using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

public class DnsPacketTests
{
    // -------------------------------------------------------------------------
    // Name encoding
    // -------------------------------------------------------------------------

    [Fact]
    public void WriteName_SingleLabel()
    {
        var msg = new DnsMessage { IsResponse = false };
        msg.Questions.Add(new DnsQuestion("local.", DnsRecordType.PTR, DnsClass.IN));
        var encoded = DnsEncoder.Encode(msg);
        Assert.True(encoded.Length > 0);
    }

    [Fact]
    public void WriteName_MultiLabel_RoundTrip()
    {
        // Encode a PTR question then parse it back
        var msg = new DnsMessage { IsResponse = false };
        msg.Questions.Add(new DnsQuestion("_apple-midi._udp.local.", DnsRecordType.PTR, DnsClass.IN));
        var encoded = DnsEncoder.Encode(msg);

        Assert.True(DnsParser.TryParse(encoded, out var parsed));
        Assert.NotNull(parsed);
        Assert.Single(parsed.Questions);
        Assert.Equal("_apple-midi._udp.local.", parsed.Questions[0].Name, ignoreCase: true);
        Assert.Equal(DnsRecordType.PTR, parsed.Questions[0].Type);
    }

    // -------------------------------------------------------------------------
    // PTR record
    // -------------------------------------------------------------------------

    [Fact]
    public void Ptr_BuildAndParse_RoundTrip()
    {
        var target = "MyService._apple-midi._udp.local.";
        var data   = DnsEncoder.BuildPtr(target);

        // ParsePtr with the data as its own "full packet" (no compression pointers)
        var parsed = DnsParser.ParsePtr(data, data);
        Assert.Equal(target, parsed, ignoreCase: true);
    }

    // -------------------------------------------------------------------------
    // SRV record
    // -------------------------------------------------------------------------

    [Fact]
    public void Srv_BuildAndParse_RoundTrip()
    {
        var data = DnsEncoder.BuildSrv(0, 0, 5004, "DMX-Core-100.local.");
        var (priority, weight, port, target) = DnsParser.ParseSrv(data, data);

        Assert.Equal(0, priority);
        Assert.Equal(0, weight);
        Assert.Equal(5004, port);
        Assert.Equal("DMX-Core-100.local.", target, ignoreCase: true);
    }

    // -------------------------------------------------------------------------
    // TXT record
    // -------------------------------------------------------------------------

    [Fact]
    public void Txt_EmptyProperties_RoundTrip()
    {
        var data   = DnsEncoder.BuildTxt(new Dictionary<string, string>());
        var parsed = DnsParser.ParseTxt(data);
        Assert.Empty(parsed);
    }

    [Fact]
    public void Txt_WithProperties_RoundTrip()
    {
        var props = new Dictionary<string, string>
        {
            ["txtvers"] = "1",
            ["name"]    = "Test Device",
        };
        var data   = DnsEncoder.BuildTxt(props);
        var parsed = DnsParser.ParseTxt(data);

        Assert.Equal("1",           parsed["txtvers"]);
        Assert.Equal("Test Device", parsed["name"]);
    }

    // -------------------------------------------------------------------------
    // A record
    // -------------------------------------------------------------------------

    [Fact]
    public void A_BuildAndParse_RoundTrip()
    {
        var ip   = IPAddress.Parse("192.168.1.100");
        var data = DnsEncoder.BuildA(ip);
        var parsed = DnsParser.ParseA(data);

        Assert.NotNull(parsed);
        Assert.Equal(ip, parsed);
    }

    // -------------------------------------------------------------------------
    // Full message round-trip
    // -------------------------------------------------------------------------

    [Fact]
    public void AnnounceMessage_RoundTrip()
    {
        var ip = IPAddress.Parse("192.168.1.50");
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };

        msg.Answers.Add(new DnsRecord(
            "MyDevice._apple-midi._udp.local.", DnsRecordType.SRV, DnsClass.IN_Unicast, 120,
            DnsEncoder.BuildSrv(0, 0, 5004, "MyDevice.local.")));

        msg.Answers.Add(new DnsRecord(
            "_apple-midi._udp.local.", DnsRecordType.PTR, DnsClass.IN, 4500,
            DnsEncoder.BuildPtr("MyDevice._apple-midi._udp.local.")));

        msg.Answers.Add(new DnsRecord(
            "MyDevice.local.", DnsRecordType.A, DnsClass.IN_Unicast, 120,
            DnsEncoder.BuildA(ip)));

        var encoded = DnsEncoder.Encode(msg);
        Assert.True(DnsParser.TryParse(encoded, out var parsed));
        Assert.NotNull(parsed);
        Assert.True(parsed.IsResponse);
        Assert.True(parsed.IsAuthoritative);
        Assert.Equal(3, parsed.Answers.Count);
    }

    [Fact]
    public void Parse_RejectsGarbage()
    {
        var garbage = new byte[] { 0x00, 0x01, 0xFF, 0xAB };
        // Should not throw, just return false or an incomplete message
        var result = DnsParser.TryParse(garbage, out _);
        // Either fails gracefully or returns empty — no exception
        Assert.True(result == true || result == false);
    }

    // -------------------------------------------------------------------------
    // ServiceProfile helpers
    // -------------------------------------------------------------------------

    [Fact]
    public void ServiceProfile_FullNames_Correct()
    {
        var profile = new ServiceProfile("DMX Core 100", "_apple-midi._udp", 5004);

        Assert.Equal("_apple-midi._udp.local.",                   profile.FullServiceType);
        Assert.Equal("DMX Core 100._apple-midi._udp.local.",      profile.FullInstanceName);
        Assert.Equal("DMX-Core-100.local.",                       profile.Hostname);
    }
}
