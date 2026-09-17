using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

/// <summary>
/// A one-shot resolver (RFC 6762 §6.7) queries from an ephemeral port and parses
/// the reply as ordinary DNS. These cover what that forces the response to look
/// like, which is not the same as our multicast announcement.
/// </summary>
public class LegacyUnicastTests
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.250.67");
    private const string ServiceType = "_osc._udp.local.";

    private static DnsMessage BuildResponse(ushort queryId = 0x1234)
    {
        var profile = new ServiceProfile("Test Core", "_osc._udp", 9000,
            new Dictionary<string, string> { ["model"] = "DMXCore100" });

        using var advertiser = new MdnsAdvertiser(profile, Local);
        var question = new DnsQuestion(ServiceType, DnsRecordType.PTR, DnsClass.IN);

        // Round-trip through the wire format: a legacy resolver sees bytes, and an
        // assertion against the object graph would not catch an encoding mistake.
        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(advertiser.BuildLegacyResponse(question, queryId)), out var parsed));
        Assert.NotNull(parsed);

        return parsed!;
    }

    [Fact]
    public void LegacyResponse_EchoesQueryIdAndQuestion()
    {
        var response = BuildResponse(queryId: 0xBEEF);

        // A legacy resolver matches the reply to its outstanding query by ID, and
        // discards a reply whose question section does not come back with it.
        Assert.Equal(0xBEEF, response.Id);
        Assert.True(response.IsResponse);
        Assert.Single(response.Questions);
        Assert.Equal(ServiceType, response.Questions[0].Name, ignoreCase: true);
        Assert.Equal(DnsRecordType.PTR, response.Questions[0].Type);
    }

    [Fact]
    public void LegacyResponse_NeverSetsCacheFlushBit()
    {
        var response = BuildResponse();

        // 0x8001 is the cache-flush bit over class IN — meaningless in ordinary DNS,
        // where it reads as class 32769 and the record is dropped as unknown.
        foreach (var record in response.Answers.Concat(response.Additionals))
            Assert.Equal(DnsClass.IN, record.Class);
    }

    [Fact]
    public void LegacyResponse_CapsEveryTtlAtTenSeconds()
    {
        var response = BuildResponse();

        Assert.NotEmpty(response.Answers);
        foreach (var record in response.Answers.Concat(response.Additionals))
            Assert.True(record.Ttl <= 10, $"{record.Type} record TTL {record.Ttl} exceeds the §6.7 ceiling of 10 s");
    }

    [Fact]
    public void LegacyResponse_ResolvesTheServiceInOneRoundTrip()
    {
        var response = BuildResponse();

        // PTR answers the question that was asked...
        var ptr = Assert.Single(response.Answers);
        Assert.Equal(DnsRecordType.PTR, ptr.Type);
        Assert.Equal("Test Core._osc._udp.local.", DnsParser.ParsePtr(ptr.Data, ptr.Data), ignoreCase: true);

        // ...and everything needed to reach the service rides along, so a one-shot
        // resolver does not have to follow up with SRV/TXT/A queries it may not send.
        var srv = Assert.Single(response.Additionals, x => x.Type == DnsRecordType.SRV);
        Assert.Equal(9000, DnsParser.ParseSrv(srv.Data, srv.Data).port);

        var txt = Assert.Single(response.Additionals, x => x.Type == DnsRecordType.TXT);
        Assert.Equal("DMXCore100", DnsParser.ParseTxt(txt.Data)["model"]);

        var a = Assert.Single(response.Additionals, x => x.Type == DnsRecordType.A);
        Assert.Equal(Local, DnsParser.ParseA(a.Data));
    }

    // -------------------------------------------------------------------------
    // The receive-side half of the same rule
    // -------------------------------------------------------------------------

    [Fact]
    public void Browser_IgnoresResponsesFromAnyOtherPort_ByDefault()
    {
        using var browser = new MdnsBrowser("_osc._udp");

        Assert.False(browser.ShouldIgnoreResponseFrom(5353));
        Assert.True(browser.ShouldIgnoreResponseFrom(53773));
        Assert.True(browser.ShouldIgnoreResponseFrom(53));
    }

    [Fact]
    public void Browser_AcceptsAnySourcePort_WhenOptedOut()
    {
        // The transitional setting for a network that still has pre-1.0.19 responders
        // on it; without it they are invisible, which is the correct behaviour and the
        // reason the opt-out has to exist at all.
        using var browser = new MdnsBrowser("_osc._udp", acceptResponsesFromAnyPort: true);

        Assert.False(browser.ShouldIgnoreResponseFrom(5353));
        Assert.False(browser.ShouldIgnoreResponseFrom(53773));
    }
}
