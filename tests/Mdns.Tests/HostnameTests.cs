using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

/// <summary>
/// The host name in the SRV target and A records is derived from the instance name
/// unless the caller gives one — the machine's real name, so that the service
/// resolves to the same name the OS responder (Bonjour, avahi) answers for.
/// </summary>
public class HostnameTests
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.250.67");

    [Fact]
    public void Hostname_IsDerivedFromTheInstanceName_ByDefault()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80);

        Assert.Equal("DMX-Core-100.local.", profile.Hostname);
    }

    [Fact]
    public void Hostname_IsTheGivenOne_WhenProvided()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80, hostname: "dmxcore-1234");

        Assert.Equal("dmxcore-1234.local.", profile.Hostname);

        // Only the host name changes: the instance is still what the user named it.
        Assert.Equal("DMX Core 100", profile.InstanceName);
        Assert.Equal("DMX Core 100._http._tcp.local.", profile.FullInstanceName);
    }

    [Theory]
    [InlineData("dmxcore-1234.local")]
    [InlineData("dmxcore-1234.local.")]
    [InlineData("dmxcore-1234.LOCAL")]
    public void Hostname_AcceptsTheLocalSuffix(string given)
    {
        // Dns.GetHostName() hands some callers "name.local"; the suffix must not be
        // sanitised into "-local" and then suffixed again.
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80, hostname: given);

        Assert.Equal("dmxcore-1234.local.", profile.Hostname);
    }

    [Fact]
    public void Hostname_IsSanitisedLikeTheInstanceName()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80, hostname: "Hakan's PC_2");

        Assert.Equal("Hakan-s-PC-2.local.", profile.Hostname);
    }

    [Fact]
    public void Announcement_PointsSrvAndARecordsAtTheGivenHostname()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80, hostname: "dmxcore-1234");
        using var advertiser = new MdnsAdvertiser(profile, Local);

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(advertiser.BuildAnnounceMessage()), out var parsed));
        Assert.NotNull(parsed);

        var srv = Assert.Single(parsed!.Answers, x => x.Type == DnsRecordType.SRV);
        Assert.Equal("dmxcore-1234.local.", DnsParser.ParseSrv(srv.Data, srv.Data).target, ignoreCase: true);

        var a = Assert.Single(parsed.Answers, x => x.Type == DnsRecordType.A);
        Assert.Equal("dmxcore-1234.local.", a.Name, ignoreCase: true);

        // The name derived from the instance must not appear anywhere any more.
        Assert.DoesNotContain(parsed.Answers, x => string.Equals(x.Name, "DMX-Core-100.local.", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void LegacyResponse_PointsSrvAndARecordsAtTheGivenHostname()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80, hostname: "dmxcore-1234");
        using var advertiser = new MdnsAdvertiser(profile, Local);
        var question = new DnsQuestion("_http._tcp.local.", DnsRecordType.PTR, DnsClass.IN);

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(advertiser.BuildLegacyResponse(question, 0x1234)), out var parsed));
        Assert.NotNull(parsed);

        var srv = Assert.Single(parsed!.Additionals, x => x.Type == DnsRecordType.SRV);
        Assert.Equal("dmxcore-1234.local.", DnsParser.ParseSrv(srv.Data, srv.Data).target, ignoreCase: true);

        var a = Assert.Single(parsed.Additionals, x => x.Type == DnsRecordType.A);
        Assert.Equal("dmxcore-1234.local.", a.Name, ignoreCase: true);
    }
}
