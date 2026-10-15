using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

/// <summary>
/// A query is answered on the interface it arrived on, with that interface's own
/// addresses, and not more than once per second there (RFC 6762 §6). These pin
/// the three pieces that add up to that: which socket keeps a packet, which
/// addresses go in a message, and when an answer is withheld.
/// </summary>
public class PerInterfaceTests
{
    private static readonly IPAddress Wired = IPAddress.Parse("192.168.240.196");
    private static readonly IPAddress HyperV = IPAddress.Parse("172.26.192.1");

    private const int WiredIndex = 4;
    private const int HyperVIndex = 40;

    // -------------------------------------------------------------------------
    // One packet, one socket
    // -------------------------------------------------------------------------

    [Fact]
    public void Socket_KeepsOnlyPacketsFromItsOwnInterface()
    {
        // Windows delivers a multicast datagram to every 0.0.0.0:5353 socket that
        // joined the group. Each socket must keep its own interface's copy and drop
        // the rest, or one query becomes N and the answers multiply with it.
        Assert.True(MulticastTransport.AcceptsPacket(WiredIndex, WiredIndex));
        Assert.False(MulticastTransport.AcceptsPacket(WiredIndex, HyperVIndex));
        Assert.False(MulticastTransport.AcceptsPacket(HyperVIndex, WiredIndex));
    }

    [Fact]
    public void Socket_KeepsPacketsOfUnknownOrigin()
    {
        // Without IP_PKTINFO there is nothing to filter on; dropping would mean
        // going deaf, which is the one failure this transport exists to avoid.
        Assert.True(MulticastTransport.AcceptsPacket(WiredIndex, 0));
        Assert.True(MulticastTransport.AcceptsPacket(WiredIndex, MulticastTransport.UnknownInterface));
    }

    // -------------------------------------------------------------------------
    // Per-interface A records
    // -------------------------------------------------------------------------

    [Fact]
    public void Announcement_CarriesOnlyTheInterfacesOwnAddresses()
    {
        var profile = new ServiceProfile("Test Core", "_osc._udp", 8000);
        using var advertiser = new MdnsAdvertiser(profile);

        var onHyperV = Addresses(advertiser.BuildAnnounceMessage(advertiser.AddressesFor([HyperV])));

        // The wired address must not leak onto the Hyper-V side: that is what made
        // Bonjour on the same host list the service twice with the same address.
        Assert.Equal([HyperV], onHyperV);

        var onWired = Addresses(advertiser.BuildAnnounceMessage(advertiser.AddressesFor([Wired])));

        Assert.Equal([Wired], onWired);
    }

    [Fact]
    public void Announcement_KeepsEveryAddressOfAMultiAddressInterface()
    {
        var second = IPAddress.Parse("192.168.241.57");
        var profile = new ServiceProfile("Test Core", "_osc._udp", 8000);
        using var advertiser = new MdnsAdvertiser(profile);

        // One NIC with two addresses still advertises both, in the order given.
        var addresses = Addresses(advertiser.BuildAnnounceMessage(advertiser.AddressesFor([Wired, second])));

        Assert.Equal([Wired, second], addresses);
    }

    [Fact]
    public void PinnedAddress_IsAdvertisedOnEveryInterface()
    {
        var profile = new ServiceProfile("Test Core", "_osc._udp", 8000);
        using var advertiser = new MdnsAdvertiser(profile, Wired);

        // An explicit address is a promise to the caller: that address and only that
        // address, whatever interface the message leaves on.
        Assert.Equal([Wired], advertiser.AddressesFor([HyperV]));
        Assert.Equal([Wired], Addresses(advertiser.BuildAnnounceMessage(advertiser.AddressesFor([HyperV]))));
    }

    [Fact]
    public void LegacyResponse_CarriesTheInterfacesOwnAddresses()
    {
        var profile = new ServiceProfile("Test Core", "_osc._udp", 8000);
        using var advertiser = new MdnsAdvertiser(profile);
        var question = new DnsQuestion("_osc._udp.local.", DnsRecordType.PTR, DnsClass.IN);

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(advertiser.BuildLegacyResponse(question, 0x1234, [HyperV])), out var parsed));
        Assert.NotNull(parsed);

        var a = Assert.Single(parsed!.Additionals, x => x.Type == DnsRecordType.A);
        Assert.Equal(HyperV, DnsParser.ParseA(a.Data));
    }

    // -------------------------------------------------------------------------
    // Once per second per interface (RFC 6762 §6)
    // -------------------------------------------------------------------------

    [Fact]
    public void RateLimiter_AllowsTheFirstAnswer()
    {
        var limiter = new AnswerRateLimiter(TimeSpan.FromSeconds(1));

        Assert.True(limiter.MayAnswer(WiredIndex, TimeSpan.Zero));
    }

    [Fact]
    public void RateLimiter_WithholdsARepeatWithinASecond()
    {
        var limiter = new AnswerRateLimiter(TimeSpan.FromSeconds(1));

        limiter.Record(WiredIndex, TimeSpan.FromSeconds(10));

        // A second querier 6 ms later already saw the first answer on the wire.
        Assert.False(limiter.MayAnswer(WiredIndex, TimeSpan.FromSeconds(10.006)));
        Assert.False(limiter.MayAnswer(WiredIndex, TimeSpan.FromSeconds(10.999)));
    }

    [Fact]
    public void RateLimiter_AllowsAgainAfterASecond()
    {
        var limiter = new AnswerRateLimiter(TimeSpan.FromSeconds(1));

        limiter.Record(WiredIndex, TimeSpan.FromSeconds(10));

        Assert.True(limiter.MayAnswer(WiredIndex, TimeSpan.FromSeconds(11)));
        Assert.True(limiter.MayAnswer(WiredIndex, TimeSpan.FromSeconds(12.5)));
    }

    [Fact]
    public void RateLimiter_IsPerInterface()
    {
        var limiter = new AnswerRateLimiter(TimeSpan.FromSeconds(1));

        limiter.Record(WiredIndex, TimeSpan.FromSeconds(10));

        // The rule is "on a given interface": an answer on the wired side must not
        // silence the Hyper-V side, whose querier never heard it.
        Assert.True(limiter.MayAnswer(HyperVIndex, TimeSpan.FromSeconds(10.001)));
    }

    // -------------------------------------------------------------------------
    // What this machine actually binds
    // -------------------------------------------------------------------------

    [Fact]
    public void Transport_BindsEachInterfaceOnceWithItsOwnAddresses()
    {
        using var transport = new MulticastTransport();

        try
        {
            transport.Start();
        }
        catch (InvalidOperationException)
        {
            // A build agent with no multicast-capable interface has nothing to check.
            return;
        }

        var adapters = transport.Adapters;

        Assert.NotEmpty(adapters);
        Assert.Equal(adapters.Count, adapters.Select(x => x.InterfaceIndex).Distinct().Count());

        foreach (var adapter in adapters)
        {
            Assert.NotEmpty(adapter.Addresses);
            Assert.All(adapter.Addresses, ip => Assert.False(IPAddress.IsLoopback(ip)));
        }
    }

    private static List<IPAddress> Addresses(DnsMessage message)
    {
        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(message), out var parsed));
        Assert.NotNull(parsed);

        return parsed!.Answers
            .Where(x => x.Type == DnsRecordType.A)
            .Select(x => DnsParser.ParseA(x.Data)!)
            .ToList();
    }
}
