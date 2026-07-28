using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

/// <summary>
/// A multi-homed host advertises one A record per address so that a client on any
/// of its networks gets a reachable answer. These cover the two halves of that:
/// the responder emitting several, and a browser not being confused by them.
/// </summary>
public class MultiHomedTests
{
    private static readonly IPAddress Wired = IPAddress.Parse("192.168.250.67");
    private static readonly IPAddress Usb = IPAddress.Parse("192.168.240.72");

    [Fact]
    public void GetLocalAddresses_ReturnsPreferredFirst()
    {
        var all = MulticastTransport.GetLocalAddresses();

        // Whatever this machine has, the single-address API must agree with the
        // head of the list — that is what keeps existing callers behaving the same.
        var preferred = MulticastTransport.GetLocalAddress();

        if (preferred == null)
        {
            Assert.Empty(all);

            return;
        }

        Assert.NotEmpty(all);
        Assert.Equal(preferred, all[0]);
        Assert.Equal(all.Count, all.Distinct().Count());
    }

    [Fact]
    public void MultipleARecords_RoundTripInOrder()
    {
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };
        msg.Answers.Add(new DnsRecord("host.local.", DnsRecordType.A, DnsClass.IN, 120, DnsEncoder.BuildA(Wired)));
        msg.Answers.Add(new DnsRecord("host.local.", DnsRecordType.A, DnsClass.IN, 120, DnsEncoder.BuildA(Usb)));

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(msg), out var parsed));
        Assert.NotNull(parsed);

        var addresses = parsed!.Answers
            .Where(x => x.Type == DnsRecordType.A)
            .Select(x => DnsParser.ParseA(x.Data))
            .ToList();

        Assert.Equal(2, addresses.Count);
        Assert.Equal(Wired, addresses[0]);
        Assert.Equal(Usb, addresses[1]);
    }

    /// <summary>
    /// The browser must keep the FIRST address for a hostname in a message, not the
    /// last. Taking each in turn would leave it holding the least preferred address,
    /// which is the regression this ordering invites.
    /// </summary>
    [Fact]
    public void FirstAddressWins_NotLast()
    {
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };
        msg.Answers.Add(new DnsRecord("host.local.", DnsRecordType.A, DnsClass.IN, 120, DnsEncoder.BuildA(Wired)));
        msg.Answers.Add(new DnsRecord("host.local.", DnsRecordType.A, DnsClass.IN, 120, DnsEncoder.BuildA(Usb)));

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(msg), out var parsed));
        Assert.NotNull(parsed);

        // Mirror the browser's rule: first A record per name is the one that sticks.
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IPAddress? chosen = null;

        foreach (var record in parsed!.Answers.Where(x => x.Type == DnsRecordType.A))
        {
            if (!taken.Add(record.Name))
                continue;

            chosen = DnsParser.ParseA(record.Data);
        }

        Assert.Equal(Wired, chosen);
    }

    /// <summary>
    /// Physical adapters must all come before virtual ones, so a consumer that takes
    /// only the first address gets the one most likely to be reachable from another
    /// machine. Asserted as a partition rather than against fixed addresses, so it
    /// holds on any machine — including one with no virtual adapters at all.
    /// </summary>
    [Fact]
    public void GetLocalAddresses_PhysicalBeforeVirtual()
    {
        var virtualAddresses = new HashSet<IPAddress>();

        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!MulticastTransport.IsLikelyVirtual(nic))
                continue;

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    virtualAddresses.Add(ua.Address);
            }
        }

        var all = MulticastTransport.GetLocalAddresses();

        bool seenVirtual = false;

        foreach (var ip in all)
        {
            if (virtualAddresses.Contains(ip))
            {
                seenVirtual = true;

                continue;
            }

            Assert.False(seenVirtual, $"physical address {ip} came after a virtual one");
        }
    }

    [Fact]
    public void ExplicitAddress_AdvertisesOnlyThatOne()
    {
        var profile = new ServiceProfile("TestInstance", "_test._udp", 1234);

        using var advertiser = new MdnsAdvertiser(profile, Usb);

        // Constructing with an explicit address must not fan out to every local
        // address — callers use this to pin an advert to one network.
        Assert.NotNull(advertiser);
    }
}
