using System.Net;
using Haukcode.Mdns;

namespace Mdns.Tests;

/// <summary>
/// A responder answers every question for a name it holds (RFC 6762 §6): the
/// service type's PTR, the instance's SRV and TXT, and the host name's A record.
/// Until 1.1 only the PTR browse was answered, so a client that already had the
/// instance or host name — or a resolver asked for dmxcore-1234.local — got
/// nothing unless an OS responder on the same machine held the name too.
///
/// Each query is built with <see cref="DnsEncoder"/> and parsed back with
/// <see cref="DnsParser"/>, which is how a received packet reaches the advertiser.
/// </summary>
public class AuthoritativeAnswerTests
{
    private static readonly IPAddress Wired = IPAddress.Parse("192.168.250.67");
    private static readonly IPAddress HyperV = IPAddress.Parse("172.26.192.1");

    private const string ServiceType = "_http._tcp.local.";
    private const string Instance = "DMX Core 100._http._tcp.local.";
    private const string Host = "dmxcore-1234.local.";

    private static MdnsAdvertiser Advertiser()
    {
        var profile = new ServiceProfile("DMX Core 100", "_http._tcp", 80,
            new Dictionary<string, string> { ["model"] = "DMXCore100" },
            hostname: "dmxcore-1234");

        return new MdnsAdvertiser(profile, Wired);
    }

    /// <summary>
    /// One question, the way it arrives: encoded, then parsed off the wire.
    /// </summary>
    private static DnsQuestion Received(string name, DnsRecordType type)
    {
        var query = new DnsMessage { Id = 0x4242, IsResponse = false };
        query.Questions.Add(new DnsQuestion(name, type, DnsClass.IN));

        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(query), out var parsed));
        Assert.NotNull(parsed);
        Assert.False(parsed!.IsResponse);

        return Assert.Single(parsed.Questions);
    }

    private static DnsMessage RoundTrip(DnsMessage message)
    {
        Assert.True(DnsParser.TryParse(DnsEncoder.Encode(message), out var parsed));
        Assert.NotNull(parsed);

        return parsed!;
    }

    // -------------------------------------------------------------------------
    // Which questions are ours
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(ServiceType, DnsRecordType.PTR, "Service")]
    [InlineData(Instance, DnsRecordType.SRV, "Instance")]
    [InlineData(Instance, DnsRecordType.TXT, "Instance")]
    [InlineData(Host, DnsRecordType.A, "Host")]
    public void Question_ForOneOfOurNames_IsRecognised(string name, DnsRecordType type, string expected)
    {
        using var advertiser = Advertiser();

        // The subject enum is internal, which a public theory parameter cannot be.
        Assert.Equal(Enum.Parse<MdnsAdvertiser.Subject>(expected), advertiser.SubjectOf(Received(name, type)));
    }

    [Theory]
    [InlineData("DMXCORE-1234.LOCAL.", DnsRecordType.A)]
    [InlineData("dmx core 100._HTTP._TCP.local.", DnsRecordType.SRV)]
    [InlineData("_HTTP._tcp.LOCAL.", DnsRecordType.PTR)]
    public void Question_IsMatchedWithoutRegardToCase(string name, DnsRecordType type)
    {
        using var advertiser = Advertiser();

        Assert.NotEqual(MdnsAdvertiser.Subject.None, advertiser.SubjectOf(Received(name, type)));
    }

    [Theory]
    [InlineData("_osc._udp.local.", DnsRecordType.PTR)]                 // another service type
    [InlineData("Other._http._tcp.local.", DnsRecordType.SRV)]          // another instance
    [InlineData("other-host.local.", DnsRecordType.A)]                  // another host
    [InlineData("DMX-Core-100.local.", DnsRecordType.A)]                // the name we would have derived, but did not
    [InlineData(Instance, DnsRecordType.A)]                             // right name, wrong type
    [InlineData(Host, DnsRecordType.SRV)]
    [InlineData(ServiceType, DnsRecordType.SRV)]
    [InlineData("_services._dns-sd._udp.local.", DnsRecordType.PTR)]   // not answered on request (unchanged)
    public void Question_ForAnythingElse_IsNotOurs(string name, DnsRecordType type)
    {
        using var advertiser = Advertiser();

        Assert.Equal(MdnsAdvertiser.Subject.None, advertiser.SubjectOf(Received(name, type)));
    }

    // -------------------------------------------------------------------------
    // Multicast answer to an A question
    // -------------------------------------------------------------------------

    [Fact]
    public void AddressAnswer_CarriesOneARecordPerAddress_AndNothingElse()
    {
        using var advertiser = Advertiser();

        var answer = RoundTrip(advertiser.BuildAddressMessage([Wired, HyperV]));

        Assert.True(answer.IsResponse);
        Assert.True(answer.IsAuthoritative);
        Assert.Empty(answer.Questions);
        Assert.Empty(answer.Additionals);

        Assert.Equal(2, answer.Answers.Count);
        Assert.All(answer.Answers, record =>
        {
            Assert.Equal(DnsRecordType.A, record.Type);
            Assert.Equal(Host, record.Name, ignoreCase: true);
            // Authoritative multicast answers carry the cache-flush bit, as the
            // announcement's A records do.
            Assert.Equal(DnsClass.IN_Unicast, record.Class);
        });
        Assert.Equal([Wired, HyperV], answer.Answers.Select(x => DnsParser.ParseA(x.Data)!));
    }

    // -------------------------------------------------------------------------
    // Legacy unicast answers (RFC 6762 §6.7) to the new question types
    // -------------------------------------------------------------------------

    [Fact]
    public void LegacyResponse_ToAnSrvQuestion_AnswersSrv_WithTxtAndARidingAlong()
    {
        using var advertiser = Advertiser();
        var question = Received(Instance, DnsRecordType.SRV);

        var response = RoundTrip(advertiser.BuildLegacyResponse(question, 0x4242, [Wired]));

        Assert.Equal(0x4242, response.Id);
        Assert.Equal(question, Assert.Single(response.Questions));

        var srv = Assert.Single(response.Answers);
        Assert.Equal(DnsRecordType.SRV, srv.Type);
        Assert.Equal(Instance, srv.Name, ignoreCase: true);
        var (_, _, port, target) = DnsParser.ParseSrv(srv.Data, srv.Data);
        Assert.Equal(80, port);
        Assert.Equal(Host, target, ignoreCase: true);

        var txt = Assert.Single(response.Additionals, x => x.Type == DnsRecordType.TXT);
        Assert.Equal("DMXCore100", DnsParser.ParseTxt(txt.Data)["model"]);

        var a = Assert.Single(response.Additionals, x => x.Type == DnsRecordType.A);
        Assert.Equal(Host, a.Name, ignoreCase: true);
        Assert.Equal(Wired, DnsParser.ParseA(a.Data));

        // The browse PTR was not asked for and is not sent.
        Assert.DoesNotContain(response.Answers.Concat(response.Additionals), x => x.Type == DnsRecordType.PTR);
    }

    [Fact]
    public void LegacyResponse_ToATxtQuestion_AnswersTxt_WithSrvAndARidingAlong()
    {
        using var advertiser = Advertiser();
        var question = Received(Instance, DnsRecordType.TXT);

        var response = RoundTrip(advertiser.BuildLegacyResponse(question, 0x4242, [Wired]));

        Assert.Equal(question, Assert.Single(response.Questions));

        var txt = Assert.Single(response.Answers);
        Assert.Equal(DnsRecordType.TXT, txt.Type);
        Assert.Equal("DMXCore100", DnsParser.ParseTxt(txt.Data)["model"]);

        Assert.Single(response.Additionals, x => x.Type == DnsRecordType.SRV);
        Assert.Single(response.Additionals, x => x.Type == DnsRecordType.A);
        Assert.DoesNotContain(response.Answers.Concat(response.Additionals), x => x.Type == DnsRecordType.PTR);
    }

    [Fact]
    public void LegacyResponse_ToAnAQuestion_AnswersWithTheAddressesAlone()
    {
        using var advertiser = Advertiser();
        var question = Received(Host, DnsRecordType.A);

        var response = RoundTrip(advertiser.BuildLegacyResponse(question, 0x4242, [Wired, HyperV]));

        Assert.Equal(0x4242, response.Id);
        Assert.Equal(question, Assert.Single(response.Questions));

        Assert.Equal(2, response.Answers.Count);
        Assert.All(response.Answers, record =>
        {
            Assert.Equal(DnsRecordType.A, record.Type);
            Assert.Equal(Host, record.Name, ignoreCase: true);
        });
        Assert.Equal([Wired, HyperV], response.Answers.Select(x => DnsParser.ParseA(x.Data)!));

        Assert.Empty(response.Additionals);
    }

    [Fact]
    public void LegacyResponse_ToTheNewQuestions_KeepsTheLegacyRules()
    {
        using var advertiser = Advertiser();

        foreach (var question in new[] { Received(Instance, DnsRecordType.SRV), Received(Instance, DnsRecordType.TXT), Received(Host, DnsRecordType.A) })
        {
            var response = RoundTrip(advertiser.BuildLegacyResponse(question, 0x4242, [Wired]));

            // No cache-flush bit and no TTL over 10 s, the same as the PTR reply:
            // the resolver parses this as ordinary DNS.
            Assert.NotEmpty(response.Answers);
            foreach (var record in response.Answers.Concat(response.Additionals))
            {
                Assert.Equal(DnsClass.IN, record.Class);
                Assert.True(record.Ttl <= 10, $"{record.Type} record TTL {record.Ttl} exceeds the §6.7 ceiling of 10 s");
            }
        }
    }

    [Fact]
    public void LegacyResponse_ToAQuestionThatIsNotOurs_IsRefused()
    {
        using var advertiser = Advertiser();
        var question = Received("other-host.local.", DnsRecordType.A);

        Assert.Throws<ArgumentException>(() => advertiser.BuildLegacyResponse(question, 0x4242, [Wired]));
    }
}
