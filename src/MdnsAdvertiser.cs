namespace Haukcode.Mdns;

/// <summary>
/// Advertises a DNS-SD service via mDNS (RFC 6762 + RFC 6763).
///
/// Announcement sequence:
///   1. Probe: send claim packet with SRV+A in the Authority section
///   2. Announce x3: send full response with PTR+SRV+TXT+A
///   3. Steady state: re-announce at 50%, 90%, 95% of TTL
///   4. Respond to incoming PTR queries for the service type — multicast to a
///      compliant querier, unicast to a legacy one-shot resolver (§6.7)
///   5. Goodbye: re-send with TTL=0 on dispose (x2, 500 ms apart)
///
/// Every multicast announcement is built per interface and carries only that
/// interface's own addresses, and a query is answered only on the interface it
/// arrived on — the way Bonjour and avahi behave.
///
/// Note: Full name-conflict resolution (RFC 6762 §8) is not implemented.
/// On a typical LAN with a single DMX controller this is acceptable.
/// </summary>
public sealed class MdnsAdvertiser : IDisposable, IAsyncDisposable
{
    private const uint LongTtl  = 4500;
    private const uint ShortTtl = 120;

    /// <summary>
    /// Ceiling on every TTL in a legacy unicast response (RFC 6762 §6.7). A legacy
    /// resolver has no way to learn that a record went away — it never sees our
    /// goodbye packets — so it must be handed something that expires on its own.
    /// </summary>
    private const uint LegacyTtl = 10;

    private const int MdnsPort = 5353;

    /// <summary>
    /// RFC 6762 §6: the same record is not multicast on one interface more than once
    /// per second.
    /// </summary>
    private static readonly TimeSpan MinimumAnswerInterval = TimeSpan.FromSeconds(1);

    private readonly MulticastTransport transport;
    private readonly ServiceProfile profile;

    /// <summary>
    /// Every address this host advertises, in preference order. Used when an
    /// interface cannot be told apart — a legacy reply or a packet whose arrival
    /// interface the kernel did not report.
    /// </summary>
    private readonly IReadOnlyList<IPAddress> localAddresses;

    /// <summary>
    /// The one address to advertise everywhere, when the caller pinned one.
    /// </summary>
    private readonly IPAddress? pinnedAddress;

    private readonly Timer announceTimer;
    private AnnounceState state = AnnounceState.Idle;
    private int countdown;
    private readonly Stopwatch elapsed = new();
    private int refreshCountdown = 2;

    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly AnswerRateLimiter answerRateLimiter = new(MinimumAnswerInterval);

    private bool disposed;
    private readonly object mutex = new();

    /// <summary>
    /// Completed (TrySetResult) when the goodbye sequence finishes so that
    /// Dispose/DisposeAsync can release resources without busy-waiting.
    /// </summary>
    private readonly TaskCompletionSource<bool> goodbyeDone =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <param name="profile">Service to advertise.</param>
    /// <param name="localAddress">
    /// Local IPv4 address to include in A records. When null, each interface
    /// advertises its own addresses (see <see cref="MulticastTransport.GetLocalAddresses"/>
    /// for which interfaces qualify) so that a multi-homed host is reachable from all
    /// of its networks; pass an address explicitly to advertise that one address on
    /// every interface.
    /// </param>
    public MdnsAdvertiser(ServiceProfile profile, IPAddress? localAddress = null)
    {
        this.profile = profile;
        this.pinnedAddress = localAddress;
        this.localAddresses = localAddress != null
            ? [localAddress]
            : [.. MulticastTransport.GetLocalAddresses()];

        if (this.localAddresses.Count == 0)
            throw new InvalidOperationException("No suitable local IPv4 address found.");

        transport = new MulticastTransport();
        transport.PacketReceived += OnPacketReceived;

        announceTimer = new Timer(OnTimer, null, Timeout.Infinite, Timeout.Infinite);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>Start advertising the service on the local network.</summary>
    public void Start()
    {
        lock (mutex)
        {
            if (state != AnnounceState.Idle)
                return;

            transport.Start();

            // Probe first (claim packet)
            SendOnEveryInterface(BuildClaimMessage, countsAsAnswer: false);

            state = AnnounceState.Announce1;
            countdown = 2;
            ScheduleTimer(500);
        }
    }

    // -------------------------------------------------------------------------
    // Timer state machine
    // -------------------------------------------------------------------------

    private void OnTimer(object? _)
    {
        lock (mutex)
        {
            // The goodbye states run *because* we are disposed — BeginGoodbye sets the
            // flag before handing the rest of the sequence to this timer. Bailing out
            // on the flag alone (as this did) meant the second goodbye packet was never
            // sent, goodbyeDone was never completed, and every teardown paid the full
            // wait: 2 s of dead time from Dispose, and a TimeoutException out of
            // DisposeAsync.
            if (disposed && state != AnnounceState.Goodbye1)
                return;

            switch (state)
            {
                case AnnounceState.Announce1:
                    if (--countdown == 0)
                    {
                        SendAnnouncementOnEveryInterface();
                        state = AnnounceState.Announce2;
                        countdown = 1;
                    }
                    break;

                case AnnounceState.Announce2:
                    if (--countdown == 0)
                    {
                        SendAnnouncementOnEveryInterface();
                        state = AnnounceState.Announce3;
                        countdown = 4;
                    }
                    break;

                case AnnounceState.Announce3:
                    if (--countdown == 0)
                    {
                        SendAnnouncementOnEveryInterface();
                        state = AnnounceState.Ready;
                        elapsed.Restart();
                        refreshCountdown = 2;
                    }
                    break;

                case AnnounceState.Ready:
                    var targetSeconds = refreshCountdown switch
                    {
                        2 => 0.5  * LongTtl,
                        1 => 0.9  * LongTtl,
                        _ => 0.95 * LongTtl,
                    };

                    if (elapsed.Elapsed.TotalSeconds >= targetSeconds)
                    {
                        refreshCountdown = (2 + refreshCountdown) % 3;
                        if (refreshCountdown == 2) elapsed.Restart();
                        SendAnnouncementOnEveryInterface();
                    }
                    break;

                case AnnounceState.Goodbye1:
                    if (--countdown == 0)
                    {
                        // Second and last goodbye, 500 ms after the one BeginGoodbye
                        // sent inline. Nothing is waiting after it, so release the
                        // caller here rather than idling through another state.
                        transport.Send(DnsEncoder.Encode(BuildGoodbyeMessage()));
                        state = AnnounceState.Idle;
                        goodbyeDone.TrySetResult(true);
                        return; // done — no reschedule
                    }
                    break;
            }

            ScheduleTimer(500);
        }
    }

    private void ScheduleTimer(int ms)
        => announceTimer.Change(ms, Timeout.Infinite);

    // -------------------------------------------------------------------------
    // Respond to incoming PTR queries
    // -------------------------------------------------------------------------

    private void OnPacketReceived(byte[] data, IPEndPoint remote, int interfaceIndex)
    {
        if (!DnsParser.TryParse(data, out var msg) || msg == null || msg.IsResponse)
            return;

        // A query from a port other than 5353 is a one-shot resolver — `dns-sd`,
        // a browser's discovery call, an embedded client — not a full Multicast
        // DNS querier (RFC 6762 §5.1). It is listening on that ephemeral socket
        // for a unicast answer and generally not a member of the multicast group
        // at all, so a multicast re-announce never reaches it.
        bool isLegacyQuerier = remote.Port != MdnsPort;

        lock (mutex)
        {
            if (state != AnnounceState.Ready) return;

            foreach (var q in msg.Questions)
            {
                if (q.Type == DnsRecordType.PTR &&
                    string.Equals(q.Name, profile.FullServiceType, StringComparison.OrdinalIgnoreCase))
                {
                    if (isLegacyQuerier)
                    {
                        transport.SendTo(DnsEncoder.Encode(BuildLegacyResponse(q, msg.Id, AddressesOn(interfaceIndex))), remote);
                    }
                    else
                    {
                        AnswerOn(interfaceIndex);
                    }
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Multicast the announcement in answer to a query heard on
    /// <paramref name="interfaceIndex"/>: on that interface only, with that
    /// interface's addresses, and not within a second of the last one there.
    /// </summary>
    private void AnswerOn(int interfaceIndex)
    {
        var now = clock.Elapsed;

        if (interfaceIndex == MulticastTransport.UnknownInterface)
        {
            // No arrival interface: answer the old way, everywhere, but still no more
            // than once per second.
            if (!answerRateLimiter.MayAnswer(interfaceIndex, now))
                return;

            SendAnnouncementOnEveryInterface();
            answerRateLimiter.Record(interfaceIndex, now);
            elapsed.Restart();

            return;
        }

        if (!answerRateLimiter.MayAnswer(interfaceIndex, now))
            return;

        var addresses = AddressesOn(interfaceIndex);

        if (addresses.Count == 0)
            return;

        transport.SendOn(interfaceIndex, DnsEncoder.Encode(BuildAnnounceMessage(addresses)));
        answerRateLimiter.Record(interfaceIndex, now);
        elapsed.Restart();
    }

    /// <summary>
    /// The addresses to put in a message that leaves on
    /// <paramref name="interfaceIndex"/>: the pinned address if there is one, else
    /// that interface's own addresses, else (interface unknown or not ours) every
    /// local address.
    /// </summary>
    private IReadOnlyList<IPAddress> AddressesOn(int interfaceIndex)
    {
        if (pinnedAddress != null)
            return [pinnedAddress];

        if (interfaceIndex == MulticastTransport.UnknownInterface)
            return localAddresses;

        var adapter = transport.Adapters.FirstOrDefault(x => x.InterfaceIndex == interfaceIndex);

        return adapter == null ? localAddresses : AddressesFor(adapter.Addresses);
    }

    /// <summary>
    /// What one interface advertises, given the addresses configured on it.
    /// </summary>
    /// <remarks>
    /// Per-interface A records are what make a multi-homed host honest: a browser on
    /// the Hyper-V side of a developer PC is told the Hyper-V address, and a browser
    /// on the wired side the wired one. Handing both sides the full list, as this did
    /// until now, made Bonjour on the same host list the service once per interface
    /// with the same first address each time.
    /// </remarks>
    internal IReadOnlyList<IPAddress> AddressesFor(IReadOnlyList<IPAddress> interfaceAddresses)
        => pinnedAddress != null ? [pinnedAddress] : interfaceAddresses;

    /// <summary>
    /// Multicast the full announcement on every interface, each with its own
    /// addresses. Used for the unsolicited announcements and TTL refreshes.
    /// </summary>
    private void SendAnnouncementOnEveryInterface()
        => SendOnEveryInterface(BuildAnnounceMessage, countsAsAnswer: true);

    private void SendOnEveryInterface(Func<IReadOnlyList<IPAddress>, DnsMessage> build, bool countsAsAnswer)
    {
        var now = clock.Elapsed;
        bool sentAny = false;

        foreach (var adapter in transport.Adapters)
        {
            var addresses = AddressesFor(adapter.Addresses);

            if (addresses.Count == 0)
                continue;

            transport.SendOn(adapter.InterfaceIndex, DnsEncoder.Encode(build(addresses)));

            if (countsAsAnswer)
                answerRateLimiter.Record(adapter.InterfaceIndex, now);

            sentAny = true;
        }

        if (!sentAny)
        {
            // Nothing bound with an address of its own (should not happen once Start
            // succeeded) - fall back to one message with every address, everywhere.
            transport.Send(DnsEncoder.Encode(build(localAddresses)));
        }
    }

    // -------------------------------------------------------------------------
    // Message builders
    // -------------------------------------------------------------------------

    private DnsMessage BuildClaimMessage(IReadOnlyList<IPAddress> addresses)
    {
        var msg = new DnsMessage { IsResponse = false };
        msg.Questions.Add(new DnsQuestion(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN));
        msg.Questions.Add(new DnsQuestion(profile.Hostname, DnsRecordType.SRV, DnsClass.IN));

        msg.Authorities.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN, ShortTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));
        foreach (var address in addresses)
        {
            msg.Authorities.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN, ShortTtl,
                DnsEncoder.BuildA(address)));
        }

        return msg;
    }

    /// <summary>
    /// The full announcement with every local address - what a message carries when
    /// the interface it leaves on cannot be told.
    /// </summary>
    internal DnsMessage BuildAnnounceMessage()
        => BuildAnnounceMessage(localAddresses);

    /// <summary>
    /// The full announcement: PTR, SRV, TXT and one A per address in
    /// <paramref name="addresses"/>.
    /// </summary>
    /// <remarks>
    /// Record order is load-bearing, which is not obvious from the wire format. A
    /// browsing client matches an incoming packet to its outstanding request by the
    /// PTR answer naming the service type; lwIP (and the stacks built on it — ESP-IDF,
    /// Zephyr) establishes the request at that record and drops everything that came
    /// *before* it in the packet. With SRV first, as this built the message until now,
    /// every such client learned the name and address but got port 0 and had to guess.
    /// So the service-type PTR goes first and everything that describes the instance
    /// follows it.
    ///
    /// Everything stays in the Answer section rather than moving SRV/TXT/A to
    /// Additional, which is the other way to fix the same thing: these messages are
    /// also the unsolicited announcements, and RFC 6762 §8.3 asks for the newly
    /// registered records in the Answer section. Ordering satisfies both readings.
    /// </remarks>
    internal DnsMessage BuildAnnounceMessage(IReadOnlyList<IPAddress> addresses)
    {
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };

        // PTR: service type → instance. First, deliberately — see above.
        msg.Answers.Add(new DnsRecord(profile.FullServiceType, DnsRecordType.PTR, DnsClass.IN, LongTtl,
            DnsEncoder.BuildPtr(profile.FullInstanceName)));

        // PTR: _services._dns-sd._udp.local. → service type
        msg.Answers.Add(new DnsRecord("_services._dns-sd._udp.local.", DnsRecordType.PTR, DnsClass.IN, LongTtl,
            DnsEncoder.BuildPtr(profile.FullServiceType)));

        // SRV
        msg.Answers.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN_Unicast, ShortTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));

        // TXT
        msg.Answers.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.TXT, DnsClass.IN_Unicast, LongTtl,
            DnsEncoder.BuildTxt(profile.Properties)));

        // A — one per address of the interface this message leaves on, so a client
        // on that network is handed an address it can reach and not the ones on
        // the host's other networks.
        foreach (var address in addresses)
        {
            msg.Answers.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN_Unicast, ShortTtl,
                DnsEncoder.BuildA(address)));
        }

        return msg;
    }

    /// <summary>
    /// The unicast answer to a legacy one-shot query (RFC 6762 §6.7), carrying every
    /// local address.
    /// </summary>
    internal DnsMessage BuildLegacyResponse(DnsQuestion question, ushort queryId)
        => BuildLegacyResponse(question, queryId, localAddresses);

    /// <summary>
    /// Build the unicast answer to a legacy one-shot query (RFC 6762 §6.7).
    /// </summary>
    /// <remarks>
    /// This is not the announce message with a different destination — a legacy
    /// resolver parses it as ordinary DNS, so four things differ:
    ///
    ///   * the query's ID is echoed (our multicast messages always use ID 0, which a
    ///     legacy resolver would reject as not matching its outstanding query);
    ///   * the question is repeated in the Question section, as a DNS reply must;
    ///   * the cache-flush bit is never set — in ordinary DNS that bit is part of the
    ///     class, so IN_Unicast (0x8001) reads as class 32769 and the record is
    ///     discarded as unknown;
    ///   * every TTL is capped at <see cref="LegacyTtl"/> seconds.
    ///
    /// The answer to the PTR question goes in the Answer section and everything needed
    /// to actually reach the service rides along in Additionals, so a one-shot browse
    /// resolves in a single round trip.
    /// </remarks>
    internal DnsMessage BuildLegacyResponse(DnsQuestion question, ushort queryId, IReadOnlyList<IPAddress> addresses)
    {
        var msg = new DnsMessage { Id = queryId, IsResponse = true, IsAuthoritative = true };

        msg.Questions.Add(question);

        msg.Answers.Add(new DnsRecord(profile.FullServiceType, DnsRecordType.PTR, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildPtr(profile.FullInstanceName)));

        msg.Additionals.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));

        msg.Additionals.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.TXT, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildTxt(profile.Properties)));

        foreach (var address in addresses)
        {
            msg.Additionals.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN, LegacyTtl,
                DnsEncoder.BuildA(address)));
        }

        return msg;
    }

    private DnsMessage BuildGoodbyeMessage()
    {
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };
        msg.Answers.Add(new DnsRecord(profile.FullServiceType, DnsRecordType.PTR, DnsClass.IN, 0,
            DnsEncoder.BuildPtr(profile.FullInstanceName)));
        return msg;
    }

    // -------------------------------------------------------------------------
    // IDisposable / IAsyncDisposable
    // -------------------------------------------------------------------------

    public void Dispose()
    {
        BeginGoodbye();
        // Wait up to 2 s for the two goodbye packets to be sent
        goodbyeDone.Task.Wait(2000);
        ReleaseResources();
    }

    public async ValueTask DisposeAsync()
    {
        BeginGoodbye();
        // Task.WaitAsync avoids blocking a thread pool thread (available since .NET 6).
        // A goodbye that cannot complete must not abort teardown — throwing here would
        // leave the sockets open, which is the one outcome Dispose exists to prevent.
        try
        {
            await goodbyeDone.Task.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }

        ReleaseResources();
    }

    private void BeginGoodbye()
    {
        lock (mutex)
        {
            if (disposed) return;
            disposed = true;

            // Send first goodbye immediately, then let the timer send the second
            transport.Send(DnsEncoder.Encode(BuildGoodbyeMessage()));
            state = AnnounceState.Goodbye1;
            countdown = 1;
            ScheduleTimer(500);
        }
    }

    private void ReleaseResources()
    {
        announceTimer.Dispose();
        transport.PacketReceived -= OnPacketReceived;
        transport.Dispose();
    }

    // -------------------------------------------------------------------------
    // State machine
    // -------------------------------------------------------------------------

    private enum AnnounceState
    {
        Idle,
        Announce1,
        Announce2,
        Announce3,
        Ready,
        Goodbye1,
    }
}
