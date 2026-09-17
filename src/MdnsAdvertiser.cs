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

    private readonly MulticastTransport transport;
    private readonly ServiceProfile profile;
    private readonly IReadOnlyList<IPAddress> localAddresses;

    private readonly Timer announceTimer;
    private AnnounceState state = AnnounceState.Idle;
    private int countdown;
    private readonly Stopwatch elapsed = new();
    private int refreshCountdown = 2;

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
    /// Local IPv4 address to include in A records. When null, every local address is
    /// advertised (see <see cref="MulticastTransport.GetLocalAddresses"/>) so that a
    /// multi-homed host is reachable from all of its networks; pass an address
    /// explicitly to advertise on one network only.
    /// </param>
    public MdnsAdvertiser(ServiceProfile profile, IPAddress? localAddress = null)
    {
        this.profile = profile;
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
            transport.Send(DnsEncoder.Encode(BuildClaimMessage()));

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
                        transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
                        state = AnnounceState.Announce2;
                        countdown = 1;
                    }
                    break;

                case AnnounceState.Announce2:
                    if (--countdown == 0)
                    {
                        transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
                        state = AnnounceState.Announce3;
                        countdown = 4;
                    }
                    break;

                case AnnounceState.Announce3:
                    if (--countdown == 0)
                    {
                        transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
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
                        transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
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

    private void OnPacketReceived(byte[] data, IPEndPoint remote)
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
                        transport.SendTo(DnsEncoder.Encode(BuildLegacyResponse(q, msg.Id)), remote);
                    }
                    else
                    {
                        // Re-announce immediately
                        transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
                        elapsed.Restart();
                    }
                    break;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Message builders
    // -------------------------------------------------------------------------

    private DnsMessage BuildClaimMessage()
    {
        var msg = new DnsMessage { IsResponse = false };
        msg.Questions.Add(new DnsQuestion(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN));
        msg.Questions.Add(new DnsQuestion(profile.Hostname, DnsRecordType.SRV, DnsClass.IN));

        msg.Authorities.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN, ShortTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));
        foreach (var address in localAddresses)
        {
            msg.Authorities.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN, ShortTtl,
                DnsEncoder.BuildA(address)));
        }

        return msg;
    }

    /// <summary>
    /// The full announcement: PTR, SRV, TXT and one A per local address.
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
    internal DnsMessage BuildAnnounceMessage()
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

        // A — one per local address, so a client on any of our networks has a
        // reachable answer rather than only the first interface's address.
        foreach (var address in localAddresses)
        {
            msg.Answers.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN_Unicast, ShortTtl,
                DnsEncoder.BuildA(address)));
        }

        return msg;
    }

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
    internal DnsMessage BuildLegacyResponse(DnsQuestion question, ushort queryId)
    {
        var msg = new DnsMessage { Id = queryId, IsResponse = true, IsAuthoritative = true };

        msg.Questions.Add(question);

        msg.Answers.Add(new DnsRecord(profile.FullServiceType, DnsRecordType.PTR, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildPtr(profile.FullInstanceName)));

        msg.Additionals.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));

        msg.Additionals.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.TXT, DnsClass.IN, LegacyTtl,
            DnsEncoder.BuildTxt(profile.Properties)));

        foreach (var address in localAddresses)
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
