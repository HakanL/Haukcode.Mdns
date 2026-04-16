namespace Haukcode.Mdns;

/// <summary>
/// Advertises a DNS-SD service via mDNS (RFC 6762 + RFC 6763).
///
/// Announcement sequence (matches vendored ZeroConfigWatcher behavior):
///   1. Probe: send claim packet with SRV+A in the Authority section
///   2. Announce x3: send full response with PTR+SRV+TXT+A+NSEC
///   3. Steady state: re-announce at 50%, 90%, 95% of TTL
///   4. Respond to incoming PTR queries for the service type
///   5. Goodbye: re-send with TTL=0 on dispose (x2)
///
/// Note: Full name-conflict resolution (RFC 6762 §8) is not implemented.
/// On a typical LAN with a single DMX controller this is acceptable.
/// </summary>
public sealed class MdnsAdvertiser : IDisposable
{
    private const uint LongTtl  = 4500;
    private const uint ShortTtl = 120;

    private readonly MulticastTransport transport;
    private readonly ServiceProfile profile;
    private readonly IPAddress localAddress;

    private readonly Timer announceTimer;
    private AnnounceState state = AnnounceState.Idle;
    private int countdown;
    private readonly Stopwatch elapsed = new();
    private int refreshCountdown = 2;

    private bool disposed;
    private readonly object mutex = new();

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <param name="profile">Service to advertise.</param>
    /// <param name="localAddress">
    /// Local IPv4 address to include in A records.
    /// If null, <see cref="MulticastTransport.GetLocalAddress"/> is used.
    /// </param>
    public MdnsAdvertiser(ServiceProfile profile, IPAddress? localAddress = null)
    {
        this.profile      = profile;
        this.localAddress = localAddress ?? MulticastTransport.GetLocalAddress()
            ?? throw new InvalidOperationException("No suitable local IPv4 address found.");

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
            if (disposed) return;

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
                        transport.Send(DnsEncoder.Encode(BuildGoodbyeMessage()));
                        state = AnnounceState.Goodbye2;
                        countdown = 2;
                    }
                    break;

                case AnnounceState.Goodbye2:
                    if (--countdown == 0)
                    {
                        state = AnnounceState.Idle;
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

        lock (mutex)
        {
            if (state != AnnounceState.Ready) return;

            foreach (var q in msg.Questions)
            {
                if (q.Type == DnsRecordType.PTR &&
                    string.Equals(q.Name, profile.FullServiceType, StringComparison.OrdinalIgnoreCase))
                {
                    // Re-announce immediately
                    transport.Send(DnsEncoder.Encode(BuildAnnounceMessage()));
                    elapsed.Restart();
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
        msg.Authorities.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN, ShortTtl,
            DnsEncoder.BuildA(localAddress)));

        return msg;
    }

    private DnsMessage BuildAnnounceMessage()
    {
        var msg = new DnsMessage { IsResponse = true, IsAuthoritative = true };

        // SRV
        msg.Answers.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.SRV, DnsClass.IN_Unicast, ShortTtl,
            DnsEncoder.BuildSrv(0, 0, profile.Port, profile.Hostname)));

        // TXT
        msg.Answers.Add(new DnsRecord(profile.FullInstanceName, DnsRecordType.TXT, DnsClass.IN_Unicast, LongTtl,
            DnsEncoder.BuildTxt(profile.Properties)));

        // PTR: _services._dns-sd._udp.local. → service type
        msg.Answers.Add(new DnsRecord("_services._dns-sd._udp.local.", DnsRecordType.PTR, DnsClass.IN, LongTtl,
            DnsEncoder.BuildPtr(profile.FullServiceType)));

        // PTR: service type → instance
        msg.Answers.Add(new DnsRecord(profile.FullServiceType, DnsRecordType.PTR, DnsClass.IN, LongTtl,
            DnsEncoder.BuildPtr(profile.FullInstanceName)));

        // A
        msg.Answers.Add(new DnsRecord(profile.Hostname, DnsRecordType.A, DnsClass.IN_Unicast, ShortTtl,
            DnsEncoder.BuildA(localAddress)));

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
    // IDisposable
    // -------------------------------------------------------------------------

    public void Dispose()
    {
        lock (mutex)
        {
            if (disposed) return;
            disposed = true;

            // Start goodbye sequence
            transport.Send(DnsEncoder.Encode(BuildGoodbyeMessage()));
            state = AnnounceState.Goodbye1;
            countdown = 2;
            ScheduleTimer(500);
        }

        // Wait briefly for goodbye packets to send before disposing transport
        Thread.Sleep(1200);

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
        Goodbye2,
    }
}
