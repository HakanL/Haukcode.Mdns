namespace Haukcode.Mdns;

/// <summary>
/// Browses for DNS-SD services via mDNS (RFC 6762 + RFC 6763).
///
/// Usage:
///   1. Subscribe to <see cref="ServiceFound"/> and/or <see cref="ServiceLost"/>
///   2. Call <see cref="Start"/> — sends an initial PTR query and listens continuously
///   3. Call <see cref="Dispose"/> to stop
///
/// Services are considered lost when their PTR TTL expires and they are not refreshed.
/// Re-queries are sent with exponential back-off (1 s → 2 s → 4 s … up to 1 h) per RFC 6762 §5.2.
/// </summary>
public sealed class MdnsBrowser : IDisposable, IAsyncDisposable
{
    private const int MdnsPort = 5353;

    private readonly string serviceType; // e.g. "_apple-midi._udp.local."
    private readonly bool acceptResponsesFromAnyPort;
    private readonly MulticastTransport transport;
    private readonly Timer expiryTimer;
    private readonly object mutex = new();

    private readonly Dictionary<string, DiscoveredService> services = new(StringComparer.OrdinalIgnoreCase);

    // Re-query back-off state (RFC 6762 §5.2)
    private DateTime nextQueryTime = DateTime.MaxValue; // set on Start()
    private int queryIntervalSeconds = 1;               // doubles up to 3600

    // Interlocked int used as a boolean: 0 = alive, 1 = disposed.
    // int is required because Interlocked.CompareExchange has no bool overload.
    private int disposed;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    public event Action<ServiceProfile>? ServiceFound;
    public event Action<ServiceProfile>? ServiceLost;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <param name="serviceType">
    /// Service type to browse, e.g. "_apple-midi._udp" or "_osc._udp".
    /// Do not include ".local." — it is appended automatically.
    /// </param>
    /// <param name="acceptResponsesFromAnyPort">
    /// Accept responses whose source UDP port is not 5353, which RFC 6762 §6 says to
    /// silently ignore. Off by default — leave it off unless you have a specific reason.
    /// </param>
    /// <remarks>
    /// The escape hatch exists for exactly one situation: a network that still holds
    /// responders which send from an ephemeral port, as this library itself did up to
    /// 1.0.18. Enforcing the rule makes those responders invisible, so a rollout where
    /// browser and responder upgrade at different times needs a way to stay lenient
    /// until the last old responder is gone. It is a transitional setting, not a
    /// preference: anything that reaches you only because of it is, by the letter of
    /// the spec, not Multicast DNS.
    /// </remarks>
    public MdnsBrowser(string serviceType, bool acceptResponsesFromAnyPort = false)
    {
        this.serviceType = serviceType.EndsWith(".local.", StringComparison.OrdinalIgnoreCase)
            ? serviceType
            : serviceType + ".local.";

        this.acceptResponsesFromAnyPort = acceptResponsesFromAnyPort;

        transport = new MulticastTransport();
        transport.PacketReceived += OnPacketReceived;

        expiryTimer = new Timer(OnExpiryTimer, null, Timeout.Infinite, Timeout.Infinite);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public void Start()
    {
        transport.Start();
        SendQuery();
        nextQueryTime = DateTime.UtcNow.AddSeconds(queryIntervalSeconds);
        expiryTimer.Change(1000, 1000);
    }

    public IReadOnlyList<ServiceProfile> CurrentServices()
    {
        lock (mutex)
            return services.Values
                .Where(s => s.IsComplete)
                .Select(s => s.ToProfile())
                .ToList();
    }

    // -------------------------------------------------------------------------
    // Expiry + re-query timer (fires every 1 s)
    // -------------------------------------------------------------------------

    private void OnExpiryTimer(object? _)
    {
        List<DiscoveredService>? expired = null;

        lock (mutex)
        {
            foreach (var svc in services.Values)
            {
                if (svc.IsExpired())
                {
                    expired ??= [];
                    expired.Add(svc);
                }
            }

            if (expired != null)
                foreach (var svc in expired)
                    services.Remove(svc.InstanceName);
        }

        if (expired != null)
            foreach (var svc in expired)
                if (svc.IsComplete)
                    ServiceLost?.Invoke(svc.ToProfile());

        // Re-query with exponential back-off (RFC 6762 §5.2)
        if (DateTime.UtcNow >= nextQueryTime)
        {
            SendQuery();
            queryIntervalSeconds = Math.Min(queryIntervalSeconds * 2, 3600);
            nextQueryTime = DateTime.UtcNow.AddSeconds(queryIntervalSeconds);
        }
    }

    // -------------------------------------------------------------------------
    // Receive
    // -------------------------------------------------------------------------

    /// <summary>
    /// RFC 6762 §6: "Multicast DNS implementations MUST silently ignore any Multicast
    /// DNS responses they receive where the source UDP port is not 5353."
    /// </summary>
    /// <remarks>
    /// The rule is not pedantry. A response from an ephemeral port is either a reply to
    /// a legacy one-shot query somebody else asked — whose TTLs are capped at 10 s and
    /// whose records are therefore wrong to cache as though they were announcements —
    /// or it is unsolicited traffic from something that is not a responder at all.
    /// Honoring either one puts entries in the cache that no goodbye packet will ever
    /// clear.
    /// </remarks>
    internal bool ShouldIgnoreResponseFrom(int sourcePort)
        => !acceptResponsesFromAnyPort && sourcePort != MdnsPort;

    private void OnPacketReceived(byte[] data, IPEndPoint remote)
    {
        if (!DnsParser.TryParse(data, out var msg) || msg == null || !msg.IsResponse)
            return;

        if (ShouldIgnoreResponseFrom(remote.Port))
            return;

        var allRecords = msg.Answers.Concat(msg.Authorities).Concat(msg.Additionals).ToList();

        bool changed = false;

        // A multi-homed responder sends one A record per address in a single message.
        // Tracks which hostnames have already had their address set replaced by this
        // message, so the first record clears the previous set and the rest append to
        // it rather than each one overwriting the last.
        var addressTakenFor = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        lock (mutex)
        {
            foreach (var record in allRecords)
            {
                switch (record.Type)
                {
                    case DnsRecordType.PTR when
                        string.Equals(record.Name, serviceType, StringComparison.OrdinalIgnoreCase):
                    {
                        var instanceName = DnsParser.ParsePtr(record.Data, data);
                        // Strip the service type suffix to get just the instance name
                        var shortName = StripServiceType(instanceName);
                        if (shortName == null) break;

                        var svc = GetOrCreate(shortName);
                        svc.PtrTtl = record.Ttl;
                        svc.PtrExpiry = DateTime.UtcNow.AddSeconds(record.Ttl);
                        changed = true;
                        break;
                    }

                    case DnsRecordType.SRV:
                    {
                        var shortName = StripServiceType(record.Name);
                        if (shortName == null) break;

                        var (_, _, port, target) = DnsParser.ParseSrv(record.Data, data);
                        var svc = GetOrCreate(shortName);
                        svc.Port     = port;
                        svc.Hostname = target;
                        changed = true;
                        break;
                    }

                    case DnsRecordType.TXT:
                    {
                        var shortName = StripServiceType(record.Name);
                        if (shortName == null) break;

                        var svc = GetOrCreate(shortName);
                        svc.Properties = DnsParser.ParseTxt(record.Data);
                        changed = true;
                        break;
                    }

                    case DnsRecordType.A:
                    {
                        // Match by hostname against known services
                        var ip = DnsParser.ParseA(record.Data);
                        if (ip == null) break;

                        foreach (var svc in services.Values)
                        {
                            if (string.Equals(svc.Hostname, record.Name, StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(svc.Hostname, record.Name + ".", StringComparison.OrdinalIgnoreCase))
                            {
                                // The first A record for this name in this message starts
                                // a fresh set: a responder announces its current addresses
                                // together, so anything we held before is stale. Later
                                // records in the same message add to it, preserving the
                                // announced order.
                                if (addressTakenFor.Add(record.Name))
                                    svc.Addresses.Clear();

                                if (!svc.Addresses.Contains(ip))
                                {
                                    svc.Addresses.Add(ip);
                                    changed = true;
                                }
                            }
                        }

                        // Also try matching by remote endpoint as fallback
                        foreach (var svc in services.Values.Where(s => s.Address == null))
                        {
                            svc.Addresses.Add(remote.Address);
                            changed = true;
                        }
                        break;
                    }
                }
            }

            if (changed)
            {
                foreach (var svc in services.Values.Where(s => s.IsComplete && !s.Announced))
                {
                    svc.Announced = true;
                    ServiceFound?.Invoke(svc.ToProfile());
                }
            }
        }

        // Outside the lock: fire off follow-up queries for any services
        // still missing port/address. Safe to call repeatedly; questions
        // for already-resolved data simply won't be emitted.
        if (changed)
            SendFollowUpQueries();
    }

    // -------------------------------------------------------------------------
    // Query
    // -------------------------------------------------------------------------

    private void SendQuery()
    {
        var msg = new DnsMessage { IsResponse = false };
        msg.Questions.Add(new DnsQuestion(serviceType, DnsRecordType.PTR, DnsClass.IN));
        transport.Send(DnsEncoder.Encode(msg));
    }

    /// <summary>
    /// Send targeted SRV/A queries for any known-but-incomplete services.
    /// Some responders (notably lwIP's built-in mDNS responder on embedded
    /// devices) only return the PTR record in response to the initial PTR
    /// query and expect the client to follow up with SRV / A queries. macOS
    /// mDNSResponder bundles everything into one packet so the slower path
    /// was easy to miss. This method closes the gap.
    /// </summary>
    private void SendFollowUpQueries()
    {
        List<DnsQuestion>? questions = null;

        lock (mutex)
        {
            foreach (var svc in services.Values)
            {
                // Need SRV if we have the instance but no port yet.
                if (svc.Port == 0)
                {
                    questions ??= [];
                    questions.Add(new DnsQuestion(
                        svc.InstanceName + "." + serviceType,
                        DnsRecordType.SRV, DnsClass.IN));
                }

                // Need A if SRV gave us a hostname but no address yet.
                if (svc.Address == null && !string.IsNullOrEmpty(svc.Hostname))
                {
                    questions ??= [];
                    questions.Add(new DnsQuestion(svc.Hostname!,
                        DnsRecordType.A, DnsClass.IN));
                }
            }
        }

        if (questions == null) return;

        var msg = new DnsMessage { IsResponse = false };
        foreach (var q in questions) msg.Questions.Add(q);
        transport.Send(DnsEncoder.Encode(msg));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private DiscoveredService GetOrCreate(string instanceName)
    {
        if (!services.TryGetValue(instanceName, out var svc))
            services[instanceName] = svc = new DiscoveredService(instanceName, serviceType);
        return svc;
    }

    private string? StripServiceType(string fullName)
    {
        // "MyDevice._apple-midi._udp.local." → "MyDevice"
        var suffix = "." + serviceType;
        if (fullName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            return fullName[..^suffix.Length];
        // Already just the instance name (no suffix)
        if (!fullName.Contains('.'))
            return fullName;
        return null;
    }

    // -------------------------------------------------------------------------
    // IDisposable / IAsyncDisposable
    // -------------------------------------------------------------------------

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
            return;

        expiryTimer.Dispose();
        transport.PacketReceived -= OnPacketReceived;
        transport.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    private sealed class DiscoveredService(string instanceName, string serviceType)
    {
        public string InstanceName { get; } = instanceName;
        public string ServiceType  { get; } = serviceType;
        public ushort Port     { get; set; }
        public string? Hostname { get; set; }
        public List<IPAddress> Addresses { get; } = [];
        public IPAddress? Address => Addresses.Count > 0 ? Addresses[0] : null;
        public Dictionary<string, string> Properties { get; set; } = [];
        public uint PtrTtl    { get; set; }
        public DateTime PtrExpiry { get; set; }
        public bool Announced { get; set; }

        public bool IsComplete => Port > 0 && Address != null;

        public bool IsExpired() => PtrTtl > 0 && DateTime.UtcNow > PtrExpiry;

        public ServiceProfile ToProfile() => new(
            InstanceName,
            ServiceType,
            Port,
            Properties)
        {
            Address = Address,
            Addresses = Addresses.ToArray(),
        };
    }
}
