namespace Haukcode.Mdns;

/// <summary>
/// Manages multicast UDP sockets for mDNS traffic on 224.0.0.251:5353.
/// Binds to all suitable network interfaces and handles receive/send.
/// Matches the multi-adapter approach from the vendored ZeroConfigWatcher.
/// </summary>
internal sealed class MulticastTransport : IDisposable
{
    private static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
    private const int MdnsPort = 5353;

    private readonly object mutex = new();
    private UdpClient[]? clients;       // bound to 5353, one per interface: receive AND send
    private bool disposed;

    public event Action<byte[], IPEndPoint>? PacketReceived;

    // -------------------------------------------------------------------------
    // Start / Stop
    // -------------------------------------------------------------------------

    public void Start()
    {
        lock (mutex)
        {
            if (clients != null) return;
            clients = BuildClients();
            foreach (var client in clients)
                BeginReceive(client);
        }
    }

    public int AdapterCount
    {
        get { lock (mutex) return clients?.Length ?? 0; }
    }

    // -------------------------------------------------------------------------
    // Send
    // -------------------------------------------------------------------------

    /// <summary>
    /// Send a datagram to 224.0.0.251:5353 out of every joined interface.
    /// </summary>
    /// <remarks>
    /// The source port is 5353, because these are the sockets bound to 5353. That is
    /// not incidental — it is what makes the traffic mDNS at all:
    ///
    ///   RFC 6762 §6:   "The source UDP port in all Multicast DNS responses MUST be
    ///                   5353" and "Multicast DNS implementations MUST silently ignore
    ///                   any Multicast DNS responses they receive where the source UDP
    ///                   port is not 5353."
    ///   RFC 6762 §5.2: "A compliant Multicast DNS querier ... MUST send its Multicast
    ///                   DNS queries from UDP source port 5353."
    ///
    /// This previously sent from a separate set of ephemeral-port sockets, on the
    /// reasoning that a port only we hold cannot have its unicast replies absorbed by
    /// a Bonjour/avahi responder already bound to 5353. The cost of that was total:
    /// every announcement we sent carried a random source port, so a conforming
    /// receiver — avahi and mDNSResponder both do this — dropped it on the floor. Our
    /// own browser did not check the port, which is exactly why Core-to-Core discovery
    /// kept working and hid the fault.
    ///
    /// Queries here are QM (no unicast-response bit), so answers come back multicast
    /// and land on these same group-joined sockets; the absorption worry applied to
    /// unicast replies, which we do not ask for.
    /// </remarks>
    public void Send(byte[] datagram)
    {
        var ep = new IPEndPoint(MulticastGroup, MdnsPort);
        lock (mutex)
        {
            if (clients == null) return;
            foreach (var client in clients)
            {
                try { client.Send(datagram, datagram.Length, ep); }
                catch (SocketException) { /* interface may have gone away */ }
            }
        }
    }

    /// <summary>
    /// Send a datagram to one address — the unicast reply path for legacy queriers
    /// (RFC 6762 §6.7). Source port is 5353, same as every other packet we send.
    /// </summary>
    /// <remarks>
    /// Any of the sockets will do: they are bound to 0.0.0.0:5353, so the kernel picks
    /// the outbound interface and source address from the routing table for this
    /// destination. MulticastInterface, which is what differentiates them, applies only
    /// to multicast. Sending from just one is the point — sending from all of them
    /// would put N copies of the same reply on the wire.
    /// </remarks>
    public void SendTo(byte[] datagram, IPEndPoint destination)
    {
        lock (mutex)
        {
            if (clients == null) return;
            foreach (var client in clients)
            {
                try
                {
                    client.Send(datagram, datagram.Length, destination);
                    return;
                }
                catch (SocketException) { /* try the next socket */ }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Network interface selection — prefer wired, sticky per type
    // -------------------------------------------------------------------------

    private static IPAddress? stickyEthernet;
    private static IPAddress? stickyWifi;
    private static readonly object ipLock = new();

    public static IPAddress? GetLocalAddress()
    {
        lock (ipLock)
        {
            var ethernet = new List<IPAddress>();
            var wifi     = new List<IPAddress>();
            var virtualAddresses = new HashSet<IPAddress>();

            CollectAddresses(ethernet, wifi, virtualAddresses);

            return PickSticky(ethernet, virtualAddresses, ref stickyEthernet)
                ?? PickSticky(wifi, virtualAddresses, ref stickyWifi);
        }
    }

    private static void CollectAddresses(List<IPAddress> ethernet, List<IPAddress> wifi, HashSet<IPAddress>? virtualAddresses = null)
    {
        // Physical adapters are collected ahead of virtual ones so that the address a
        // caller reaches for first is the one most likely to be reachable from another
        // machine. A Hyper-V/WSL/Docker switch address is perfectly valid locally and
        // completely useless to anyone else, and on a developer machine those often
        // enumerate first.
        var physicalEthernet = new List<IPAddress>();
        var virtualEthernet  = new List<IPAddress>();
        var physicalWifi     = new List<IPAddress>();
        var virtualWifi      = new List<IPAddress>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.SupportsMulticast) continue;
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (IsPointToPoint(nic)) continue;

            bool isVirtual = IsLikelyVirtual(nic);
            bool isWifi = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                var ip = ua.Address;
                if (ip.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IPAddress.IsLoopback(ip)) continue;

                if (isVirtual)
                    virtualAddresses?.Add(ip);

                (isWifi
                    ? (isVirtual ? virtualWifi : physicalWifi)
                    : (isVirtual ? virtualEthernet : physicalEthernet)).Add(ip);
            }
        }

        ethernet.AddRange(physicalEthernet);
        ethernet.AddRange(virtualEthernet);
        wifi.AddRange(physicalWifi);
        wifi.AddRange(virtualWifi);
    }

    /// <summary>
    /// A point-to-point link (VPN tunnel, PPP) — excluded outright, unlike the
    /// virtual adapters below which are merely sorted last.
    /// </summary>
    /// <remarks>
    /// This is a categorical exclusion rather than a guess. mDNS is link-local: a
    /// responder answers on links it shares with the querier, and a point-to-point
    /// tunnel has exactly one peer and no multicast neighbours to answer. Advertising
    /// such an address (e.g. a 100.64.0.0/10 CGNAT address on a VPN tun device) hands
    /// every listener on the real network an address none of them can use. A Hyper-V
    /// or Docker bridge is a different case — a real broadcast link with real peers —
    /// so those are only deprioritised.
    /// </remarks>
    internal static bool IsPointToPoint(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
            return true;

        // On Linux the link-layer type is authoritative and cheap: ARPHRD_ETHER (1)
        // covers ethernet and Wi-Fi, while a tun device reports ARPHRD_NONE (65534).
        if (OperatingSystem.IsLinux())
        {
            try
            {
                string path = $"/sys/class/net/{nic.Name}/type";

                if (File.Exists(path) && int.TryParse(File.ReadAllText(path).Trim(), out int arpHrdType))
                    return arpHrdType != 1;
            }
            catch
            {
                // Fall through — treat as a normal link
            }
        }

        return false;
    }

    /// <summary>
    /// Best-effort "this adapter is a virtual switch, not a way off this machine".
    /// Only ever used to sort addresses, never to drop one — a wrong guess costs
    /// ordering, not reachability.
    /// </summary>
    internal static bool IsLikelyVirtual(NetworkInterface nic)
    {
        // Linux puts virtual devices (bridges, veth, tun, docker) under
        // /sys/devices/virtual/net; a real NIC resolves to a pci/platform/usb path.
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var target = Directory.ResolveLinkTarget($"/sys/class/net/{nic.Name}", returnFinalTarget: true);

                if (target != null)
                    return target.FullName.Contains("/devices/virtual/", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                // Fall through to the vendor checks below
            }
        }

        // Well-known virtual-NIC MAC prefixes.
        var mac = nic.GetPhysicalAddress().GetAddressBytes();
        if (mac.Length == 6)
        {
            // Hyper-V, VMware (three ranges), VirtualBox, Docker/veth
            if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) return true;
            if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) return true;
            if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return true;
            if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) return true;
            if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) return true;
            if (mac[0] == 0x02 && mac[1] == 0x42) return true;
        }

        // Last resort: what the OS calls it. Windows names its switches plainly.
        var text = $"{nic.Name} {nic.Description}";

        return text.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
            || text.Contains("VMware", StringComparison.OrdinalIgnoreCase)
            || text.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
            || text.Contains("WSL", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Default Switch", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Every local IPv4 address worth advertising, wired first then wireless.
    /// </summary>
    /// <remarks>
    /// A multi-homed host reachable on several networks should say so: advertising a
    /// single address means clients on the other networks are handed one they may not
    /// be able to reach, and there is nothing in the response for them to fall back to.
    /// Publishing an A record per address is what avahi and Bonjour do, and the client
    /// picks whichever answers. Ordering still puts wired first, so a client that
    /// simply takes the first one keeps the old behaviour.
    /// </remarks>
    public static IReadOnlyList<IPAddress> GetLocalAddresses()
    {
        lock (ipLock)
        {
            var ethernet = new List<IPAddress>();
            var wifi     = new List<IPAddress>();
            var virtualAddresses = new HashSet<IPAddress>();

            CollectAddresses(ethernet, wifi, virtualAddresses);

            // Keep the sticky choice at the head of the list so the address a client
            // sees first stays put across calls, rather than reordering underneath it.
            var preferred = PickSticky(ethernet, virtualAddresses, ref stickyEthernet)
                ?? PickSticky(wifi, virtualAddresses, ref stickyWifi);

            var result = new List<IPAddress>();

            if (preferred != null)
                result.Add(preferred);

            foreach (var ip in ethernet.Concat(wifi))
            {
                if (!result.Contains(ip))
                    result.Add(ip);
            }

            return result;
        }
    }

    private static IPAddress? PickSticky(List<IPAddress> list, HashSet<IPAddress> virtualAddresses, ref IPAddress? sticky)
    {
        if (list.Count == 0) return null;

        var current = sticky;

        if (current != null && list.Any(ip => ip.Equals(current)))
        {
            // Keep the previous choice, unless it is a virtual adapter and a physical
            // one is now available — otherwise a machine that came up with only its
            // Hyper-V switch ready would stay pinned to it for the life of the process.
            bool stuckOnVirtual = virtualAddresses.Contains(current) && !virtualAddresses.Contains(list[0]);

            if (!stuckOnVirtual)
                return current;
        }

        sticky = list[0];

        return sticky;
    }

    // -------------------------------------------------------------------------
    // Socket setup
    // -------------------------------------------------------------------------

    /// <summary>
    /// Build one UDP socket per interface, bound to 5353 and joined to the mDNS
    /// group. Every packet we receive arrives on these, and every packet we send
    /// leaves from these — so the source port is always 5353, as RFC 6762 requires
    /// of both responses (§6) and compliant queries (§5.2).
    /// </summary>
    private static UdpClient[] BuildClients()
    {
        var result = new List<UdpClient>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.SupportsMulticast) continue;
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var ipProps = nic.GetIPProperties();
            IPv4InterfaceProperties? ipv4Props;
            try
            {
                ipv4Props = ipProps.GetIPv4Properties();
            }
            catch (NetworkInformationException)
            {
                // Some adapters (e.g. Hyper-V, tunnel, or partially-disabled)
                // throw instead of returning null when IPv4 is not configured.
                continue;
            }
            if (ipv4Props == null) continue;

            if (!ipProps.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
                continue;

            try
            {
                var client = new UdpClient();
                var socket = client.Client;

                socket.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.MulticastInterface,
                    IPAddress.HostToNetworkOrder(ipv4Props.Index));

                client.ExclusiveAddressUse = false;
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                    new MulticastOption(MulticastGroup, ipv4Props.Index));

                // RFC 6762 §11: multicast DNS packets are sent with IP TTL 255, which
                // lets a receiver tell a genuine link-local packet from a routed one.
                // This used to be set on the send-only sockets; it belongs here now
                // that these sockets do the sending.
                socket.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.MulticastTimeToLive, 255);

                result.Add(client);
            }
            catch (SocketException)
            {
                // Skip interfaces that can't bind
            }
        }

        if (result.Count == 0)
            throw new InvalidOperationException("No multicast-capable network interfaces found.");

        return result.ToArray();
    }

    // -------------------------------------------------------------------------
    // Receive loop
    // -------------------------------------------------------------------------

    private void BeginReceive(UdpClient client)
    {
        _ = ReceiveLoopAsync(client);
    }

    /// <summary>
    /// Persistent receive loop for one socket. Replaces the earlier
    /// BeginReceive/EndReceive chain, which a single unexpected exception could
    /// sever silently: an escape from the callback became an unobserved task
    /// exception, the socket was never re-armed, and from then on queries piled
    /// up unread in a full kernel buffer while the process looked healthy.
    /// Observed in production as "device advertises at startup, goes deaf
    /// minutes later" — /proc/net/udp showed the 5353 receive queues full with
    /// thousands of drops. A loop has no re-arm step to miss: every failure
    /// path either exits because we are disposed or iterates and receives
    /// again.
    /// </summary>
    private async Task ReceiveLoopAsync(UdpClient client)
    {
        while (true)
        {
            byte[] data;
            IPEndPoint remote;

            try
            {
                var result = await client.ReceiveAsync().ConfigureAwait(false);
                data = result.Buffer;
                remote = result.RemoteEndPoint;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception)
            {
                lock (mutex)
                {
                    if (disposed) return;
                }

                // Transient by assumption (an ICMP error surfaced on the socket,
                // an interface blip, ...). The brief pause keeps a persistent
                // error from becoming a hot spin; the loop stays alive either
                // way, because a dead receive loop is strictly worse than a
                // noisy one.
                await Task.Delay(250).ConfigureAwait(false);
                continue;
            }

            lock (mutex)
            {
                if (disposed) return;
            }

            try
            {
                PacketReceived?.Invoke(data, remote);
            }
            catch
            {
                // A subscriber bug must not take the receive loop down with it.
            }
        }
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

            if (clients != null)
            {
                foreach (var c in clients) c.Dispose();
                clients = null;
            }
        }
    }
}
