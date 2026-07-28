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
    private UdpClient[]? clients;       // bound to 5353, receive multicast announcements
    private UdpClient[]? senders;       // bound to ephemeral, send queries and receive unicast replies
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
            senders = BuildSenderClients();
            foreach (var client in clients)
                BeginReceive(client);
            foreach (var sender in senders)
                BeginReceive(sender);
        }
    }

    public int AdapterCount
    {
        get { lock (mutex) return clients?.Length ?? 0; }
    }

    // -------------------------------------------------------------------------
    // Send
    // -------------------------------------------------------------------------

    public void Send(byte[] datagram)
    {
        var ep = new IPEndPoint(MulticastGroup, MdnsPort);
        lock (mutex)
        {
            // Send from ephemeral-port sockets so unicast replies come back
            // to a port only we hold (not Windows Bonjour / avahi / etc.
            // which already bind 5353 exclusively for unicast).
            if (senders == null) return;
            foreach (var sender in senders)
            {
                try { sender.Send(datagram, datagram.Length, ep); }
                catch (SocketException) { /* interface may have gone away */ }
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
    /// Build one UDP socket per interface, bound to an ephemeral port. These
    /// sockets are used to SEND queries. Because they bind to a random port,
    /// unicast replies (to the querier's source address/port) come back to
    /// us rather than being absorbed by Bonjour / avahi / Windows mDNS also
    /// bound to 5353.
    /// </summary>
    private static UdpClient[] BuildSenderClients()
    {
        var result = new List<UdpClient>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.SupportsMulticast) continue;
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var ipProps = nic.GetIPProperties();
            IPv4InterfaceProperties? ipv4Props;
            try { ipv4Props = ipProps.GetIPv4Properties(); }
            catch (NetworkInformationException) { continue; }
            if (ipv4Props == null) continue;

            if (!ipProps.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
                continue;

            try
            {
                // Ephemeral port on this interface. MulticastInterface ensures
                // outbound multicast packets go out this specific adapter.
                var client = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                client.Client.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.MulticastInterface,
                    IPAddress.HostToNetworkOrder(ipv4Props.Index));
                client.Client.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.MulticastTimeToLive, 255);
                result.Add(client);
            }
            catch (SocketException) { /* skip interface */ }
        }

        return result.ToArray();
    }

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
        client.BeginReceive(ReceiveCallback, client);
    }

    private void ReceiveCallback(IAsyncResult result)
    {
        var client = (UdpClient)result.AsyncState!;

        byte[]? data = null;
        IPEndPoint? remote = null;

        lock (mutex)
        {
            if (disposed) return;

            try
            {
                IPEndPoint? ep = new(IPAddress.Any, 0);
                data = client.EndReceive(result, ref ep);
                remote = ep;
            }
            catch (SocketException) { /* socket closed */ }
            catch (ObjectDisposedException) { return; }

            // Re-arm before invoking the event so we never miss a packet
            try { client.BeginReceive(ReceiveCallback, client); }
            catch (ObjectDisposedException) { }
        }

        // Invoke outside the lock to prevent lock-order deadlocks with subscribers
        if (data != null && remote != null)
            PacketReceived?.Invoke(data, remote);
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
            if (senders != null)
            {
                foreach (var s in senders) s.Dispose();
                senders = null;
            }
        }
    }
}
