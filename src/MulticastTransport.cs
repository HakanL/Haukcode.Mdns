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
    private UdpClient[]? clients;
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

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!nic.SupportsMulticast) continue;
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    var ip = ua.Address;
                    if (ip.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(ip)) continue;

                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                        wifi.Add(ip);
                    else
                        ethernet.Add(ip);
                }
            }

            return PickSticky(ethernet, ref stickyEthernet)
                ?? PickSticky(wifi, ref stickyWifi);
        }
    }

    private static IPAddress? PickSticky(List<IPAddress> list, ref IPAddress? sticky)
    {
        if (list.Count == 0) return null;
        var current = sticky;
        if (current != null && list.Any(ip => ip.Equals(current))) return current;
        sticky = list[0];
        return sticky;
    }

    // -------------------------------------------------------------------------
    // Socket setup
    // -------------------------------------------------------------------------

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
        }
    }
}
