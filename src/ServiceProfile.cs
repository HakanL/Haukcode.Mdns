namespace Haukcode.Mdns;

/// <summary>
/// Describes a DNS-SD service to advertise or that was discovered via browsing.
/// </summary>
public sealed class ServiceProfile
{
    /// <summary>
    /// Instance name — the human-readable part, e.g. "DMX Core 100".
    /// Must be unique on the local network; conflict resolution is not implemented.
    /// </summary>
    public string InstanceName { get; }

    /// <summary>
    /// Service type including protocol, e.g. "_apple-midi._udp" or "_osc._udp".
    /// Do not include ".local." — that is appended automatically.
    /// </summary>
    public string ServiceType { get; }

    /// <summary>UDP port the service listens on.</summary>
    public ushort Port { get; }

    /// <summary>Optional TXT record key/value pairs.</summary>
    public IReadOnlyDictionary<string, string> Properties { get; }

    /// <summary>
    /// Resolved IPv4 address. Populated when a service is discovered via browsing;
    /// null when used to describe a local service to advertise.
    /// </summary>
    public IPAddress? Address { get; internal set; }

    /// <summary>
    /// Fully-qualified service type: "_apple-midi._udp.local."
    /// </summary>
    public string FullServiceType => $"{ServiceType}.local.";

    /// <summary>
    /// Fully-qualified instance name: "DMX Core 100._apple-midi._udp.local."
    /// </summary>
    public string FullInstanceName => $"{InstanceName}.{FullServiceType}";

    /// <summary>
    /// Hostname used in SRV records: "DMX-Core-100.local."
    /// Spaces replaced with hyphens per RFC 6763.
    /// </summary>
    public string Hostname => $"{InstanceName.Replace(' ', '-')}.local.";

    public ServiceProfile(string instanceName, string serviceType, ushort port,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        InstanceName = instanceName;
        ServiceType  = serviceType;
        Port         = port;
        Properties   = properties ?? new Dictionary<string, string>();
    }
}
