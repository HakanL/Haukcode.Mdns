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
    /// Resolved IPv4 address — the first of <see cref="Addresses"/>. Populated when a
    /// service is discovered via browsing; null when used to describe a local service
    /// to advertise.
    /// </summary>
    /// <remarks>
    /// A multi-homed responder publishes several addresses and only the caller knows
    /// which of them it can actually reach — prefer <see cref="Addresses"/> and pick
    /// one on your own subnet. This property is the first advertised address, which is
    /// not necessarily a reachable one.
    /// </remarks>
    public IPAddress? Address { get; internal set; }

    /// <summary>
    /// Every IPv4 address the service advertised, in the order it announced them.
    /// Empty for a profile describing a local service to advertise.
    /// </summary>
    public IReadOnlyList<IPAddress> Addresses { get; internal set; } = [];

    /// <summary>
    /// The host name given to the constructor, before sanitising and without any
    /// ".local" suffix; null when the host name is derived from the instance name.
    /// </summary>
    private readonly string? hostname;

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
    /// Derived from <see cref="InstanceName"/>, unless a host name was given to the
    /// constructor — then that one, so the SRV target can be the machine's real
    /// name, the one the OS resolver (Bonjour, avahi) answers for as well.
    /// Per RFC 6763 §4.3, the label must consist only of letters, digits, and hyphens.
    /// All other characters are replaced with hyphens, and leading/trailing hyphens are removed.
    /// </summary>
    public string Hostname => $"{SanitizeHostLabel(hostname ?? InstanceName)}.local.";

    /// <param name="instanceName">Human-readable instance name, e.g. "DMX Core 100".</param>
    /// <param name="serviceType">Service type including protocol, e.g. "_http._tcp".</param>
    /// <param name="port">Port the service listens on.</param>
    /// <param name="properties">Optional TXT record key/value pairs.</param>
    /// <param name="hostname">
    /// Host name to advertise the A records under and point the SRV record at, as a
    /// single label ("dmxcore-1234") or with the ".local" suffix ("dmxcore-1234.local",
    /// as <c>Dns.GetHostName()</c> may return it); the suffix is dropped and the label
    /// sanitised the same way as the instance name. Null derives the host name from
    /// <paramref name="instanceName"/>.
    /// </param>
    public ServiceProfile(string instanceName, string serviceType, ushort port,
        IReadOnlyDictionary<string, string>? properties = null, string? hostname = null)
    {
        InstanceName  = instanceName;
        ServiceType   = serviceType;
        Port          = port;
        Properties    = properties ?? new Dictionary<string, string>();
        this.hostname = hostname == null ? null : TrimLocalSuffix(hostname);
    }

    /// <summary>
    /// Converts an arbitrary instance name into a valid DNS label (RFC 1123):
    /// only [A-Za-z0-9-], runs of invalid characters collapsed into a single hyphen,
    /// leading/trailing hyphens stripped.
    /// </summary>
    public static string SanitizeHostLabel(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length);
        bool lastWasHyphen = false;

        foreach (char c in name)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(c);
                lastWasHyphen = false;
            }
            else if (!lastWasHyphen && sb.Length > 0)
            {
                // Replace any run of non-alphanumeric chars with a single hyphen.
                // The sb.Length > 0 guard ensures the label never starts with a hyphen.
                sb.Append('-');
                lastWasHyphen = true;
            }
        }

        // Trim trailing hyphen that may have been appended for a non-alphanumeric tail
        if (sb.Length > 0 && sb[^1] == '-')
            sb.Length--;

        return sb.Length > 0 ? sb.ToString() : "device";
    }

    /// <summary>
    /// "dmxcore-1234.local." and "dmxcore-1234.local" → "dmxcore-1234". Without this
    /// the dot would be sanitised into a hyphen and the name advertised would be
    /// "dmxcore-1234-local.local.".
    /// </summary>
    private static string TrimLocalSuffix(string hostname)
    {
        var trimmed = hostname.TrimEnd('.');

        if (trimmed.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[..^".local".Length];

        return trimmed;
    }
}
