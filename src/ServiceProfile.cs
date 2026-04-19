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
    /// Per RFC 6763 §4.3, the label must consist only of letters, digits, and hyphens.
    /// All other characters are replaced with hyphens, and leading/trailing hyphens are removed.
    /// </summary>
    public string Hostname => $"{SanitizeHostLabel(InstanceName)}.local.";

    public ServiceProfile(string instanceName, string serviceType, ushort port,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        InstanceName = instanceName;
        ServiceType  = serviceType;
        Port         = port;
        Properties   = properties ?? new Dictionary<string, string>();
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
}
