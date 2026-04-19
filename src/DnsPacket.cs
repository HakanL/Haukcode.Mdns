using System.Text;

namespace Haukcode.Mdns;

/// <summary>
/// Minimal DNS record types needed for mDNS service advertising and browsing.
/// Covers RFC 6762 (mDNS) + RFC 6763 (DNS-SD): PTR, SRV, TXT, A records.
/// </summary>

// -------------------------------------------------------------------------
// Record types
// -------------------------------------------------------------------------

public enum DnsRecordType : ushort
{
    A    = 1,
    PTR  = 12,
    TXT  = 16,
    SRV  = 33,
    NSEC = 47,
}

public enum DnsClass : ushort
{
    IN         = 1,
    IN_Unicast = 0x8001,  // cache-flush bit set (authoritative answers)
}

public sealed record DnsRecord(
    string Name,
    DnsRecordType Type,
    DnsClass Class,
    uint Ttl,
    byte[] Data);

public sealed class DnsMessage
{
    public ushort Id { get; init; }
    public bool IsResponse { get; init; }
    public bool IsAuthoritative { get; init; }

    public List<DnsQuestion> Questions   { get; } = [];
    public List<DnsRecord>   Answers     { get; } = [];
    public List<DnsRecord>   Authorities { get; } = [];
    public List<DnsRecord>   Additionals { get; } = [];
}

public sealed record DnsQuestion(string Name, DnsRecordType Type, DnsClass Class);

// -------------------------------------------------------------------------
// Encoder
// -------------------------------------------------------------------------

public static class DnsEncoder
{
    public static byte[] Encode(DnsMessage msg)
    {
        var w = new DnsWriter();

        // Header
        w.WriteUInt16(msg.Id);
        ushort flags = 0;
        if (msg.IsResponse)      flags |= 0x8000;
        if (msg.IsAuthoritative) flags |= 0x0400;
        w.WriteUInt16(flags);
        w.WriteUInt16((ushort)msg.Questions.Count);
        w.WriteUInt16((ushort)msg.Answers.Count);
        w.WriteUInt16((ushort)msg.Authorities.Count);
        w.WriteUInt16((ushort)msg.Additionals.Count);

        foreach (var q in msg.Questions)
        {
            w.WriteName(q.Name);
            w.WriteUInt16((ushort)q.Type);
            w.WriteUInt16((ushort)q.Class);
        }

        foreach (var section in new[] { msg.Answers, msg.Authorities, msg.Additionals })
            foreach (var r in section)
            {
                w.WriteName(r.Name);
                w.WriteUInt16((ushort)r.Type);
                w.WriteUInt16((ushort)r.Class);
                w.WriteUInt32(r.Ttl);
                w.WriteUInt16((ushort)r.Data.Length);
                w.WriteBytes(r.Data);
            }

        return w.ToArray();
    }

    // -------------------------------------------------------------------------
    // Record data builders
    // -------------------------------------------------------------------------

    public static byte[] BuildPtr(string targetName)
    {
        var w = new DnsWriter();
        w.WriteName(targetName);
        return w.ToArray();
    }

    public static byte[] BuildSrv(ushort priority, ushort weight, ushort port, string target)
    {
        var w = new DnsWriter();
        w.WriteUInt16(priority);
        w.WriteUInt16(weight);
        w.WriteUInt16(port);
        w.WriteName(target);
        return w.ToArray();
    }

    public static byte[] BuildTxt(IReadOnlyDictionary<string, string> properties)
    {
        var w = new DnsWriter();
        if (properties.Count == 0)
        {
            w.WriteByte(0); // empty TXT record requires a single 0-length string
        }
        else
        {
            foreach (var kv in properties)
            {
                if (string.IsNullOrEmpty(kv.Key))
                    throw new ArgumentException("TXT record key must not be empty.", nameof(properties));
                if (kv.Key.Contains('='))
                    throw new ArgumentException($"TXT record key '{kv.Key}' must not contain '=' (RFC 6763 §6.4).", nameof(properties));

                var entry = Encoding.UTF8.GetBytes($"{kv.Key}={kv.Value}");
                if (entry.Length > 255)
                    throw new ArgumentException($"TXT record entry for key '{kv.Key}' exceeds 255 bytes.", nameof(properties));

                w.WriteByte((byte)entry.Length);
                w.WriteBytes(entry);
            }
        }
        return w.ToArray();
    }

    public static byte[] BuildA(IPAddress address)
        => address.GetAddressBytes(); // already 4 bytes for IPv4
}

// -------------------------------------------------------------------------
// Parser
// -------------------------------------------------------------------------

public static class DnsParser
{
    public static bool TryParse(byte[] data, out DnsMessage? message)
    {
        message = null;
        try
        {
            var r = new DnsReader(data);

            var id    = r.ReadUInt16();
            var flags = r.ReadUInt16();
            var qdCount = r.ReadUInt16();
            var anCount = r.ReadUInt16();
            var nsCount = r.ReadUInt16();
            var arCount = r.ReadUInt16();

            bool isResponse      = (flags & 0x8000) != 0;
            bool isAuthoritative = (flags & 0x0400) != 0;

            var msg = new DnsMessage
            {
                Id = id,
                IsResponse = isResponse,
                IsAuthoritative = isAuthoritative,
            };

            for (int i = 0; i < qdCount; i++)
            {
                var name  = r.ReadName();
                var type  = (DnsRecordType)r.ReadUInt16();
                var cls   = (DnsClass)r.ReadUInt16();
                msg.Questions.Add(new DnsQuestion(name, type, cls));
            }

            ReadRecords(r, anCount, msg.Answers);
            ReadRecords(r, nsCount, msg.Authorities);
            ReadRecords(r, arCount, msg.Additionals);

            message = msg;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ReadRecords(DnsReader r, int count, List<DnsRecord> list)
    {
        for (int i = 0; i < count; i++)
        {
            var name  = r.ReadName();
            var type  = (DnsRecordType)r.ReadUInt16();
            var cls   = (DnsClass)r.ReadUInt16();
            var ttl   = r.ReadUInt32();
            var rdLen = r.ReadUInt16();
            var data  = r.ReadBytes(rdLen);
            list.Add(new DnsRecord(name, type, cls, ttl, data));
        }
    }

    // -------------------------------------------------------------------------
    // Record data parsers
    // -------------------------------------------------------------------------

    public static string ParsePtr(byte[] data, byte[] fullPacket)
    {
        var r = new DnsReader(data, fullPacket);
        return r.ReadName();
    }

    public static (ushort priority, ushort weight, ushort port, string target) ParseSrv(byte[] data, byte[] fullPacket)
    {
        var r = new DnsReader(data, fullPacket);
        var priority = r.ReadUInt16();
        var weight   = r.ReadUInt16();
        var port     = r.ReadUInt16();
        var target   = r.ReadName();
        return (priority, weight, port, target);
    }

    public static Dictionary<string, string> ParseTxt(byte[] data)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int pos = 0;
        while (pos < data.Length)
        {
            int len = data[pos++];
            if (len == 0 || pos + len > data.Length) break;
            var entry = Encoding.UTF8.GetString(data, pos, len);
            pos += len;
            int eq = entry.IndexOf('=');
            if (eq >= 0)
                result[entry[..eq]] = entry[(eq + 1)..];
            else
                result[entry] = string.Empty;
        }
        return result;
    }

    public static IPAddress? ParseA(byte[] data)
        => data.Length == 4 ? new IPAddress(data) : null;
}

// -------------------------------------------------------------------------
// DNS wire-format writer
// -------------------------------------------------------------------------

internal sealed class DnsWriter
{
    private readonly List<byte> buf = [];

    public void WriteByte(byte b) => buf.Add(b);

    public void WriteUInt16(ushort v)
    {
        buf.Add((byte)(v >> 8));
        buf.Add((byte)(v & 0xFF));
    }

    public void WriteUInt32(uint v)
    {
        buf.Add((byte)(v >> 24));
        buf.Add((byte)(v >> 16));
        buf.Add((byte)(v >> 8));
        buf.Add((byte)(v & 0xFF));
    }

    public void WriteBytes(byte[] bytes) => buf.AddRange(bytes);

    /// <summary>
    /// Writes a DNS name as a sequence of labels (no compression — safe for mDNS).
    /// e.g. "MyService._apple-midi._udp.local." → 3-label sequence + root 0x00
    /// </summary>
    public void WriteName(string name)
    {
        if (string.IsNullOrEmpty(name) || name == ".")
        {
            buf.Add(0);
            return;
        }

        var labels = name.TrimEnd('.').Split('.');
        foreach (var label in labels)
        {
            var encoded = System.Text.Encoding.UTF8.GetBytes(label);
            buf.Add((byte)encoded.Length);
            buf.AddRange(encoded);
        }
        buf.Add(0); // root label
    }

    public byte[] ToArray() => [.. buf];
}

// -------------------------------------------------------------------------
// DNS wire-format reader
// -------------------------------------------------------------------------

internal sealed class DnsReader
{
    private readonly byte[] data;
    private readonly byte[]? fullPacket; // for pointer decompression
    private int pos;

    public DnsReader(byte[] data, byte[]? fullPacket = null)
    {
        this.data = data;
        this.fullPacket = fullPacket ?? data;
        this.pos = 0;
    }

    public byte ReadByte() => data[pos++];

    public ushort ReadUInt16()
    {
        var v = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos));
        pos += 2;
        return v;
    }

    public uint ReadUInt32()
    {
        var v = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));
        pos += 4;
        return v;
    }

    public byte[] ReadBytes(int count)
    {
        var result = data[pos..(pos + count)];
        pos += count;
        return result;
    }

    public string ReadName()
    {
        var sb = new StringBuilder();
        ReadNameInto(sb, data, ref pos, fullPacket!);
        if (sb.Length > 0 && sb[^1] != '.')
            sb.Append('.');
        return sb.ToString();
    }

    private static void ReadNameInto(StringBuilder sb, byte[] data, ref int pos, byte[] fullPacket, int depth = 0)
    {
        if (depth > 10) return; // guard against malformed compression loops

        while (pos < data.Length)
        {
            byte len = data[pos];

            if (len == 0)
            {
                pos++;
                return;
            }

            if ((len & 0xC0) == 0xC0)
            {
                // Pointer — 2-byte offset into full packet
                int offset = ((len & 0x3F) << 8) | data[pos + 1];
                pos += 2;
                ReadNameInto(sb, fullPacket, ref offset, fullPacket, depth + 1);
                return;
            }

            pos++;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(System.Text.Encoding.UTF8.GetString(data, pos, len));
            pos += len;
        }
    }
}
