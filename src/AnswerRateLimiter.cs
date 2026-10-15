namespace Haukcode.Mdns;

/// <summary>
/// The RFC 6762 §6 rule that a record is not multicast on a given interface more
/// than once per second, kept per interface so an answer on one link never
/// suppresses one on another.
/// </summary>
/// <remarks>
/// "A Multicast DNS responder MUST NOT multicast a record on a given interface until
/// at least one second has elapsed since the last time that record was multicast on
/// that particular interface. A legitimate querier on the network should have seen
/// the previous transmission, so there is no need to send it again."
///
/// Our answer to a query is the whole announcement, so the limiter tracks the
/// announcement as one unit rather than record by record. Legacy unicast replies
/// (§6.7) are not multicast and are not subject to this.
/// </remarks>
internal sealed class AnswerRateLimiter(TimeSpan minimumInterval)
{
    private readonly Dictionary<int, TimeSpan> lastSent = new();

    /// <summary>
    /// Whether an announcement may be multicast on <paramref name="interfaceIndex"/>
    /// at <paramref name="now"/>.
    /// </summary>
    public bool MayAnswer(int interfaceIndex, TimeSpan now)
    {
        if (!lastSent.TryGetValue(interfaceIndex, out var last))
            return true;

        return now - last >= minimumInterval;
    }

    /// <summary>
    /// Note that the announcement went out on <paramref name="interfaceIndex"/> at
    /// <paramref name="now"/>, solicited or not.
    /// </summary>
    public void Record(int interfaceIndex, TimeSpan now)
    {
        lastSent[interfaceIndex] = now;
    }
}
