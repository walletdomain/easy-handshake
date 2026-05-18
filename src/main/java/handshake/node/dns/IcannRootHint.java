package handshake.node.dns;

/**
 * Immutable data carrier for a single DNS root nameserver.
 *
 * There are 13 root nameserver addresses (a through m), each operated
 * by an independent organization. Behind each address sit hundreds of
 * anycast instances distributed globally — as of 2025 there are ~1,959
 * physical instances behind the 13 logical addresses.
 *
 * @param letter    single letter identifier ("a" through "m")
 * @param hostname  fully qualified hostname (e.g. "a.root-servers.net.")
 * @param operator  organization responsible for this root server
 * @param ipv4      IPv4 address (stable for decades, anycast)
 * @param ipv6      IPv6 address (added progressively since 2008)
 */
public record IcannRootHint(
        String letter,
        String hostname,
        String operator,
        String ipv4,
        String ipv6
) {}