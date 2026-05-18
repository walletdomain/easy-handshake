package handshake.node.dns;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The 13 DNS root nameservers used to bootstrap ICANN TLD resolution.
 *
 * IPv4 and IPv6 addresses verified from IANA (iana.org/domains/root/servers)
 * and root-servers.org in May 2026. These addresses are anycast — each IP
 * routes to the nearest of hundreds of physical server instances.
 *
 * Usage in the recursive resolver:
 *   1. Query arrives for an ICANN/reserved TLD (e.g. "google.com")
 *   2. Pick a root hint (randomly for load distribution)
 *   3. Send a DNS query to rootHint.ipv4() port 53
 *   4. Root server returns NS referral for ".com"
 *   5. Follow the referral chain to the authoritative answer
 *
 * These addresses change extremely rarely. The last IPv4 change was
 * D-root in 2013. IPv6 addresses were added progressively 2008-2010.
 */
public class IcannRootHints {

    public static final List<IcannRootHint> HINTS = List.of(
            new IcannRootHint("a", "a.root-servers.net.", "Verisign",
                    "198.41.0.4",     "2001:503:ba3e::2:30"),
            new IcannRootHint("b", "b.root-servers.net.", "USC-ISI",
                    "199.9.14.201",   "2001:500:200::b"),
            new IcannRootHint("c", "c.root-servers.net.", "Cogent Communications",
                    "192.33.4.12",    "2001:500:2::c"),
            new IcannRootHint("d", "d.root-servers.net.", "University of Maryland",
                    "199.7.91.13",    "2001:500:2d::d"),
            new IcannRootHint("e", "e.root-servers.net.", "NASA Ames Research Center",
                    "192.203.230.10", "2001:500:a8::e"),
            new IcannRootHint("f", "f.root-servers.net.", "Internet Systems Consortium",
                    "192.5.5.241",    "2001:500:2f::f"),
            new IcannRootHint("g", "g.root-servers.net.", "DISA / DoD NIC",
                    "192.112.36.4",   "2001:500:12::d0d"),
            new IcannRootHint("h", "h.root-servers.net.", "U.S. Army Research Laboratory",
                    "198.97.190.53",  "2001:500:1::53"),
            new IcannRootHint("i", "i.root-servers.net.", "Netnod",
                    "192.36.148.17",  "2001:7fe::53"),
            new IcannRootHint("j", "j.root-servers.net.", "Verisign",
                    "192.58.128.30",  "2001:503:c27::2:30"),
            new IcannRootHint("k", "k.root-servers.net.", "RIPE NCC",
                    "193.0.14.129",   "2001:7fd::1"),
            new IcannRootHint("l", "l.root-servers.net.", "ICANN",
                    "199.7.83.42",    "2001:500:9f::42"),
            new IcannRootHint("m", "m.root-servers.net.", "WIDE Project",
                    "202.12.27.33",   "2001:dc3::35")
    );

    private IcannRootHints() {} // static utility class

    /**
     * Returns a random root hint for load distribution across servers.
     * Real resolvers distribute queries rather than always hitting the same root.
     */
    public static IcannRootHint random() {
        return HINTS.get(ThreadLocalRandom.current().nextInt(HINTS.size()));
    }

    /**
     * Returns the root hint for a specific letter (a-m), or null if not found.
     */
    public static IcannRootHint forLetter(String letter) {
        return HINTS.stream()
                .filter(h -> h.letter().equalsIgnoreCase(letter))
                .findFirst()
                .orElse(null);
    }

    /**
     * Returns all IPv4 addresses as a simple array.
     * Useful for initializing a UDP socket pool.
     */
    public static String[] allIpv4() {
        return HINTS.stream().map(IcannRootHint::ipv4).toArray(String[]::new);
    }
}