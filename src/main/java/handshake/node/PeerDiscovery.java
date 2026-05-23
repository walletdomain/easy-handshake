package handshake.node;

import handshake.node.Seed;
import org.h2.mvstore.MVMap;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Discovers new peers by sending GETADDR to known seeds and persists
 * the discovered addresses to config.mv.db.
 *
 * On startup, discovered peers are combined with seeds to give a much
 * larger pool of connection candidates. This means the node stays
 * connected even if seeds go offline.
 *
 * Discovered peers are stored in the "discoveredPeers" MVStore map:
 *   ip → "key|port|lastSeen"
 */
public class PeerDiscovery {

    private static final int    MAX_DISCOVERED  = 500;
    private static final int    GETADDR_TIMEOUT = 10_000; // ms

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile PeerDiscovery instance;

    public static PeerDiscovery get() {
        if (instance == null) {
            synchronized (PeerDiscovery.class) {
                if (instance == null) instance = new PeerDiscovery();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    /** ip → "key|port|lastSeen" */
    private MVMap<String, String> store;

    /** In-memory cache of discovered peers */
    private final ConcurrentHashMap<String, Seed> discovered = new ConcurrentHashMap<>();

    private PeerDiscovery() {}

    public void init(org.h2.mvstore.MVStore mvStore) {
        this.store = mvStore.openMap("discoveredPeers");

        // Load persisted peers into cache
        for (Map.Entry<String, String> e : store.entrySet()) {
            Seed seed = fromStorage(e.getKey(), e.getValue());
            if (seed != null) discovered.put(e.getKey(), seed);
        }
        System.out.printf("[PeerDiscovery] Loaded %d previously discovered peers.%n",
                discovered.size());
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    /**
     * Queries a connected peer for its known peers via GETADDR.
     * Any newly discovered peers are persisted for future use.
     *
     * @param peer      connected HNSPeer to query
     * @param sourceIp  IP of the peer we're querying (for logging)
     * @return          number of NEW peers discovered
     */
    public int discoverFrom(HNSPeer peer, String sourceIp) {
        try {
            List<Seed> found = peer.requestMorePeers(GETADDR_TIMEOUT);
            int newCount = 0;
            for (Seed s : found) {
                if (!discovered.containsKey(s.ipAddress())
                        && !isKnownSeed(s.ipAddress())
                        && discovered.size() < MAX_DISCOVERED) {
                    discovered.put(s.ipAddress(), s);
                    if (store != null)
                        store.put(s.ipAddress(), toStorage(s));
                    newCount++;
                }
            }
            if (newCount > 0) {
                System.out.printf("[PeerDiscovery] Discovered %d new peers "
                                + "from %s (%d total).%n",
                        newCount, sourceIp, discovered.size());
                EventBus.get().peer("Discovered " + newCount
                        + " new peers from " + sourceIp);
            }
            return newCount;
        } catch (Exception e) {
            return 0;
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /**
     * Returns all known peers — seeds + discovered peers combined.
     * Used by HNSPeerManager to build its connection pool.
     */
    public List<Seed> getAllPeers() {
        List<Seed> all = new ArrayList<>(SeedDatabase.get().getActiveSeeds());
        // Add discovered peers that aren't already in seeds
        Set<String> seedIps = new HashSet<>();
        for (Seed s : all) seedIps.add(s.ipAddress());
        for (Seed s : discovered.values()) {
            if (!seedIps.contains(s.ipAddress())) all.add(s);
        }
        return all;
    }

    /** Returns only the discovered (non-seed) peers. */
    public List<Seed> getDiscoveredPeers() {
        return new ArrayList<>(discovered.values());
    }

    public int getDiscoveredCount() { return discovered.size(); }

    /** Returns all discovered peers as JSON. */
    public String toJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Seed s : discovered.values()) {
            if (!first) sb.append(",");
            sb.append(String.format(
                    "{\"ip\":\"%s\",\"port\":%d,\"key\":\"%s\"}",
                    s.ipAddress(), s.port(), s.key()));
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Adds a cleartext-only peer (no brontide key) discovered via ADDR messages
     * or other means. These peers are only reachable on port 12038.
     */
    public void addCleartextPeer(String ip) {
        if (ip == null || ip.isBlank()) return;
        if (isKnownSeed(ip)) return;
        if (discovered.containsKey(ip)) return;
        Seed s = new Seed("", ip, HNSCleartextPeer.CLEARTEXT_PORT);
        discovered.put(ip, s);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isKnownSeed(String ip) {
        return SeedDatabase.get().getAllEntries().stream()
                .anyMatch(e -> e.ip().equals(ip));
    }

    private static String toStorage(Seed s) {
        return s.key() + "|" + s.port() + "|" + System.currentTimeMillis();
    }

    private static Seed fromStorage(String ip, String val) {
        try {
            String[] p = val.split("\\|");
            return new Seed(p[0], ip, Integer.parseInt(p[1]));
        } catch (Exception e) {
            return null;
        }
    }
}