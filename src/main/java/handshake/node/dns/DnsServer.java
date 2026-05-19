package handshake.node.dns;

import handshake.database.Database;

import java.util.concurrent.Executors;

/**
 * Manages the Handshake DNS resolver components.
 *
 * Starts and coordinates:
 *   - NameIndex build (scans all blocks to build name→records map)
 *   - AuthoritativeServer on port 5349 (serves Handshake root zone)
 *   - RecursiveResolver on port 5350 (HNS-first full resolver)
 *
 * The name index build runs on a background thread so the DNS servers
 * start immediately and answer queries as soon as they're ready.
 * During the initial build (which takes a few minutes for 330k blocks),
 * Handshake TLD lookups return NXDOMAIN — ICANN queries work immediately.
 *
 * Usage:
 *   DnsServer dns = new DnsServer(db);
 *   dns.start();
 *   // ... node runs ...
 *   dns.stop();
 *
 * The DnsServer is started from HNSPeerManager after the initial sync,
 * alongside PeerServer, NodeHttpServer, and ChainFollower.
 */
public class DnsServer {

    private final Database           db;
    private final NameIndex          nameIndex;
    private final AuthoritativeServer authNs;
    private final RecursiveResolver  recursive;

    private volatile boolean nameIndexReady = false;

    public DnsServer(Database db) {
        this(db, AuthoritativeServer.DEFAULT_PORT, RecursiveResolver.DEFAULT_PORT);
    }

    public DnsServer(Database db, int authPort, int recursivePort) {
        this.db        = db;
        this.nameIndex = new NameIndex(db);
        this.authNs    = new AuthoritativeServer(nameIndex, authPort);
        this.recursive = new RecursiveResolver(nameIndex, authNs, recursivePort);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * Starts both DNS servers and kicks off the name index build
     * on a background thread.
     */
    public void start() throws Exception {
        // Start DNS servers immediately — they'll return NXDOMAIN for
        // Handshake names until the index build completes
        authNs.start();
        recursive.start();

        // Build name index on background thread
        var buildExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "name-index-build");
            t.setDaemon(true);
            return t;
        });

        buildExecutor.submit(() -> {
            System.out.println("[DnsServer] Starting name index build...");
            nameIndex.build();
            nameIndexReady = true;
            System.out.println("[DnsServer] Name index ready. "
                    + nameIndex.size() + " Handshake names indexed.");
            buildExecutor.shutdown();
        });

        System.out.println("[DnsServer] DNS resolver started.");
        System.out.println("[DnsServer]   Authoritative: port "
                + AuthoritativeServer.DEFAULT_PORT
                + " (Handshake root zone)");
        System.out.println("[DnsServer]   Recursive:     port "
                + RecursiveResolver.DEFAULT_PORT
                + " (HNS-first full resolver)");
        System.out.println("[DnsServer] Name index building in background...");
    }

    public void stop() {
        authNs.stop();
        recursive.stop();
        System.out.println("[DnsServer] Stopped.");
    }

    // ── ChainFollower integration ─────────────────────────────────────────────

    /**
     * Called by ChainFollower after each new block is validated.
     * Keeps the name index current without a full rescan.
     */
    public void applyNewBlock(handshake.node.HNSBlock block) {
        if (nameIndexReady) nameIndex.applyBlock(block);
    }

    // ── Status ────────────────────────────────────────────────────────────────

    public boolean   isNameIndexReady() { return nameIndexReady; }
    public NameIndex getNameIndex()     { return nameIndex; }
    public int       getNameCount()     { return nameIndex.size(); }
}