package handshake.node;

import handshake.database.Database;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.*;

/**
 * Manages discovery and selection of Handshake brontide peers.
 * Polls all known seed nodes concurrently, performs the brontide handshake
 * with each, and returns authenticated peers sorted by response time.
 */
public class HNSPeerManager {

    private static final int CONNECT_TIMEOUT = 5000;
    private static final int POLL_THREADS    = 10;

    /**
     * Data directory — resolves to the working directory so the node is fully
     * self-contained and portable (runs from a USB drive, a VPS directory,
     * or any folder). All data files sit next to the JAR:
     *
     *   easy-handshake/
     *   ├── easy-handshake.jar
     *   ├── node.key          ← permanent node identity
     *   ├── chain.mv.db       ← blockchain database
     *   ├── node.mv.db        ← node state (future)
     *   └── wallet.mv.db      ← wallet (future)
     *
     * To run from a USB drive:
     *   cd /path/to/usb
     *   java -jar easy-handshake.jar
     */
    private static final String DB_DIR = new java.io.File(".").getAbsolutePath()
            .replaceAll("\\.$", "").replaceAll("[/\\\\]$", "");

    private static final String DB_PATH_CHAIN  = DB_DIR + File.separator + "chain";
    @SuppressWarnings("unused") private static final String DB_PATH_NODE   = DB_DIR + File.separator + "node";
    @SuppressWarnings("unused") private static final String DB_PATH_WALLET = DB_DIR + File.separator + "wallet";

    private static final SecureRandom RNG = new SecureRandom();

    // -------------------------------------------------------------------------
    // Base32 decoder (RFC 4648, lowercase a-z2-7)
    // Used to decode brontide public keys from seed entries.
    // -------------------------------------------------------------------------

    private static byte[] base32Decode(String input) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        int[] lookup = new int[128];
        Arrays.fill(lookup, -1);
        for (int i = 0; i < alphabet.length(); i++)
            lookup[alphabet.charAt(i)] = i;

        input = input.toLowerCase().replace("=", "");
        int bits = 0, value = 0, index = 0;
        byte[] result = new byte[input.length() * 5 / 8];
        for (char c : input.toCharArray()) {
            value = (value << 5) | lookup[c];
            bits += 5;
            if (bits >= 8) {
                result[index++] = (byte) ((value >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return Arrays.copyOf(result, index);
    }

    // -------------------------------------------------------------------------
    // Poll a single brontide seed
    // -------------------------------------------------------------------------

    /** Public entry point for BlockSyncCoordinator to connect to a single seed. */
    @SuppressWarnings("unused") // called by BlockSyncCoordinator via reflection-like dispatch
    public static Peer pollSeedPublic(Seed seed) {
        return pollSeed(seed);
    }

    private static Peer pollSeed(Seed seed) {
        long start = System.currentTimeMillis();
        String ip = seed.ipAddress();

        byte[] remoteStaticPub;
        try {
            remoteStaticPub = base32Decode(seed.key());
            if (remoteStaticPub.length != 33) return null;
        } catch (Exception e) {
            return null;
        }

        byte[] localStaticPriv = new byte[32];
        RNG.nextBytes(localStaticPriv);

        Socket socket = new Socket();
        try {
            socket.connect(
                    new InetSocketAddress(seed.ipAddress(), seed.port()),
                    CONNECT_TIMEOUT);
            socket.setSoTimeout(CONNECT_TIMEOUT);

            InputStream  in  = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            BrontideState state = new BrontideState(localStaticPriv, remoteStaticPub);
            state.init();

            // Act 1
            byte[] actOne = state.genActOne();
            out.write(actOne);
            out.flush();

            // Act 2
            byte[] actTwo = in.readNBytes(BrontideState.ACT_TWO_SIZE);
            if (actTwo.length != BrontideState.ACT_TWO_SIZE) {
                socket.close();
                return null;
            }
            if (!state.recvActTwo(actTwo)) {
                socket.close();
                return null;
            }

            // Act 3
            byte[] actThree = state.genActThree();
            out.write(actThree);
            out.flush();

            long elapsed = System.currentTimeMillis() - start;
            // brontide OK — suppress success messages to reduce noise
            return new Peer(seed, elapsed, socket, state);

        } catch (Exception e) {
            System.out.printf("  [%s] failed: %s%n", ip,
                    e.getClass().getSimpleName());
            try { socket.close(); } catch (Exception ignored) {}
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Discover peers concurrently
    // -------------------------------------------------------------------------

    public static List<Peer> discoverPeers() throws InterruptedException {
        List<Future<Peer>> futures = new ArrayList<>();

        try (ExecutorService executor = Executors.newFixedThreadPool(POLL_THREADS)) {
            for (Seed seed : Seed.SEEDS_BRONTIDE) {
                futures.add(executor.submit(() -> pollSeed(seed)));
            }

            executor.shutdown();
            boolean finished = executor.awaitTermination(
                    CONNECT_TIMEOUT + 2000L, TimeUnit.MILLISECONDS);
            if (!finished)
                System.out.println("Warning: some peers timed out before termination.");
        }

        List<Peer> peers = new ArrayList<>();
        for (Future<Peer> future : futures) {
            try {
                Peer peer = future.get();
                if (peer != null) peers.add(peer);
            } catch (Exception ignored) {}
        }

        peers.sort(Comparator.comparingLong(p -> p.responseTimeMs));
        return peers;
    }

    // -------------------------------------------------------------------------
    // Select the fastest authenticated peer
    // -------------------------------------------------------------------------

    @SuppressWarnings("unused") // called by ChainFollower
    public static Peer selectBestPeer(List<Peer> peers) {
        return peers.isEmpty() ? null : peers.getFirst();
    }

    // -------------------------------------------------------------------------
    // Main
    // -------------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        System.out.println("Opening database at " + DB_PATH_CHAIN + " ...");

        // Load or generate our permanent node identity
        NodeIdentity identity = new NodeIdentity(DB_DIR);

        try (Database db = new Database(DB_PATH_CHAIN)) {

            // Initialize event bus with persistent storage
            handshake.node.EventBus.get().init(db);
            handshake.node.EventBus.get().system("Node started. Database: " + DB_PATH_CHAIN);

            // ── Phase 1: Header sync ──────────────────────────────────────
            syncHeaderPhase(db);

            // ── Phase 2: Block sync ───────────────────────────────────────
            syncBlockPhase(db);

            System.out.println("\nFull sync complete. Database: "
                    + DB_PATH_CHAIN + ".mv.db");

            // ── Phase 3: Run as peer node ─────────────────────────────────
            // Accept inbound connections from other Handshake nodes
            PeerServer server = new PeerServer(identity, db);
            server.start();

            // ── Phase 4: Embedded HTTP dashboard and REST API ─────────────
            NodeHttpServer httpServer = new NodeHttpServer(db);
            httpServer.start();

            // ── Phase 5: Follow the live chain ────────────────────────────
            // Background thread checks for new blocks every 60 seconds
            ChainFollower follower = new ChainFollower(db);
            follower.start();

            // ── Phase 6: DNS resolver ─────────────────────────────────────
            // Authoritative (port 5349) + recursive (port 5350)
            // Name index builds in background from block database
            handshake.node.dns.DnsServer dnsServer =
                    new handshake.node.dns.DnsServer(db);
            dnsServer.start();

            // Wire DNS server into ChainFollower so new blocks update the name index
            follower.setDnsServer(dnsServer);

            System.out.println("\nNode is running. Press Ctrl+C to stop.");
            System.out.println("Dashboard:     http://localhost:"
                    + NodeHttpServer.DEFAULT_PORT);
            System.out.println("Brontide:      port 44806");
            System.out.println("DNS Auth:      port 5349");
            System.out.println("DNS Recursive: port 5350");

            // Keep running until interrupted
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                System.out.println("Shutting down...");
                dnsServer.stop();
                follower.stop();
                httpServer.stop();
                server.stop();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 1 — Header sync
    // -------------------------------------------------------------------------

    private static void syncHeaderPhase(Database db) throws Exception {
        final int MAX_RETRIES   = 10;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            int tipHeight = db.getTipHeight();
            System.out.println("\n[Header sync] Local tip: "
                    + (tipHeight == -1 ? "(empty)" : tipHeight)
                    + " | Attempt " + attempt + "/" + MAX_RETRIES);

            HNSPeer p = connectToBestPeer(tipHeight);
            if (p == null) {
                waitBeforeRetry(attempt);
                continue;
            }

            try {
                int peerHeight = p.getPeerHeight();
                System.out.println("[Header sync] Peer height: " + peerHeight);

                // Already at tip — no sync needed
                if (tipHeight >= peerHeight - 1) {
                    System.out.println("[Header sync] Already at tip ("
                            + tipHeight + ") — skipping.");
                    p.peer.socket.close();
                    return;
                }

                // Build locator
                List<byte[]> locator = tipHeight == -1
                        ? List.of(HNSPeer.GENESIS_HASH)
                        : List.of(db.getHashAtHeight(tipHeight));
                int startHeight = tipHeight == -1 ? 0 : tipHeight + 1;

                // Sync all headers
                List<HNSPeer.BlockHeader> headers = p.syncAllHeaders(locator);
                if (headers.isEmpty()) {
                    System.out.println("[Header sync] Already at tip.");
                    p.peer.socket.close();
                    return;
                }

                // Sanity check — if we got far fewer headers than the peer
                // claims to have, the peer may have served a short chain.
                // Retry with a different peer.
                int expectedMin = p.getPeerHeight() - startHeight - 100;
                if (headers.size() < expectedMin && p.getPeerHeight() > 1000) {
                    System.out.println("[Header sync] WARNING: got " + headers.size()
                            + " headers but peer height is " + p.getPeerHeight()
                            + " — peer may have served wrong chain, retrying.");
                    p.peer.socket.close();
                    waitBeforeRetry(attempt);
                    continue;
                }

                System.out.println("First: " + headers.getFirst());
                System.out.println("Last:  " + headers.getLast());

                // Persist
                db.insertHeaders(headers, startHeight);
                System.out.println("[Header sync] Tip now: " + db.getTipHeight()
                        + "  Total: " + db.getHeaderCount());

                p.peer.socket.close();
                return; // success

            } catch (Exception e) {
                System.out.println("[Header sync] Error: "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
                try { p.peer.socket.close(); } catch (Exception ignored) {}
                if (attempt == MAX_RETRIES) throw e;
                waitBeforeRetry(attempt);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 2 — Block sync (parallel, multi-peer)
    // -------------------------------------------------------------------------

    private static void syncBlockPhase(Database db) throws Exception {
        final int MAX_RETRIES   = 200;

        // Diagnostic and sanity check
        {
            int contigTip = db.getBlockDataTip();
            int hdrTip    = db.getTipHeight();
            System.out.println("[Block sync] Contiguous block tip: " + contigTip);
            System.out.println("[Block sync] Header tip:           " + hdrTip);

            // One-time cleanup: remove any blocks stored above the header tip
            // (can occur when headers were re-synced to a lower height)
            if (contigTip > hdrTip) {
                System.out.println("[Block sync] WARNING: block tip > header tip."
                        + " Recomputing contiguous tip...");
                db.recomputeBlockTip();
                db.removeBlocksAbove(hdrTip);
                contigTip = db.getBlockDataTip();
                System.out.println("[Block sync] Recomputed contiguous block tip: "
                        + contigTip);
            }

            if (contigTip < hdrTip) {
                System.out.println("[Block sync] Scanning for first gap above height "
                        + contigTip + "...");
                int gapAt = -1;
                for (int h = contigTip + 1;
                     h <= Math.min(contigTip + 10_000, hdrTip); h++) {
                    if (db.getRawBlock(h) == null) { gapAt = h; break; }
                }
                if (gapAt >= 0)
                    System.out.println("[Block sync] First missing block: " + gapAt);
                else
                    System.out.println("[Block sync] No gap in first 10,000 above tip.");
            }
        }

        int lastBlockTip = -1;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            int blockTip  = db.getBlockDataTip();
            int headerTip = db.getTipHeight();

            if (blockTip >= headerTip) {
                System.out.println("[Block sync] Already at tip — done.");
                return;
            }

            // Reset attempt counter whenever we made forward progress
            if (blockTip > lastBlockTip && lastBlockTip >= 0) {
                System.out.println("[Block sync] Progress made ("
                        + (blockTip - lastBlockTip)
                        + " new blocks). Resetting retry counter.");
                attempt = 1;
            }
            lastBlockTip = blockTip;

            System.out.println("\n[Block sync] " + (headerTip - blockTip)
                    + " blocks remaining | Attempt " + attempt
                    + "/" + MAX_RETRIES
                    + " | tip=" + blockTip);

            // Authenticate all peers concurrently
            List<Peer> peers = discoverPeers();
            if (peers.isEmpty()) {
                System.out.println("[Block sync] No peers responded.");
                waitBeforeRetry(attempt);
                continue;
            }

            System.out.println("[Block sync] " + peers.size()
                    + " peers authenticated:");
            for (Peer peer : peers)
                System.out.printf("  %-18s  %5dms%n",
                        peer.seed.ipAddress(), peer.responseTimeMs);

            try {
                BlockSyncCoordinator coordinator =
                        new BlockSyncCoordinator(peers, db);
                coordinator.sync();

                if (db.getBlockDataTip() >= headerTip) {
                    System.out.println("[Block sync] Complete.");
                    return;
                }
                System.out.println("[Block sync] Some blocks not downloaded,"
                        + " retrying...");

            } catch (Exception e) {
                System.out.println("[Block sync] Error: "
                        + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
                for (Peer peer : peers)
                    try { peer.socket.close(); } catch (Exception ignored) {}
            }

            waitBeforeRetry(attempt);
        }
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /**
     * Authenticates all seeds, picks the fastest peer at or above our tip,
     * does the P2P handshake, and returns a ready HNSPeer.
     * Returns null if no peers responded or all are below our local tip.
     * Used by syncHeaderPhase — block sync uses all peers via the coordinator.
     */
    private static HNSPeer connectToBestPeer(int localTip) throws Exception {
        List<Peer> peers = discoverPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers responded.");
            return null;
        }
        // Try peers in order of response time, skip any below our tip
        for (Peer best : peers) {
            @SuppressWarnings("DuplicatedCode") // same pattern in ChainFollower — kept separate
            HNSPeer p;
            try {
                p = new HNSPeer(best, best.brontide);
                p.handshake();
                p.sendSendHeaders();
                if (p.getPeerHeight() >= localTip) {
                    // Close remaining unused sockets
                    for (Peer peer : peers)
                        if (peer != best)
                            try { peer.socket.close(); } catch (Exception ignored) {}
                    return p;
                }
                System.out.println("[Header sync] Skipping "
                        + best.seed.ipAddress()
                        + " (height=" + p.getPeerHeight()
                        + " < our tip=" + localTip + ")");
                best.socket.close();
            } catch (Exception e) {
                System.out.println("[Header sync] Peer "
                        + best.seed.ipAddress() + " failed: " + e.getMessage());
                try { best.socket.close(); } catch (Exception ignored) {}
            }
        }
        System.out.println("[Header sync] No peers at or above our tip.");
        return null;
    }

    private static void waitBeforeRetry(int attempt) throws Exception {
        int delay = Math.min(5 * attempt, 120);
        System.out.println("Retrying in " + delay + "s...");
        Thread.sleep(delay * 1000L);
    }
}