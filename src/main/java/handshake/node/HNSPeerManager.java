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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Manages discovery and selection of Handshake brontide peers.
 * Polls all known seed nodes concurrently, performs the brontide handshake
 * with each, and returns authenticated peers sorted by response time.
 */
public class HNSPeerManager {

    private static final int CONNECT_TIMEOUT = 5000;
    private static final int POLL_THREADS    = 10;

    /**
     * Data directory — uses the working directory so the node is fully
     * self-contained and portable (runs from a USB drive, a VPS directory,
     * or any folder). All data files sit next to the JAR:
     * .
     *   easy-handshake/
     *   ├── handshake-node.jar
     *   ├── node.key          ← permanent node identity
     *   ├── chain.mv.db       ← blockchain database
     *   ├── node.mv.db        ← node state (future)
     *   └── wallet.mv.db      ← wallet (future)
     * .
     * To run from a USB drive:
     *   cd /path/to/usb
     *   java -jar easy-handshake.jar
     */
    private static final String DB_DIR = System.getProperty("user.dir");

    private static final String DB_PATH_CHAIN  = DB_DIR + File.separator + "chain";
    private static final String DB_PATH_NODE   = DB_DIR + File.separator + "node";
    private static final String DB_PATH_WALLET = DB_DIR + File.separator + "wallet";

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
    public static Peer pollSeedPublic(Seed seed) {
        return pollSeed(seed);
    }

    private static Peer pollSeed(Seed seed) {
        long start = System.currentTimeMillis();
        String ip = seed.ipAddress();

        byte[] remoteStaticPub;
        try {
            remoteStaticPub = base32Decode(seed.key());
            if (remoteStaticPub.length != 33) {
                System.out.println("  [" + ip + "] Bad key length: " + remoteStaticPub.length);
                return null;
            }
        } catch (Exception e) {
            System.out.println("  [" + ip + "] Key decode failed: " + e.getMessage());
            return null;
        }

        // Generate a fresh local static key for this session
        byte[] localStaticPriv = new byte[32];
        RNG.nextBytes(localStaticPriv);

        Socket socket = new Socket();
        try {
            System.out.println("  [" + ip + "] Connecting on port " + seed.port() + "...");
            socket.connect(
                    new InetSocketAddress(seed.ipAddress(), seed.port()),
                    CONNECT_TIMEOUT);
            socket.setSoTimeout(CONNECT_TIMEOUT);
            System.out.println("  [" + ip + "] TCP connected.");

            InputStream  in  = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            BrontideState state = new BrontideState(localStaticPriv, remoteStaticPub);
            state.init();
            state.mixHash(BrontideState.PROLOGUE.getBytes());
            state.mixHash(remoteStaticPub);

            // Act 1
            System.out.println("  [" + ip + "] Generating Act 1...");
            byte[] actOne = state.genActOne();
            System.out.println("  [" + ip + "] Sending Act 1 (" + actOne.length + " bytes)...");
            out.write(actOne);
            out.flush();
            System.out.println("  [" + ip + "] Act 1 sent. Waiting for Act 2...");

            // Act 2
            byte[] actTwo = in.readNBytes(BrontideState.ACT_TWO_SIZE);
            System.out.println("  [" + ip + "] Received " + actTwo.length + " bytes for Act 2.");
            if (actTwo.length != BrontideState.ACT_TWO_SIZE) {
                System.out.println("  [" + ip + "] Act 2 wrong size, expected "
                        + BrontideState.ACT_TWO_SIZE + " got " + actTwo.length);
                socket.close();
                return null;
            }
            boolean act2ok = state.recvActTwo(actTwo);
            System.out.println("  [" + ip + "] Act 2 verify: " + (act2ok ? "OK" : "FAILED"));
            if (!act2ok) {
                socket.close();
                return null;
            }

            // Act 3
            System.out.println("  [" + ip + "] Sending Act 3...");
            byte[] actThree = state.genActThree();
            out.write(actThree);
            out.flush();
            System.out.println("  [" + ip + "] Act 3 sent (" + actThree.length + " bytes).");

            long elapsed = System.currentTimeMillis() - start;
            System.out.println("  [" + ip + "] Brontide handshake COMPLETE (" + elapsed + "ms)");
            return new Peer(seed, elapsed, socket, state);

        } catch (Exception e) {
            System.out.println("  [" + ip + "] ERROR: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
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

    public static Peer selectBestPeer(List<Peer> peers) {
        return peers.isEmpty() ? null : peers.getFirst();
    }

    // -------------------------------------------------------------------------
    // Main
    // -------------------------------------------------------------------------

    static void main() throws Exception {
        System.out.println("Opening database at " + DB_PATH_CHAIN + " ...");

        // Load or generate our permanent node identity
        NodeIdentity identity = new NodeIdentity(DB_DIR);

        try (Database db = new Database(DB_PATH_CHAIN)) {

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

            System.out.println("\nNode is running. Press Ctrl+C to stop.");
            System.out.println("Brontide address: connect to port 44806");

            // Keep running until interrupted
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                System.out.println("Shutting down...");
                server.stop();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 1 — Header sync
    // -------------------------------------------------------------------------

    private static void syncHeaderPhase(Database db) throws Exception {
        final int MAX_RETRIES   = 10;
        final int RETRY_DELAY_S = 5;

        // Quick check — if we have headers and block data is also at tip,
        // skip header sync entirely without opening any connections
        int dbTip = db.getTipHeight();
        if (dbTip > 0 && db.getBlockDataTip() >= dbTip) {
            System.out.println("[Header sync] Already at tip (" + dbTip
                    + ") — skipping (no connection needed).");
            return;
        }

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            int tipHeight = db.getTipHeight();
            System.out.println("\n[Header sync] Tip: "
                    + (tipHeight == -1 ? "(empty)" : tipHeight)
                    + " | Attempt " + attempt + "/" + MAX_RETRIES);

            HNSPeer p = connectToBestPeer();
            if (p == null) {
                waitBeforeRetry(attempt, RETRY_DELAY_S);
                continue;
            }

            try {
                // Check if headers are already at chain tip
                if (tipHeight >= p.getPeerHeight() - 1) {
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
                    waitBeforeRetry(attempt, RETRY_DELAY_S);
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
                waitBeforeRetry(attempt, RETRY_DELAY_S);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 2 — Block sync (parallel, multi-peer)
    // -------------------------------------------------------------------------

    private static void syncBlockPhase(Database db) throws Exception {
        final int MAX_RETRIES   = 200; // allow many reconnects for long sync
        final int RETRY_DELAY_S = 5;

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
                waitBeforeRetry(attempt, RETRY_DELAY_S);
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

            waitBeforeRetry(attempt, RETRY_DELAY_S);
        }
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /**
     * Authenticates all seeds, picks the fastest, does the P2P handshake,
     * and returns a ready HNSPeer. Returns null if no peers responded.
     * Used by syncHeaderPhase — block sync uses all peers via the coordinator.
     */
    private static HNSPeer connectToBestPeer() throws Exception {
        List<Peer> peers = discoverPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers responded.");
            return null;
        }
        Peer best = selectBestPeer(peers);
        // Close unused sockets
        for (Peer peer : peers)
            if (peer != best)
                try { peer.socket.close(); } catch (Exception ignored) {}
        HNSPeer p = new HNSPeer(best, best.brontide);
        p.handshake();
        p.sendSendHeaders();
        return p;
    }

    private static void waitBeforeRetry(int attempt, int baseDelay) throws Exception {
        int delay = Math.min(baseDelay * attempt, 120);
        System.out.println("Retrying in " + delay + "s...");
        Thread.sleep(delay * 1000L);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}