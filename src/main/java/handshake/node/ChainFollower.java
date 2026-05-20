package handshake.node;

import handshake.database.Database;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * ChainFollower — keeps the node current with the live Handshake chain.
 *
 * After the initial sync, new blocks are mined roughly every 10 minutes.
 * This class runs a background thread that periodically:
 *   1. Connects to the fastest available peer
 *   2. Compares their height against our local header tip
 *   3. If they're ahead, syncs new headers then downloads new blocks
 *   4. Sleeps until the next check interval
 *
 * It also listens for INV messages from the PeerServer (future enhancement)
 * which would allow instant notification of new blocks rather than polling.
 *
 * Thread safety: all database writes are synchronised on the Database instance.
 * The PeerServer only reads from the database, so concurrent access is safe
 * as long as we don't write during an active PeerServer block serve.
 */
public class ChainFollower {

    /** How often to check for new blocks when idle. */
    private static final int POLL_INTERVAL_SECONDS = 60;

    private final Database              db;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean         running = new AtomicBoolean(false);
    private handshake.node.dns.DnsServer      dnsServer;
    private handshake.wallet.WalletManager    walletManager;

    public ChainFollower(Database db) {
        this.db        = db;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "chain-follower");
            t.setDaemon(true);
            return t;
        });
    }

    /** Wire in the DNS server so new blocks update the name index. */
    public void setDnsServer(handshake.node.dns.DnsServer dns) {
        this.dnsServer = dns;
    }

    /** Wire in the wallet manager for renewal warnings. */
    public void setWalletManager(handshake.wallet.WalletManager wm) {
        this.walletManager = wm;
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start() {
        running.set(true);
        // Run immediately on start, then every POLL_INTERVAL_SECONDS
        scheduler.scheduleWithFixedDelay(
                this::followChain,
                0,
                POLL_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        System.out.println("[ChainFollower] Started. Checking for new blocks every "
                + POLL_INTERVAL_SECONDS + "s.");
    }

    public void stop() {
        running.set(false);
        scheduler.shutdown();
        System.out.println("[ChainFollower] Stopped.");
    }

    // -------------------------------------------------------------------------
    // Main follow loop — runs every POLL_INTERVAL_SECONDS
    // -------------------------------------------------------------------------

    private void followChain() {
        if (!running.get()) return;

        try {
            int localTip = db.getTipHeight();

            // Connect to best peer and check their height
            HNSPeer peer = connectToBestPeer();
            if (peer == null) {
                System.out.println("[ChainFollower] No peers available — will retry in "
                        + POLL_INTERVAL_SECONDS + "s.");
                return;
            }

            int peerHeight = peer.getPeerHeight();

            if (localTip >= peerHeight - 1) {
                // Already current — close connection and wait
                System.out.println("[ChainFollower] Up to date at height " + localTip + ".");
                try { peer.peer.socket.close(); } catch (Exception ignored) {}
                // Check renewal warnings every cycle
                if (walletManager != null)
                    walletManager.checkRenewalWarnings(localTip);
                return;
            }

            int newBlocks = peerHeight - localTip;
            System.out.println("[ChainFollower] " + newBlocks
                    + " new block(s) available (local=" + localTip
                    + " peer=" + peerHeight + "). Syncing...");
            EventBus.get().peer("Syncing " + newBlocks + " new block(s) from "
                    + peer.peer.seed.ipAddress()
                    + " (h=" + peerHeight + ")");

            // ── Step 1: Sync new headers ──────────────────────────────────
            List<byte[]> locator = localTip == -1
                    ? List.of(HNSPeer.GENESIS_HASH)
                    : List.of(db.getHashAtHeight(localTip));
            int startHeight = localTip + 1;

            List<HNSPeer.BlockHeader> headers = peer.syncAllHeaders(locator);
            if (headers.isEmpty()) {
                System.out.println("[ChainFollower] No headers returned — already current.");
                try { peer.peer.socket.close(); } catch (Exception ignored) {}
                return;
            }

            db.insertHeaders(headers, startHeight);
            int newTip = db.getTipHeight();
            System.out.println("[ChainFollower] Headers synced. New tip: " + newTip);
            try { peer.peer.socket.close(); } catch (Exception ignored) {}

            // ── Step 2: Download new blocks ───────────────────────────────
            int blockTip = db.getBlockDataTip();
            if (blockTip >= newTip) {
                System.out.println("[ChainFollower] Blocks already current.");
                return;
            }

            System.out.println("[ChainFollower] Downloading " + (newTip - blockTip)
                    + " new block(s)...");

            // Authenticate all peers for parallel download
            List<Peer> peers = HNSPeerManager.discoverPeers();
            if (peers.isEmpty()) {
                System.out.println("[ChainFollower] No peers for block download — "
                        + "will retry next cycle.");
                return;
            }

            BlockSyncCoordinator coordinator = new BlockSyncCoordinator(peers, db);
            coordinator.sync();

            // Validate any newly written blocks
            int finalTip = db.getBlockDataTip();
            for (int h = blockTip + 1; h <= finalTip; h++) {
                byte[] rawBlock = db.getRawBlock(h);
                HNSPeer.BlockHeader header = HNSPeer.BlockHeader.parse(
                        db.getHeaderAtHeight(h), 0);
                if (rawBlock != null) {
                    HNSBlock block = HNSBlock.parse(rawBlock);
                    try {
                        BlockValidator.validate(block, header, h);
                        if (dnsServer != null && dnsServer.isNameIndexReady())
                            dnsServer.applyNewBlock(block);
                        EventBus.get().block("Block " + h + " validated ✓ ("
                                + block.txs.size() + " txs)");
                    } catch (SecurityException e) {
                        System.out.println("[ChainFollower] INVALID block at height "
                                + h + ": " + e.getMessage());
                        EventBus.get().block("⚠ INVALID block at height " + h
                                + ": " + e.getMessage());
                    }
                }
            }

            System.out.println("[ChainFollower] Sync complete. Block tip: " + finalTip);

        } catch (Exception e) {
            System.out.println("[ChainFollower] Error: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            // scheduleWithFixedDelay will run again after POLL_INTERVAL_SECONDS
        }
    }

    // -------------------------------------------------------------------------
    // Peer connection helper
    // -------------------------------------------------------------------------

    private HNSPeer connectToBestPeer() {
        try {
            List<Peer> peers = HNSPeerManager.discoverPeers();
            if (peers.isEmpty()) return null;

            int localTip = db.getTipHeight();

            // Prefer peers at or above our tip — do P2P handshake on each
            // in order of response time until we find one that's current
            for (Peer best : peers) {
                HNSPeer hnsPeer;
                String ip = best.seed.ipAddress();
                try {
                    hnsPeer = new HNSPeer(best, best.brontide);
                    hnsPeer.handshake();
                    hnsPeer.sendSendHeaders();

                    if (hnsPeer.getPeerHeight() >= localTip) {
                        PeerScorecard.get().recordSuccess(ip,
                                hnsPeer.getPeerAgent(), hnsPeer.getPeerHeight());
                        // Opportunistically discover new peers via GETADDR
                        PeerDiscovery.get().discoverFrom(hnsPeer, ip);
                        for (Peer p : peers)
                            if (p != best)
                                try { p.socket.close(); } catch (Exception ignored) {}
                        return hnsPeer;
                    }

                    PeerScorecard.get().recordStaleTip(ip,
                            hnsPeer.getPeerHeight(), localTip);
                    System.out.println("[ChainFollower] Skipping " + ip
                            + " (height=" + hnsPeer.getPeerHeight()
                            + " < our tip=" + localTip + ")");
                    best.socket.close();

                } catch (Exception e) {
                    System.out.println("[ChainFollower] Peer " + ip
                            + " failed: " + e.getMessage());
                    PeerScorecard.get().recordFailure(ip, e.getMessage());
                    try { best.socket.close(); } catch (Exception ignored) {}
                }
            }

            System.out.println("[ChainFollower] No peers at or above our tip.");
            return null;

        } catch (Exception e) {
            System.out.println("[ChainFollower] Peer connection failed: "
                    + e.getMessage());
            return null;
        }
    }
}