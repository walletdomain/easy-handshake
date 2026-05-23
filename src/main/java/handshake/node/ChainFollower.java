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
    private handshake.wallet.WalletScanner    walletScanner;

    public ChainFollower(Database db) {
        this.db        = db;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "chain-follower");
            t.setDaemon(true);
            return t;
        });
    }

    public void setDnsServer(handshake.node.dns.DnsServer dns) {
        this.dnsServer = dns;
    }

    public void setWalletManager(handshake.wallet.WalletManager wm) {
        this.walletManager = wm;
    }

    public void setWalletScanner(handshake.wallet.WalletScanner ws) {
        this.walletScanner = ws;
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
                        if (walletScanner != null)
                            walletScanner.applyNewBlock(block, h);
                        // Check for pending FINALIZE transactions
                        if (walletManager != null)
                            checkPendingFinalizations(h, header.hash());
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

    // ── Auto-finalize pending transfers ───────────────────────────────────────

    /**
     * Checks all wallets for pending FINALIZE transactions.
     * Called on every new block. When a TRANSFER lockup period expires,
     * automatically builds and broadcasts FINALIZE (unless manual approval required).
     */
    private void checkPendingFinalizations(int height, byte[] blockHash) {
        if (walletManager == null) return;
        Config cfg = Config.get();
        boolean requireApproval = cfg.isTransferApprovalRequired();

        handshake.wallet.WalletDB walletDb = walletManager.getWalletDB();

        for (handshake.wallet.WalletDB.WalletRecord wallet :
                walletManager.getAllWallets()) {
            for (handshake.wallet.WalletDB.NameRecord nameRec :
                    walletDb.getNamesForWallet(wallet.id)) {

                if (!"TRANSFERRING".equals(nameRec.state)) continue;
                if (nameRec.finalizeAfterHeight <= 0) continue;
                if (height < nameRec.finalizeAfterHeight) continue;
                if (nameRec.recipientAddress == null
                        || nameRec.recipientAddress.isEmpty()) continue;
                if (nameRec.ownerPrivKeyHex == null
                        || nameRec.ownerPrivKeyHex.isEmpty()) continue;

                System.out.printf("[ChainFollower] TRANSFER lockup expired for .%s at height %d%n",
                        nameRec.name, height);

                if (requireApproval) {
                    // Mark as ready to finalize — UI will show Finalize button
                    nameRec.state = "READY_TO_FINALIZE";
                    walletDb.saveName(nameRec);
                    System.out.printf("[ChainFollower] Manual approval required for .%s%n",
                            nameRec.name);
                    EventBus.get().name("." + nameRec.name
                            + " is ready to finalize — click Finalize in wallet");
                    continue;
                }

                // Auto-finalize
                try {
                    sendFinalize(nameRec, height, blockHash, walletDb);
                } catch (Exception e) {
                    System.out.printf("[ChainFollower] Auto-finalize failed for .%s: %s%n",
                            nameRec.name, e.getMessage());
                }
            }
        }
    }

    private void sendFinalize(handshake.wallet.WalletDB.NameRecord nameRec,
                              int height, byte[] blockHash,
                              handshake.wallet.WalletDB walletDb) throws Exception {
        // Find the TRANSFER UTXO — it was created by the TRANSFER tx
        // The TRANSFER tx output index for the name is 0
        byte[] namePrevHash = fromHex(nameRec.transferTxid);
        if (namePrevHash == null || namePrevHash.length != 32) {
            System.out.printf("[ChainFollower] No transferTxid for .%s%n", nameRec.name);
            return;
        }

        // The name UTXO value is preserved through TRANSFER
        // Find it from the UTXO records
        long nameValue = 0;
        for (handshake.wallet.WalletDB.UtxoRecord u :
                walletDb.getAllUtxosForAddress(nameRec.ownerAddress)) {
            if (u.txHash.equals(nameRec.transferTxid) && u.outputIndex == 0) {
                nameValue = u.value;
                break;
            }
        }
        if (nameValue == 0) {
            // Use stored value from original name UTXO as fallback
            for (handshake.wallet.WalletDB.UtxoRecord u :
                    walletDb.getAllUtxosForAddress(nameRec.ownerAddress)) {
                if (u.txHash.equals(nameRec.utxoTxHash)
                        && u.outputIndex == nameRec.utxoIndex) {
                    nameValue = u.value;
                    break;
                }
            }
        }

        System.out.printf("[ChainFollower] Building FINALIZE for .%s nameValue=%d blockHash=%s%n",
                nameRec.name, nameValue,
                handshake.wallet.HNSTxBuilder.toHex(blockHash).substring(0, 16));

        handshake.wallet.HNSTxBuilder.SignedTx tx =
                handshake.wallet.HNSTransferBuilder.buildFinalize(
                        nameRec, namePrevHash, 0, nameValue, blockHash);

        handshake.wallet.HNSBroadcaster.broadcast(tx);

        // Update name record — clear sensitive key data, update state
        nameRec.state           = "FINALIZED";
        nameRec.transferTxid    = tx.txid;
        nameRec.ownerPrivKeyHex = ""; // clear private key
        nameRec.feePrivKeyHex   = ""; // clear private key
        walletDb.saveName(nameRec);

        System.out.printf("[ChainFollower] FINALIZE broadcast for .%s txid=%s%n",
                nameRec.name, tx.txid);
        EventBus.get().name("." + nameRec.name + " transfer finalized → "
                + nameRec.recipientAddress.substring(0, 12) + "...");
    }

    private static byte[] fromHex(String hex) {
        if (hex == null || hex.length() < 2) return null;
        try {
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < b.length; i++)
                b[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
            return b;
        } catch (Exception e) { return null; }
    }
}