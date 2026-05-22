package handshake.wallet;

import handshake.node.HNSMessage;
import handshake.node.HNSPeer;
import handshake.node.HNSPeerManager;
import handshake.node.Peer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Broadcasts a signed Handshake transaction to the P2P network.
 *
 * Strategy:
 *   1. Discover available peers via HNSPeerManager.discoverPeers()
 *   2. Connect to up to MAX_BROADCAST_PEERS concurrently
 *   3. Complete the VERSION/VERACK handshake on each connection
 *   4. Send the TX message (raw transaction bytes) directly
 *   5. Report how many peers accepted it
 *
 * We send the TX directly rather than using INV→GETDATA→TX because:
 *   - Simpler, fewer round trips
 *   - Acceptable for wallet use (not a full node relaying to many peers)
 *   - hsd mempool will validate and relay it onward if it's valid
 *
 * A transaction is considered "broadcast" if at least MIN_SUCCESS_PEERS
 * peers accepted it without closing the connection.
 */
public class HNSBroadcaster {

    private static final int MAX_BROADCAST_PEERS = 4;  // connect to up to 4 peers
    private static final int MIN_SUCCESS_PEERS   = 1;  // need at least 1 to succeed
    private static final int CONNECT_TIMEOUT_MS  = 8_000;
    private static final int SEND_TIMEOUT_MS     = 10_000;

    // ── Main broadcast entry point ────────────────────────────────────────────

    /**
     * Broadcasts a signed transaction to the Handshake P2P network.
     *
     * @param tx the signed transaction from HNSTxBuilder / HNSSigner
     * @return BroadcastResult with success flag and per-peer details
     */
    public static BroadcastResult broadcast(HNSTxBuilder.SignedTx tx) {
        System.out.printf("[HNSBroadcaster] Broadcasting tx %s (%d bytes)%n",
                tx.txid, tx.raw.length);

        List<Peer> peers;
        try {
            peers = HNSPeerManager.discoverPeers();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return BroadcastResult.failure("Interrupted while discovering peers");
        }

        if (peers.isEmpty())
            return BroadcastResult.failure("No peers available");

        // Cap at MAX_BROADCAST_PEERS
        List<Peer> targets = peers.subList(0, Math.min(MAX_BROADCAST_PEERS, peers.size()));

        // Broadcast concurrently
        ExecutorService exec = Executors.newFixedThreadPool(targets.size());
        List<Future<PeerResult>> futures = new ArrayList<>();

        for (Peer peer : targets) {
            futures.add(exec.submit(() -> sendToPeer(peer, tx.raw)));
        }

        exec.shutdown();
        try {
            exec.awaitTermination(SEND_TIMEOUT_MS + CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Collect results
        List<PeerResult> results = new ArrayList<>();
        int successes = 0;
        for (Future<PeerResult> f : futures) {
            try {
                PeerResult r = f.isDone() ? f.get() : PeerResult.timeout();
                results.add(r);
                if (r.success) successes++;
            } catch (Exception e) {
                results.add(PeerResult.error(e.getMessage()));
            }
        }

        // Close remaining peer sockets
        for (Peer p : targets) {
            try { p.socket.close(); } catch (Exception ignored) {}
        }

        boolean ok = successes >= MIN_SUCCESS_PEERS;
        System.out.printf("[HNSBroadcaster] Broadcast %s — %d/%d peers accepted%n",
                ok ? "SUCCESS" : "FAILED", successes, targets.size());

        return new BroadcastResult(ok, successes, targets.size(), results, tx.txid);
    }

    // ── Per-peer send ─────────────────────────────────────────────────────────

    /**
     * Connects to a single peer, completes handshake, sends the TX message.
     * Returns success if the peer accepted without error.
     */
    static PeerResult sendToPeer(Peer peer, byte[] rawTx) {
        String ip = peer.seed.ipAddress();
        try {
            peer.socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            System.out.printf("[Broadcaster] Connecting to %s...%n", ip);

            HNSPeer hnsPeer = new HNSPeer(peer, peer.brontide);
            hnsPeer.handshake();

            System.out.printf("[Broadcaster] Sending TX (%d bytes) to %s%n",
                    rawTx.length, ip);
            hnsPeer.sendTx(rawTx);

            System.out.printf("[Broadcaster] [%s] TX sent OK%n", ip);
            return PeerResult.success(ip);

        } catch (Exception e) {
            System.out.printf("[Broadcaster] [%s] failed: %s%n",
                    ip, e.getMessage());
            return PeerResult.error(ip, e.getMessage());
        }
    }

    // ── Result types ──────────────────────────────────────────────────────────

    public static class BroadcastResult {
        public final boolean         success;
        public final int             peersAccepted;
        public final int             peersAttempted;
        public final List<PeerResult> peerResults;
        public final String          txid;
        public final String          errorMessage;

        BroadcastResult(boolean success, int accepted, int attempted,
                        List<PeerResult> results, String txid) {
            this.success        = success;
            this.peersAccepted  = accepted;
            this.peersAttempted = attempted;
            this.peerResults    = results;
            this.txid           = txid;
            this.errorMessage   = null;
        }

        private BroadcastResult(String error) {
            this.success        = false;
            this.peersAccepted  = 0;
            this.peersAttempted = 0;
            this.peerResults    = List.of();
            this.txid           = null;
            this.errorMessage   = error;
        }

        static BroadcastResult failure(String error) {
            return new BroadcastResult(error);
        }

        @Override
        public String toString() {
            if (!success && errorMessage != null)
                return "BroadcastResult{FAILED: " + errorMessage + "}";
            return String.format("BroadcastResult{%s txid=%s accepted=%d/%d}",
                    success ? "SUCCESS" : "FAILED",
                    txid, peersAccepted, peersAttempted);
        }
    }

    public static class PeerResult {
        public final boolean success;
        public final String  ip;
        public final String  error;

        private PeerResult(boolean success, String ip, String error) {
            this.success = success;
            this.ip      = ip;
            this.error   = error;
        }

        static PeerResult success(String ip)             { return new PeerResult(true,  ip, null); }
        static PeerResult error(String ip, String msg)   { return new PeerResult(false, ip, msg);  }
        static PeerResult error(String msg)              { return new PeerResult(false, "?", msg); }
        static PeerResult timeout()                      { return new PeerResult(false, "?", "timeout"); }
    }

    private HNSBroadcaster() {}
}