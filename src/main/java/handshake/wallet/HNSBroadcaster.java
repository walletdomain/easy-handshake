package handshake.wallet;

import handshake.node.HNSPeer;
import handshake.node.HNSPeerManager;
import handshake.node.Peer;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Broadcasts a signed Handshake transaction to the P2P network.
 *
 * Strategy:
 *   1. Submit via relay node RPC (most reliable - enters real mempool gossip)
 *   2. Also broadcast directly via P2P to connected peers
 *
 * The relay node is a trusted hsd instance that accepts sendrawtransaction
 * and gossips it through the real mempool protocol (INV->GETDATA->TX).
 * Direct P2P sending of unsolicited TX messages is unreliable since
 * peers may ignore them without the proper INV announcement first.
 */
public class HNSBroadcaster {

    private static final int MAX_BROADCAST_PEERS = 4;
    private static final int MIN_SUCCESS_PEERS   = 1;
    private static final int CONNECT_TIMEOUT_MS  = 8_000;
    private static final int SEND_TIMEOUT_MS     = 10_000;

    // Relay node - trusted hsd instance for reliable mempool submission
    private static volatile String relayNodeUrl    = null;
    private static volatile String relayNodeApiKey = null;

    public static void setRelayNode(String url, String apiKey) {
        relayNodeUrl    = url;
        relayNodeApiKey = apiKey;
        System.out.printf("[HNSBroadcaster] Relay node configured: %s%n", url);
    }

    /**
     * Submits a raw transaction to a trusted hsd node via JSON-RPC.
     */
    static boolean submitViaRelay(byte[] rawTx) {
        String url    = relayNodeUrl;
        String apiKey = relayNodeApiKey;
        // Fallback to default relay if not configured
        if (url == null || url.isBlank()) {
            url    = "http://74.208.31.75:12037";
            apiKey = "cjmgFfqYKxL79n5hJCW2tBQvR4pduNr8";
        }
        try {
            String hex  = HNSTxBuilder.toHex(rawTx);
            String body = "{\"method\":\"sendrawtransaction\",\"params\":[\""
                    + hex + "\"],\"id\":1}";

            URL urlObj = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(3_000);
            conn.setReadTimeout(3_000);

            if (apiKey != null) {
                String creds = "x:" + apiKey;
                String auth  = Base64.getEncoder().encodeToString(
                        creds.getBytes(StandardCharsets.UTF_8));
                conn.setRequestProperty("Authorization", "Basic " + auth);
            }

            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            InputStream is = code < 400 ? conn.getInputStream()
                    : conn.getErrorStream();
            String response = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            System.out.printf("[HNSBroadcaster] Relay response (%d): %s%n",
                    code, response.length() > 120 ? response.substring(0, 120) : response);
            return code == 200 && !response.contains("\"error\":{\"message\"");
        } catch (Exception e) {
            System.out.printf("[HNSBroadcaster] Relay submission failed: %s%n",
                    e.getMessage());
            return false;
        }
    }

    // ── Main broadcast entry point ────────────────────────────────────────────

    public static BroadcastResult broadcast(HNSTxBuilder.SignedTx tx) {
        System.out.printf("[HNSBroadcaster] Broadcasting tx %s (%d bytes)%n",
                tx.txid, tx.raw.length);

        // Add to our local mempool first
        boolean addedToMempool = handshake.node.HNSMempool.get().addTx(tx.raw, tx.txid, false);
        if (addedToMempool)
            System.out.println("[HNSBroadcaster] Added to local mempool");

        // Submit via relay node — most reliable path into mempool gossip
        boolean relayOk = submitViaRelay(tx.raw);
        if (relayOk)
            System.out.println("[HNSBroadcaster] Relay node accepted tx");

        // Also broadcast directly via P2P using INV announcement
        // (more reliable than direct TX push — peers request what they want)
        List<Peer> peers;
        try {
            peers = HNSPeerManager.discoverPeers();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return BroadcastResult.failure("Interrupted while discovering peers");
        }

        if (peers.isEmpty() && !relayOk)
            return BroadcastResult.failure("No peers available and relay failed");

        List<Peer> targets = peers.isEmpty() ? List.of()
                : peers.subList(0, Math.min(MAX_BROADCAST_PEERS, peers.size()));

        ExecutorService exec = Executors.newFixedThreadPool(
                Math.max(1, targets.size()));
        List<Future<PeerResult>> futures = new ArrayList<>();
        for (Peer peer : targets)
            futures.add(exec.submit(() -> sendToPeer(peer, tx.raw)));

        exec.shutdown();
        try {
            exec.awaitTermination(SEND_TIMEOUT_MS + CONNECT_TIMEOUT_MS,
                    TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

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

        for (Peer p : targets) {
            try { p.socket.close(); } catch (Exception ignored) {}
        }

        boolean ok = relayOk || successes >= MIN_SUCCESS_PEERS;

        // Also broadcast to cleartext peers on port 12038
        int cleartextSuccesses = 0;
        try {
            List<handshake.node.HNSCleartextPeer> ctPeers =
                    handshake.node.HNSPeerManager.discoverCleartextPeers();
            byte[] txidBytes = computeTxid(tx.raw);
            List<handshake.node.HNSCleartextPeer> ctTargets =
                    ctPeers.subList(0, Math.min(MAX_BROADCAST_PEERS, ctPeers.size()));
            for (handshake.node.HNSCleartextPeer ctPeer : ctTargets) {
                try {
                    boolean sent = ctPeer.broadcastTx(txidBytes, tx.raw, 5_000);
                    if (sent) {
                        cleartextSuccesses++;
                        System.out.printf("[Broadcaster] [%s:12038] TX sent via cleartext%n",
                                ctPeer.getSeed().ipAddress());
                    }
                } catch (Exception e) {
                    System.out.printf("[Broadcaster] [%s:12038] failed: %s%n",
                            ctPeer.getSeed().ipAddress(), e.getMessage());
                } finally {
                    ctPeer.close();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        ok = ok || cleartextSuccesses > 0;
        System.out.printf("[HNSBroadcaster] Broadcast %s — relay=%s brontide=%d/%d cleartext=%d%n",
                ok ? "SUCCESS" : "FAILED",
                relayOk ? "OK" : "NO",
                successes, targets.size(), cleartextSuccesses);

        return new BroadcastResult(ok, successes, targets.size(), results, tx.txid);
    }

    // ── Per-peer send ─────────────────────────────────────────────────────────

    static PeerResult sendToPeer(Peer peer, byte[] rawTx) {
        String ip = peer.seed.ipAddress();
        try {
            peer.socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            System.out.printf("[Broadcaster] Connecting to %s...%n", ip);
            HNSPeer hnsPeer = new HNSPeer(peer, peer.brontide);
            hnsPeer.handshake();

            // Announce via INV — proper P2P mempool gossip protocol
            byte[] txidBytes = computeTxid(rawTx);
            byte[] invPayload = handshake.node.HNSMempool.buildInvTx(
                    List.of(txidBytes));
            hnsPeer.send(handshake.node.HNSMessage.TYPE_INV, invPayload);

            // Wait for GETDATA — drain other messages (SENDCMPCT, PING, etc.)
            peer.socket.setSoTimeout(5_000);
            try {
                while (true) {
                    handshake.node.HNSMessage.Message msg = hnsPeer.readMessage();
                    if (msg.type == handshake.node.HNSMessage.TYPE_GETDATA) {
                        hnsPeer.sendTx(rawTx);
                        System.out.printf("[Broadcaster] [%s] TX sent via INV->GETDATA->TX%n", ip);
                        break;
                    } else if (msg.type == handshake.node.HNSMessage.TYPE_PING) {
                        // respond to ping to keep connection alive
                        hnsPeer.send(handshake.node.HNSMessage.TYPE_PONG, msg.payload);
                    }
                    // silently drain SENDCMPCT, INV, etc.
                }
            } catch (java.net.SocketTimeoutException e) {
                System.out.printf("[Broadcaster] [%s] No GETDATA — peer may already have tx%n", ip);
            }

            return PeerResult.success(ip);
        } catch (Exception e) {
            System.out.printf("[Broadcaster] [%s] failed: %s%n", ip, e.getMessage());
            return PeerResult.error(ip, e.getMessage());
        }
    }

    /** Computes the txid (blake2b-256 of base tx) from raw tx bytes. */
    private static byte[] computeTxid(byte[] rawTx) {
        try {
            handshake.node.HNSBlock.Tx tx =
                    handshake.node.HNSBlock.Tx.parse(rawTx, 0);
            byte[] base = java.util.Arrays.copyOf(rawTx, tx.baseSize);
            return handshake.node.HNSPeer.Blake2b.hash(base, 32);
        } catch (Exception e) {
            return new byte[32];
        }
    }

    // ── Result types ──────────────────────────────────────────────────────────

    public static class BroadcastResult {
        public final boolean          success;
        public final int              peersAccepted;
        public final int              peersAttempted;
        public final List<PeerResult> peerResults;
        public final String           txid;
        public final String           errorMessage;

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

        static PeerResult success(String ip)           { return new PeerResult(true,  ip, null); }
        static PeerResult error(String ip, String msg) { return new PeerResult(false, ip, msg);  }
        static PeerResult error(String msg)            { return new PeerResult(false, "?", msg); }
        static PeerResult timeout()                    { return new PeerResult(false, "?", "timeout"); }
    }

    private HNSBroadcaster() {}
}