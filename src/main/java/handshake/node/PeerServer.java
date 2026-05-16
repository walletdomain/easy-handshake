package handshake.node;

import handshake.database.Database;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Listens for inbound brontide connections from other Handshake nodes.
 *
 * When a remote peer connects to us:
 *   1. We perform the brontide handshake as the RESPONDER
 *   2. We exchange VERSION / VERACK
 *   3. We serve their requests: GETDATA (blocks), GETHEADERS, PING → PONG
 *
 * This is what makes us a full peer node that other nodes can sync from,
 * rather than just a client that downloads data.
 *
 * Usage:
 *   PeerServer server = new PeerServer(nodeIdentity, db, 44806);
 *   server.start(); // non-blocking, runs in background threads
 *   // ... later:
 *   server.stop();
 */
public class PeerServer {

    private static final int MAX_INBOUND_PEERS = 8;
    private static final int LISTEN_PORT       = 44806;

    private final NodeIdentity identity;
    private final Database          db;
    private final int               port;
    private final AtomicBoolean     running = new AtomicBoolean(false);
    private final ExecutorService   pool    =
            Executors.newFixedThreadPool(MAX_INBOUND_PEERS + 1);

    private ServerSocket serverSocket;

    public PeerServer(NodeIdentity identity, Database db, int port) {
        this.identity = identity;
        this.db       = db;
        this.port     = port;
    }

    public PeerServer(NodeIdentity identity, Database db) {
        this(identity, db, LISTEN_PORT);
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start() throws Exception {
        serverSocket = new ServerSocket(port);
        running.set(true);
        pool.submit(this::acceptLoop);
        System.out.println("[PeerServer] Listening for inbound connections on port "
                + port);
    }

    public void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        pool.shutdown();
        System.out.println("[PeerServer] Stopped.");
    }

    // -------------------------------------------------------------------------
    // Accept loop
    // -------------------------------------------------------------------------

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                String remoteIp = socket.getInetAddress().getHostAddress();
                System.out.println("[PeerServer] Inbound connection from " + remoteIp);
                pool.submit(() -> handleInbound(socket, remoteIp));
            } catch (Exception e) {
                if (running.get())
                    System.out.println("[PeerServer] Accept error: " + e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Handle one inbound peer connection
    // -------------------------------------------------------------------------

    private void handleInbound(Socket socket, String remoteIp) {
        try {
            socket.setSoTimeout(30_000);
            InputStream  in  = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // ---- Brontide handshake (RESPONDER side) ----

            BrontideState brontide = new BrontideState(identity.privateKey());
            brontide.init();

            // Receive Act One (80 bytes)
            byte[] actOne = readExact(in, BrontideState.ACT_ONE_SIZE);
            if (!brontide.recvActOne(actOne)) {
                System.out.println("[PeerServer] " + remoteIp
                        + ": Act One failed — closing.");
                socket.close();
                return;
            }

            // Send Act Two (80 bytes)
            byte[] actTwo = brontide.genActTwo();
            out.write(actTwo);
            out.flush();

            // Receive Act Three (65 bytes)
            byte[] actThree = readExact(in, BrontideState.ACT_THREE_SIZE);
            if (!brontide.recvActThree(actThree)) {
                System.out.println("[PeerServer] " + remoteIp
                        + ": Act Three failed — closing.");
                socket.close();
                return;
            }

            byte[] remotePub = brontide.getRemoteStaticPub();
            System.out.println("[PeerServer] " + remoteIp
                    + " brontide OK. RemotePub: " + bytesToHex(remotePub, 8) + "...");

            // ---- P2P handshake ----

            HNSPeer peer = new HNSPeer(socket, in, out, brontide, remoteIp);
            peer.handshakeAsResponder(db.getTipHeight());

            System.out.println("[PeerServer] " + remoteIp
                    + " P2P handshake complete. agent=" + peer.getPeerAgent());

            // ---- Serve requests ----

            serveRequests(peer, remoteIp);

        } catch (Exception e) {
            System.out.println("[PeerServer] " + remoteIp
                    + " disconnected: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // Request serving loop
    // -------------------------------------------------------------------------

    private void serveRequests(HNSPeer peer, String remoteIp) throws Exception {
        System.out.println("[PeerServer] Serving " + remoteIp);

        while (true) {
            HNSMessage.Message msg = peer.readMessage();

            switch (msg.type) {

                case HNSMessage.TYPE_PING:
                    peer.handlePing(msg.payload);
                    break;

                case HNSMessage.TYPE_GETDATA:
                    handleGetData(peer, msg.payload);
                    break;

                case HNSMessage.TYPE_GETHEADERS:
                    handleGetHeaders(peer, msg.payload);
                    break;

                case HNSMessage.TYPE_GETADDR:
                    // Send empty ADDR for now — we don't maintain a peer list yet
                    peer.send(HNSMessage.TYPE_ADDR, encodeEmptyAddr());
                    break;

                case HNSMessage.TYPE_SENDHEADERS:
                case HNSMessage.TYPE_SENDCMPCT:
                case HNSMessage.TYPE_INV:
                case HNSMessage.TYPE_VERACK:
                    // Silently ignore
                    break;

                default:
                    // Unknown message — ignore but keep connection alive
                    break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // GETDATA handler — send requested blocks
    // -------------------------------------------------------------------------

    private void handleGetData(HNSPeer peer, byte[] payload) throws Exception {
        if (payload.length < 1) return;

        long[] vi     = HNSPeer.decodeVarint(payload, 0);
        int    count  = (int) vi[0];
        int    pos    = (int) vi[1];

        int sent     = 0;
        int notFound = 0;

        for (int i = 0; i < count && pos + 5 <= payload.length; i++) {
            int  invType = payload[pos] & 0xFF; pos++; // 1 byte type
            byte[] hash  = Arrays.copyOfRange(payload, pos, pos + 32); pos += 32;

            // We only serve blocks (invType == 2)
            if (invType != HNSPeer.INV_BLOCK) continue;

            int height = db.getHeightForHash(hash);
            if (height < 0) {
                notFound++;
                continue;
            }

            byte[] rawBlock = db.getRawBlock(height);
            if (rawBlock == null) {
                notFound++;
                continue;
            }

            // Send BLOCK message
            peer.send(HNSMessage.TYPE_BLOCK, rawBlock);
            sent++;
        }

        if (notFound > 0) {
            // Send NOTFOUND for items we couldn't serve
            // (simplified: send one NOTFOUND for the whole request)
            System.out.println("[PeerServer] GETDATA: sent=" + sent
                    + " notfound=" + notFound);
        }
    }

    // -------------------------------------------------------------------------
    // GETHEADERS handler — send up to 2000 headers from the locator
    // -------------------------------------------------------------------------

    private void handleGetHeaders(HNSPeer peer, byte[] payload) throws Exception {
        if (payload.length < 5) return;

        // Parse: version(4) + locatorCount(varint) + locator hashes + stopHash(32)
        int pos = 4; // skip version
        long[] vi    = HNSPeer.decodeVarint(payload, pos);
        int locCount = (int) vi[0];
        pos          = (int) vi[1];

        // Find the highest locator hash we know
        int startHeight = 0;
        for (int i = 0; i < locCount && pos + 32 <= payload.length; i++) {
            byte[] locHash = Arrays.copyOfRange(payload, pos, pos + 32); pos += 32;
            int h = db.getHeightForHash(locHash);
            if (h >= 0) {
                startHeight = h + 1;
                break;
            }
        }

        // Build headers response (up to 2000)
        int tipHeight = db.getTipHeight();
        int endHeight = Math.min(startHeight + 2000, tipHeight + 1);

        // Count headers
        int headerCount = Math.max(0, endHeight - startHeight);
        byte[] varint   = HNSPeer.encodeVarint(headerCount);

        int totalSize = varint.length + headerCount * 236;
        byte[] response = new byte[totalSize];
        int rpos = 0;
        System.arraycopy(varint, 0, response, rpos, varint.length);
        rpos += varint.length;

        for (int h = startHeight; h < endHeight; h++) {
            byte[] raw = db.getHeaderAtHeight(h);
            if (raw == null) break;
            System.arraycopy(raw, 0, response, rpos, 236);
            rpos += 236;
        }

        peer.send(HNSMessage.TYPE_HEADERS, Arrays.copyOf(response, rpos));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static byte[] readExact(InputStream in, int n) throws Exception {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) throw new Exception("Connection closed while reading "
                    + n + " bytes (got " + read + ")");
            read += r;
        }
        return buf;
    }

    private static byte[] encodeEmptyAddr() {
        return new byte[]{0}; // varint(0) — empty address list
    }

    private static String bytesToHex(byte[] b, int maxBytes) {
        int len = Math.min(b.length, maxBytes);
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }
}