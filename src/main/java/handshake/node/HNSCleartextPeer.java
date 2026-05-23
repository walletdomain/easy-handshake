package handshake.node;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Manages a cleartext P2P session with a Handshake peer on port 12038.
 *
 * Wire format (from lib/net/parser.js):
 *   header: magic(4 LE) + type(1) + size(4 LE) = 9 bytes
 *   payload: size bytes
 *
 * This is identical to the brontide session AFTER the encrypted handshake,
 * but without any encryption layer. The same message types apply.
 *
 * Mainnet magic: 0x5B759153 (1533997779 decimal, little-endian on wire)
 */
public class HNSCleartextPeer {

    // Mainnet magic: genesis.main.magic = 1533997779 = 0x5B759153
    // In little-endian wire format: 53 91 75 5B
    public static final int  MAINNET_MAGIC   = 1533997779;
    public static final int  CLEARTEXT_PORT  = 12038;
    public static final int  HEADER_SIZE     = 9; // magic(4)+type(1)+size(4)
    public static final long MAX_MESSAGE     = 8_000_000;

    private final Seed          seed;
    private final Socket        socket;
    private final InputStream   in;
    private final OutputStream  out;

    public HNSCleartextPeer(Seed seed, Socket socket) throws Exception {
        this.seed   = seed;
        this.socket = socket;
        this.in     = socket.getInputStream();
        this.out    = socket.getOutputStream();
    }

    // ── VERSION/VERACK handshake ──────────────────────────────────────────────

    /**
     * Performs the P2P handshake:
     *   us → VERSION
     *   peer → VERSION
     *   us → VERACK
     *   peer → VERACK
     *
     * Also drains common post-handshake messages (SENDCMPCT, SENDHEADERS etc.)
     */
    public void handshake() throws Exception {
        sendVersion(0);

        // Read messages until we get VERACK from the peer
        boolean gotVersion = false;
        boolean gotVerack  = false;
        int attempts = 0;

        while ((!gotVersion || !gotVerack) && attempts < 10) {
            attempts++;
            Message msg = readMessage();
            if (msg == null) continue;

            switch (msg.type) {
                case HNSMessage.TYPE_VERSION:
                    gotVersion = true;
                    sendVerack();
                    break;
                case HNSMessage.TYPE_VERACK:
                    gotVerack = true;
                    break;
                case HNSMessage.TYPE_PING:
                    sendPong(msg.payload);
                    break;
                default:
                    // drain other messages
                    break;
            }
        }

        if (!gotVersion || !gotVerack)
            throw new Exception("Handshake incomplete after " + attempts + " messages");
    }

    // ── Message I/O ───────────────────────────────────────────────────────────

    public void send(int type, byte[] payload) throws Exception {
        byte[] header = new byte[HEADER_SIZE];
        // magic (4 bytes LE)
        header[0] = (byte)(MAINNET_MAGIC & 0xFF);
        header[1] = (byte)((MAINNET_MAGIC >>  8) & 0xFF);
        header[2] = (byte)((MAINNET_MAGIC >> 16) & 0xFF);
        header[3] = (byte)((MAINNET_MAGIC >> 24) & 0xFF);
        // type (1 byte)
        header[4] = (byte)(type & 0xFF);
        // size (4 bytes LE)
        int size = payload != null ? payload.length : 0;
        header[5] = (byte)( size        & 0xFF);
        header[6] = (byte)((size >>  8) & 0xFF);
        header[7] = (byte)((size >> 16) & 0xFF);
        header[8] = (byte)((size >> 24) & 0xFF);

        out.write(header);
        if (payload != null && payload.length > 0)
            out.write(payload);
        out.flush();
    }

    public Message readMessage() throws Exception {
        // Read 9-byte header
        byte[] header = readExact(HEADER_SIZE);

        // Verify magic
        int magic = ByteBuffer.wrap(header, 0, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (magic != MAINNET_MAGIC)
            throw new Exception(String.format(
                    "Invalid magic: 0x%08X (expected 0x%08X)", magic, MAINNET_MAGIC));

        int type = header[4] & 0xFF;
        int size = ByteBuffer.wrap(header, 5, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (size < 0 || size > MAX_MESSAGE)
            throw new Exception("Message too large: " + size);

        byte[] payload = size > 0 ? readExact(size) : new byte[0];
        return new Message(type, payload);
    }

    private byte[] readExact(int n) throws Exception {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) throw new Exception("Connection closed");
            read += r;
        }
        return buf;
    }

    // ── Send helpers ──────────────────────────────────────────────────────────

    public void sendVersion(int ourHeight) throws Exception {
        byte[] remoteIp  = HNSMessage.parseIpv4(seed.ipAddress());
        byte[] remotePub = new byte[33]; // zero key for cleartext peer
        byte[] payload   = HNSMessage.buildVersion(
                remoteIp, CLEARTEXT_PORT, remotePub,
                ourHeight, "/hsd:8.0.0/easy-handshake/");
        send(HNSMessage.TYPE_VERSION, payload);
    }

    public void sendVerack() throws Exception {
        send(HNSMessage.TYPE_VERACK, new byte[0]);
    }

    public void sendPong(byte[] pingPayload) throws Exception {
        send(HNSMessage.TYPE_PONG, pingPayload);
    }

    public void sendTx(byte[] rawTx) throws Exception {
        send(HNSMessage.TYPE_TX, rawTx);
    }

    public void sendInv(List<byte[]> txHashes) throws Exception {
        byte[] payload = HNSMempool.buildInvTx(txHashes);
        send(HNSMessage.TYPE_INV, payload);
    }

    public void sendGetData(List<byte[]> txHashes) throws Exception {
        byte[] payload = HNSMempool.buildGetDataTx(txHashes);
        send(HNSMessage.TYPE_GETDATA, payload);
    }

    public void close() {
        try { socket.close(); } catch (Exception ignored) {}
    }

    // ── Block header sync ─────────────────────────────────────────────────────

    /**
     * Sends GETHEADERS and reads the HEADERS response.
     * Mirrors HNSPeer.syncHeaders() but using cleartext framing.
     */
    public List<HNSPeer.BlockHeader> syncHeaders(
            List<byte[]> locator, byte[] stopHash) throws Exception {

        byte[] payload = buildGetHeaders(locator, stopHash);
        send(HNSMessage.TYPE_GETHEADERS, payload);

        // Drain until we get HEADERS
        socket.setSoTimeout(15_000);
        for (int i = 0; i < 20; i++) {
            Message msg = readMessage();
            if (msg.type == HNSMessage.TYPE_HEADERS)
                return parseHeaders(msg.payload);
            if (msg.type == HNSMessage.TYPE_PING)
                sendPong(msg.payload);
            // drain others
        }
        throw new Exception("No HEADERS response");
    }

    private byte[] buildGetHeaders(List<byte[]> locator, byte[] stop) {
        // version(4) + varint(count) + hashes + stop(32)
        byte[] countVarint = HNSMempool.encodeVarint(locator.size());
        int size = 4 + countVarint.length + locator.size() * 32 + 32;
        byte[] buf = new byte[size];
        int pos = 0;
        putU32LE(buf, pos, HNSMessage.PROTOCOL_VERSION); pos += 4;
        System.arraycopy(countVarint, 0, buf, pos, countVarint.length);
        pos += countVarint.length;
        for (byte[] h : locator) {
            System.arraycopy(h, 0, buf, pos, 32); pos += 32;
        }
        if (stop != null) System.arraycopy(stop, 0, buf, pos, 32);
        else Arrays.fill(buf, pos, pos + 32, (byte) 0);
        return buf;
    }

    private List<HNSPeer.BlockHeader> parseHeaders(byte[] payload) throws Exception {
        List<HNSPeer.BlockHeader> headers = new ArrayList<>();
        if (payload == null || payload.length == 0) return headers;
        int pos = 0;
        // varint count
        int count = (int)(payload[pos++] & 0xFF);
        if (count >= 0xFD) {
            count = (payload[pos] & 0xFF) | ((payload[pos+1] & 0xFF) << 8);
            pos += 2;
        }
        for (int i = 0; i < count && pos + HNSPeer.HEADER_SIZE <= payload.length; i++) {
            byte[] raw = Arrays.copyOfRange(payload, pos, pos + HNSPeer.HEADER_SIZE);
            headers.add(HNSPeer.BlockHeader.parse(raw, 0));
            pos += HNSPeer.HEADER_SIZE;
        }
        return headers;
    }

    // ── Transaction broadcast via INV→GETDATA→TX ──────────────────────────────

    /**
     * Announces a transaction via INV, waits for GETDATA, sends TX.
     * Mirrors HNSBroadcaster.sendToPeer() but for cleartext connections.
     */
    public boolean broadcastTx(byte[] txidBytes, byte[] rawTx,
                               int timeoutMs) throws Exception {
        sendInv(List.of(txidBytes));

        socket.setSoTimeout(timeoutMs);
        try {
            while (true) {
                Message msg = readMessage();
                if (msg.type == HNSMessage.TYPE_GETDATA) {
                    sendTx(rawTx);
                    return true;
                } else if (msg.type == HNSMessage.TYPE_PING) {
                    sendPong(msg.payload);
                }
                // drain SENDCMPCT etc.
            }
        } catch (java.net.SocketTimeoutException e) {
            // Peer didn't request it — may already have it
            return false;
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    public Seed getSeed()   { return seed; }
    public boolean isOpen() { return !socket.isClosed(); }

    private static void putU32LE(byte[] buf, int pos, long v) {
        buf[pos]   = (byte)( v        & 0xFF);
        buf[pos+1] = (byte)((v >>  8) & 0xFF);
        buf[pos+2] = (byte)((v >> 16) & 0xFF);
        buf[pos+3] = (byte)((v >> 24) & 0xFF);
    }

    public static class Message {
        public final int    type;
        public final byte[] payload;
        Message(int type, byte[] payload) {
            this.type = type; this.payload = payload;
        }
    }
}