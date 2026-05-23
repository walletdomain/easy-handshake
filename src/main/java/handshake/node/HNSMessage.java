package handshake.node;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Handshake P2P message framing.
 *
 * Wire format (framer.js):
 *   [ 4 bytes: magic (little-endian uint32) = 0x5B6EF2D3 ]
 *   [ 1 byte:  message type                              ]
 *   [ 4 bytes: payload length (little-endian uint32)     ]
 *   [ N bytes: payload                                   ]
 *
 * Total header = 9 bytes. No checksum.
 *
 * All messages are sent over the brontide encrypted transport, so
 * BrontideState.encryptMessage() must wrap each framed message before
 * sending, and BrontideState.decryptBody() must unwrap before parsing.
 *
 * Message types (from packets.js):
 *   VERSION=0, VERACK=1, PING=2, PONG=3, GETADDR=4, ADDR=5,
 *   INV=6, GETDATA=7, NOTFOUND=8, GETBLOCKS=9, GETHEADERS=10,
 *   HEADERS=11, SENDHEADERS=12, BLOCK=13, TX=14, REJECT=15,
 *   MEMPOOL=16, FILTERLOAD=17, FILTERADD=18, FILTERCLEAR=19,
 *   MERKLEBLOCK=20, FEEFILTER=21, SENDCMPCT=22, CMPCTBLOCK=23,
 *   GETBLOCKTXN=24, BLOCKTXN=25, GETPROOF=26, PROOF=27,
 *   CLAIM=28, AIRDROP=29, UNKNOWN=30
 */
// All message type constants and builder methods are part of the complete
// Handshake P2P protocol vocabulary. Unused ones are kept for future use
// by the mempool, DNS resolver, wallet, and mining components.
@SuppressWarnings("unused")
public class HNSMessage {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /** Mainnet magic number (little-endian 0x5B6EF2D3). */
    public static final int MAGIC = 0x5B6EF2D3;

    /** Frame header size: magic(4) + type(1) + length(4) = 9 bytes. */
    public static final int HEADER_SIZE = 9;

    /** Maximum allowed payload size (~8 MB, matching hsd MAX_MESSAGE). */
    public static final int MAX_MESSAGE = 8 * 1000 * 1000;

    /** Protocol version (common.js PROTOCOL_VERSION). */
    public static final int PROTOCOL_VERSION = 3;

    /** Minimum accepted protocol version (common.js MIN_VERSION). */
    public static final int MIN_VERSION = 1;

    /** Service bit: full network node. */
    public static final int SERVICE_NETWORK = 1;

    // -------------------------------------------------------------------------
    // Message types (packets.js types enum)
    // -------------------------------------------------------------------------

    public static final int TYPE_VERSION     = 0;
    public static final int TYPE_VERACK      = 1;
    public static final int TYPE_PING        = 2;
    public static final int TYPE_PONG        = 3;
    public static final int TYPE_GETADDR     = 4;
    public static final int TYPE_ADDR        = 5;
    public static final int TYPE_INV         = 6;
    public static final int TYPE_GETDATA     = 7;
    public static final int TYPE_NOTFOUND    = 8;
    public static final int TYPE_GETBLOCKS   = 9;
    public static final int TYPE_GETHEADERS  = 10;
    public static final int TYPE_HEADERS     = 11;
    public static final int TYPE_SENDHEADERS = 12;
    public static final int TYPE_BLOCK       = 13;
    public static final int TYPE_TX          = 14;
    public static final int TYPE_REJECT      = 15;
    public static final int TYPE_MEMPOOL     = 16;
    public static final int TYPE_FILTERLOAD  = 17;
    public static final int TYPE_FILTERADD   = 18;
    public static final int TYPE_FILTERCLEAR = 19;
    public static final int TYPE_MERKLEBLOCK = 20;
    public static final int TYPE_FEEFILTER   = 21;
    public static final int TYPE_SENDCMPCT   = 22;
    public static final int TYPE_CMPCTBLOCK  = 23;
    public static final int TYPE_GETBLOCKTXN = 24;
    public static final int TYPE_BLOCKTXN    = 25;
    public static final int TYPE_GETPROOF    = 26;
    public static final int TYPE_PROOF       = 27;
    public static final int TYPE_CLAIM       = 28;
    public static final int TYPE_AIRDROP     = 29;
    public static final int TYPE_UNKNOWN     = 30;

    /** Human-readable names for each message type, indexed by type number. */
    public static final String[] TYPE_NAMES = {
            "VERSION", "VERACK", "PING", "PONG", "GETADDR",
            "ADDR", "INV", "GETDATA", "NOTFOUND", "GETBLOCKS",
            "GETHEADERS", "HEADERS", "SENDHEADERS", "BLOCK", "TX",
            "REJECT", "MEMPOOL", "FILTERLOAD", "FILTERADD", "FILTERCLEAR",
            "MERKLEBLOCK", "FEEFILTER", "SENDCMPCT", "CMPCTBLOCK", "GETBLOCKTXN",
            "BLOCKTXN", "GETPROOF", "PROOF", "CLAIM", "AIRDROP", "UNKNOWN"
    };

    // -------------------------------------------------------------------------
    // Parsed message container
    // -------------------------------------------------------------------------

    /**
     * A parsed Handshake P2P message.
     */
    public static class Message {
        public final int    type;
        public final byte[] payload;

        public Message(int type, byte[] payload) {
            this.type    = type;
            this.payload = payload;
        }

        public String typeName() {
            if (type >= 0 && type < TYPE_NAMES.length)
                return TYPE_NAMES[type];
            return "UNKNOWN(" + type + ")";
        }

        @Override
        public String toString() {
            return "HNSMessage{type=" + typeName()
                    + ", payloadLen=" + payload.length + "}";
        }
    }

    // -------------------------------------------------------------------------
    // Framing — build a raw wire frame (before brontide encryption)
    // -------------------------------------------------------------------------

    /**
     * Frames a payload into a 9-byte-header wire message.
     * The result must be wrapped with BrontideState.encryptMessage() before
     * being written to the socket.
     *
     * @param type    message type (one of the TYPE_* constants)
     * @param payload serialized message payload (may be zero-length)
     * @return framed message bytes ready for encryption
     */
    public static byte[] frame(int type, byte[] payload) {
        if ((type & 0xFF) != type)
            throw new IllegalArgumentException("Message type must fit in 1 byte: " + type);
        if (payload.length > MAX_MESSAGE)
            throw new IllegalArgumentException("Payload too large: " + payload.length);

        byte[] msg = new byte[HEADER_SIZE + payload.length];
        ByteBuffer buf = ByteBuffer.wrap(msg).order(ByteOrder.LITTLE_ENDIAN);

        buf.putInt(MAGIC);               // 4 bytes, little-endian
        buf.put((byte) type);            // 1 byte
        buf.putInt(payload.length);      // 4 bytes, little-endian
        buf.put(payload);                // N bytes

        return msg;
    }

    // -------------------------------------------------------------------------
    // Parsing — parse a decrypted wire frame
    // -------------------------------------------------------------------------

    /**
     * Parses a decrypted wire frame into a Message.
     * The input must already be brontide-decrypted.
     *
     * @param  frame decrypted bytes (must be at least HEADER_SIZE bytes)
     * @return parsed Message
     * @throws IllegalArgumentException if the frame is malformed
     */
    public static Message parse(byte[] frame) {
        if (frame.length < HEADER_SIZE)
            throw new IllegalArgumentException(
                    "Frame too short: " + frame.length + " < " + HEADER_SIZE);

        ByteBuffer buf = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN);

        int magic = buf.getInt();
        if (magic != MAGIC)
            throw new IllegalArgumentException(
                    "Bad magic: 0x" + Integer.toHexString(magic)
                            + " expected 0x" + Integer.toHexString(MAGIC));

        int type       = buf.get() & 0xFF;
        int payloadLen = buf.getInt();

        if (payloadLen < 0 || payloadLen > MAX_MESSAGE)
            throw new IllegalArgumentException("Invalid payload length: " + payloadLen);
        if (frame.length < HEADER_SIZE + payloadLen)
            throw new IllegalArgumentException(
                    "Frame truncated: have " + frame.length
                            + " need " + (HEADER_SIZE + payloadLen));

        byte[] payload = Arrays.copyOfRange(frame, HEADER_SIZE, HEADER_SIZE + payloadLen);
        return new Message(type, payload);
    }

    // -------------------------------------------------------------------------
    // Payload builders
    // -------------------------------------------------------------------------

    /**
     * Builds a VERSION payload.
     *
     * Wire layout (from packets.js VersionPacket.write):
     *   version    uint32 LE   4
     *   services   uint32 LE   4
     *   hi_svc     uint32 LE   4  (always 0 — hi service bits unused)
     *   time       uint64 LE   8
     *   remote     NetAddress 88  (the peer's address as we see it)
     *   nonce      bytes[8]    8
     *   agentLen   uint8       1
     *   agent      ascii       N
     *   height     uint32 LE   4
     *   noRelay    uint8       1  (0 = relay txs, 1 = don't)
     *
     * @param remoteIp   the peer's IPv4 address as a 4-byte array
     * @param remotePort the peer's port
     * @param remotePub  the peer's 33-byte brontide public key
     * @param height     our current chain height (0 if unknown)
     * @param agent      our user agent string (e.g. "/easyhandshakewallet:0.1/")
     */
    public static byte[] buildVersion(byte[] remoteIp, int remotePort,
                                      byte[] remotePub, int height,
                                      String agent) {
        byte[] agentBytes = agent.getBytes(StandardCharsets.US_ASCII);
        if (agentBytes.length > 255)
            throw new IllegalArgumentException("Agent string too long (max 255 chars)");

        // NetAddress is always 88 bytes (netaddress.js getSize() = 88)
        int size = 4 + 4 + 4 + 8 + 88 + 8 + 1 + agentBytes.length + 4 + 1;
        byte[] payload = new byte[size];
        ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);

        // version, services, hi_services
        buf.putInt(PROTOCOL_VERSION);
        buf.putInt(SERVICE_NETWORK);
        buf.putInt(0);

        // time (Unix seconds)
        buf.putLong(System.currentTimeMillis() / 1000L);

        // remote NetAddress (88 bytes)
        // time(8) + services(4) + hi_svc(4) + type(1) + raw[16](IP padded)
        // + reserved[20] + port(2) + key[33]
        writeNetAddress(buf, remoteIp, remotePort, remotePub);

        // nonce (8 random bytes — we use zeros for simplicity)
        buf.put(new byte[8]);

        // agent
        buf.put((byte) agentBytes.length);
        buf.put(agentBytes);

        // height, noRelay
        buf.putInt(height);
        buf.put((byte) 0); // relay transactions

        return payload;
    }

    /**
     * Builds a VERACK payload (empty — verack has no payload).
     */
    public static byte[] buildVerack() {
        return new byte[0];
    }

    /**
     * Builds a PING payload.
     * @param nonce 8 random bytes
     */
    public static byte[] buildPing(byte[] nonce) {
        if (nonce.length != 8)
            throw new IllegalArgumentException("Ping nonce must be 8 bytes.");
        return nonce.clone();
    }

    /**
     * Builds a PONG payload (echoes the ping nonce).
     * @param pingNonce the 8-byte nonce from the received PING
     */
    public static byte[] buildPong(byte[] pingNonce) {
        if (pingNonce.length != 8)
            throw new IllegalArgumentException("Pong nonce must be 8 bytes.");
        return pingNonce.clone();
    }

    /**
     * Builds a GETADDR payload (empty — getaddr has no payload).
     */
    public static byte[] buildGetAddr() {
        return new byte[0];
    }

    /**
     * Builds a SENDHEADERS payload (empty — sendheaders has no payload).
     */
    public static byte[] buildSendHeaders() {
        return new byte[0];
    }

    // -------------------------------------------------------------------------
    // Payload parsers
    // -------------------------------------------------------------------------

    /**
     * Parses a VERSION payload.
     * Returns a VersionInfo record with the peer's advertised fields.
     */
    public static VersionInfo parseVersion(byte[] payload) {
        ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        int    version  = buf.getInt();
        int    services = buf.getInt();
        buf.getInt(); // hi service bits — unused
        long   time     = buf.getLong();
        buf.position(buf.position() + 88); // skip remote NetAddress
        byte[] nonce    = new byte[8];
        buf.get(nonce);
        int    agentLen = buf.get() & 0xFF;
        byte[] agentBytes = new byte[agentLen];
        buf.get(agentBytes);
        String agent    = new String(agentBytes, StandardCharsets.US_ASCII);
        int    height   = buf.getInt();
        boolean noRelay = buf.get() == 1;
        return new VersionInfo(version, services, time, nonce, agent, height, noRelay);
    }

    /**
     * Parses a PING payload and returns the 8-byte nonce.
     */
    public static byte[] parsePing(byte[] payload) {
        if (payload.length < 8)
            throw new IllegalArgumentException("Ping payload too short.");
        return Arrays.copyOf(payload, 8);
    }

    // -------------------------------------------------------------------------
    // VersionInfo — result of parseVersion()
    // -------------------------------------------------------------------------

    public static class VersionInfo {
        public final int     version;
        public final int     services;
        public final long    time;
        public final byte[]  nonce;
        public final String  agent;
        public final int     height;
        public final boolean noRelay;

        public VersionInfo(int version, int services, long time,
                           byte[] nonce, String agent,
                           int height, boolean noRelay) {
            this.version  = version;
            this.services = services;
            this.time     = time;
            this.nonce    = nonce;
            this.agent    = agent;
            this.height   = height;
            this.noRelay  = noRelay;
        }

        @Override
        public String toString() {
            return "VersionInfo{version=" + version
                    + ", agent=" + agent
                    + ", height=" + height
                    + ", services=" + services + "}";
        }
    }

    // -------------------------------------------------------------------------
    /**
     * Parses an ADDR message payload into a list of discovered peers.
     * Each NetAddress is 88 bytes:
     *   time(8) + services(4) + hi_svc(4) + type(1) + raw[16]
     *   + reserved[20] + port(2 LE) + key[33]
     *
     * @return list of [ip, port, keyHex] arrays
     */
    public static List<String[]> parseAddr(byte[] payload) {
        List<String[]> peers = new ArrayList<>();
        if (payload == null || payload.length < 1) return peers;
        int pos = 0;

        // Read varint count
        int count = payload[pos++] & 0xFF;
        if (count == 0xFD) {
            count = (payload[pos] & 0xFF) | ((payload[pos+1] & 0xFF) << 8);
            pos += 2;
        } else if (count == 0xFE || count == 0xFF) {
            return peers; // too large, skip
        }

        for (int i = 0; i < count && pos + 88 <= payload.length; i++) {
            // time(8) + services(4) + hi_svc(4) = 16 bytes
            pos += 16;
            // type(1)
            int type = payload[pos++] & 0xFF;
            // raw[16] — IPv4-mapped is last 4 bytes
            byte[] raw = Arrays.copyOfRange(payload, pos, pos + 16);
            pos += 16;
            // reserved[20]
            pos += 20;
            // port(2 LE)
            int port = (payload[pos] & 0xFF) | ((payload[pos+1] & 0xFF) << 8);
            pos += 2;
            // key[33]
            byte[] key = Arrays.copyOfRange(payload, pos, pos + 33);
            pos += 33;

            // Extract IPv4 address from raw bytes
            // IPv4-mapped: 10 zeros + FF FF + 4 IPv4 bytes
            String ip = null;
            if (type == 0) {
                // IPv4-mapped IPv6: last 4 bytes are the IPv4 address
                ip = String.format("%d.%d.%d.%d",
                        raw[12] & 0xFF, raw[13] & 0xFF,
                        raw[14] & 0xFF, raw[15] & 0xFF);
            }
            // Skip if invalid or loopback/private
            if (ip == null || ip.startsWith("0.") || ip.startsWith("127.")
                    || ip.startsWith("10.") || ip.startsWith("192.168.")
                    || ip.equals("0.0.0.0")) continue;

            // Check if key is non-zero (brontide peer)
            boolean hasKey = false;
            for (byte b : key) if (b != 0) { hasKey = true; break; }

            String keyHex = hasKey ? toHex(key) : "";
            peers.add(new String[]{ ip,
                    String.valueOf(port > 0 ? port : CLEARTEXT_PORT),
                    keyHex });
        }
        return peers;
    }

    private static final int CLEARTEXT_PORT = 12038;

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // NetAddress helper
    // -------------------------------------------------------------------------

    /**
     * Writes a 88-byte NetAddress into buf (netaddress.js write(bw) format):
     *   time(8) + services(4) + hi_svc(4) + type(1) + raw[16] + reserved[20]
     *   + port(2 LE) + key[33]
     *
     * raw[16] is the standard IPv4-mapped IPv6 format:
     *   10 zero bytes + 0xFF 0xFF + 4 IPv4 bytes
     * Verified from probe_version.js: port=12038 encodes as 06 2f (LE).
     *
     * @param buf         must have at least 88 bytes remaining
     * @param ipv4        4-byte IPv4 address
     * @param port        TCP port
     * @param brontideKey 33-byte compressed public key (or zeros if unknown)
     */
    private static void writeNetAddress(ByteBuffer buf,
                                        byte[] ipv4, int port,
                                        byte[] brontideKey) {
        // na.time = 0 (we don't track when we last saw this peer)
        buf.putLong(0L);
        // na.services = 0, na.hi_services = 0 (unknown for remote)
        buf.putInt(0);
        buf.putInt(0);
        // type (1 byte): 0 = IPv4
        buf.put((byte) 0);
        // raw[16]: IPv4-mapped IPv6 — 10 zero bytes + 0xFF 0xFF + 4 IPv4 bytes
        buf.put(new byte[10]);
        buf.put((byte) 0xFF);
        buf.put((byte) 0xFF);
        buf.put(ipv4);           // 4 bytes
        // reserved[20]
        buf.put(new byte[20]);
        // port (2 bytes, little-endian) — bufio writeU16 is LE
        buf.put((byte)  (port       & 0xFF));
        buf.put((byte) ((port >> 8) & 0xFF));
        // brontide key[33]
        if (brontideKey != null && brontideKey.length == 33)
            buf.put(brontideKey);
        else
            buf.put(new byte[33]); // zero key if unknown
    }

    /**
     * Parses a 4-byte dotted-decimal IPv4 string (e.g. "194.50.5.26")
     * into a 4-byte array suitable for writeNetAddress.
     */
    public static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4)
            throw new IllegalArgumentException("Not a valid IPv4 address: " + ip);
        byte[] raw = new byte[4];
        for (int i = 0; i < 4; i++)
            raw[i] = (byte) Integer.parseInt(parts[i]);
        return raw;
    }
}