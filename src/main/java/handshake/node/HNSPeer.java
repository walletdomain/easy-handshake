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
 * Manages the post-brontide P2P session with a single Handshake peer.
 *
 * Responsibilities:
 *   - version/verack handshake (establishes the P2P session)
 *   - ping/pong keep-alive
 *   - getheaders / headers sync (downloads block headers)
 *
 * Usage:
 *   Peer      brontidePeer  = HNSPeerManager.selectBestPeer(peers);
 *   HNSPeer   p             = new HNSPeer(brontidePeer, brontideState);
 *   p.handshake();
 *   List<HNSPeer.BlockHeader> headers = p.syncAllHeaders(List.of(HNSPeer.GENESIS_HASH));
 */
public class HNSPeer {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static final String USER_AGENT          = "/easyhandshakewallet:0.1/";
    public  static final int    MAX_HEADERS_RESULTS = 2000;
    private static final int    READ_TIMEOUT_MS     = 60_000;

    /** Mainnet genesis block hash. */
    public static final byte[] GENESIS_HASH = {
            (byte)0x5b,(byte)0x6e,(byte)0xf2,(byte)0xd3,(byte)0xc1,(byte)0xf3,(byte)0xcd,(byte)0xca,
            (byte)0xdf,(byte)0xd9,(byte)0xa0,(byte)0x30,(byte)0xba,(byte)0x18,(byte)0x11,(byte)0xef,
            (byte)0xdd,(byte)0x17,(byte)0x74,(byte)0x0f,(byte)0x14,(byte)0xe1,(byte)0x66,(byte)0x48,
            (byte)0x97,(byte)0x60,(byte)0x74,(byte)0x1d,(byte)0x07,(byte)0x59,(byte)0x92,(byte)0xe0
    };

    /** All-zero stop hash for getheaders — means fetch as many as possible. */
    public static final byte[] ZERO_HASH = new byte[32];

    // -------------------------------------------------------------------------
    // Block header field sizes
    // -------------------------------------------------------------------------

    public static final int HEADER_SIZE = 236; // consensus.HEADER_SIZE
    public static final int NONCE_SIZE  = 24;  // consensus.NONCE_SIZE (extraNonce)

    // -------------------------------------------------------------------------
    // InvItem types — full protocol vocabulary kept for future mempool/wallet use
    // -------------------------------------------------------------------------

    @SuppressWarnings("unused") public static final int INV_TX             = 1;
    public static final int INV_BLOCK          = 2;
    @SuppressWarnings("unused") public static final int INV_FILTERED_BLOCK = 3;
    @SuppressWarnings("unused") public static final int INV_CMPCT_BLOCK    = 4;
    @SuppressWarnings("unused") public static final int INV_CLAIM          = 5;
    @SuppressWarnings("unused") public static final int INV_AIRDROP        = 6;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    public final Peer          peer;
    private final BrontideState brontide;
    private final InputStream   in;
    private final OutputStream  out;

    private boolean versionSent     = false;
    private boolean versionReceived = false;
    private boolean verackSent      = false;
    private boolean verackReceived  = false;

    private int    peerHeight = 0;
    private String peerAgent  = "";

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public HNSPeer(Peer peer, BrontideState brontide) throws Exception {
        if (!brontide.isReady())
            throw new IllegalStateException(
                    "BrontideState must be ready before creating HNSPeer.");
        this.peer     = peer;
        this.brontide = brontide;
        peer.socket.setSoTimeout(READ_TIMEOUT_MS);
        this.in       = peer.socket.getInputStream();
        this.out      = peer.socket.getOutputStream();
    }

    /**
     * Constructor for INBOUND connections (we are the responder).
     * The brontide handshake has already been completed by PeerServer.
     */
    public HNSPeer(Socket socket, java.io.InputStream in,
                   java.io.OutputStream out,
                   BrontideState brontide, String remoteIp) throws Exception {
        // Create a minimal Peer wrapper for the inbound socket
        this.peer     = new Peer(socket, remoteIp);
        this.brontide = brontide;
        this.in       = in;
        this.out      = out;
        socket.setSoTimeout(READ_TIMEOUT_MS);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * VERSION/VERACK handshake for INBOUND connections (we are the responder).
     * We wait for the initiator's VERSION first, then send ours.
     *
     * @param ourHeight our current chain tip height to advertise
     */
    public void handshakeAsResponder(int ourHeight) throws Exception {
        long deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;

        // Initiator sends VERSION first — wait for it
        while (!versionReceived) {
            if (System.currentTimeMillis() > deadline)
                throw new Exception("Responder handshake timed out waiting for VERSION.");
            handleHandshakeMessage(readMessage());
        }

        // Send our VERSION and VERACK
        sendVersion(ourHeight);
        send(HNSMessage.TYPE_VERACK, new byte[0]);
        verackSent = true;

        // Wait for their VERACK
        while (isHandshakePending()) {
            if (System.currentTimeMillis() > deadline)
                throw new Exception("Responder handshake timed out waiting for VERACK.");
            handleHandshakeMessage(readMessage());
        }
    }

    public void handshake() throws Exception {
        sendVersion();
        long deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;
        while (isHandshakePending()) {
            if (System.currentTimeMillis() > deadline)
                throw new Exception("Version handshake timed out.");
            handleHandshakeMessage(readMessage());
        }
        System.out.printf("  [%s] P2P OK (%s h=%d)%n",
                peer.seed.ipAddress(), peerAgent, peerHeight);
    }

    /**
     * Sends a SENDHEADERS message, asking the peer to announce new blocks
     * via HEADERS instead of INV messages.
     */
    public void sendSendHeaders() throws Exception {
        send(HNSMessage.TYPE_SENDHEADERS, HNSMessage.buildSendHeaders());
    }

    /**
     * Sends a GETHEADERS request and waits for the HEADERS response.
     *
     * @param locator  list of known block hashes, most recent first.
     *                 Use List.of(GENESIS_HASH) when starting from scratch.
     * @param stopHash stop at this hash, or ZERO_HASH to fetch as many as possible
     * @return up to 2000 block headers
     */
    public List<BlockHeader> getHeaders(List<byte[]> locator,
                                        byte[] stopHash) throws Exception {
        sendGetHeaders(locator, stopHash);
        long deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;
        while (true) {
            if (System.currentTimeMillis() > deadline)
                throw new Exception("getHeaders timed out.");
            HNSMessage.Message msg = readMessage();
            switch (msg.type) {
                case HNSMessage.TYPE_HEADERS:
                    return parseHeaders(msg.payload);
                case HNSMessage.TYPE_PING:
                    handlePing(msg.payload);
                    break;
                default:
                    // silently ignore unexpected messages while waiting for HEADERS
            }
        }
    }

    /**
     * Syncs all headers from the given locator to the chain tip by repeatedly
     * calling getHeaders() until fewer than MAX_HEADERS_RESULTS are returned.
     *
     * @param startLocator initial locator (e.g. List.of(GENESIS_HASH))
     * @return all headers from the locator to the chain tip
     */
    public List<BlockHeader> syncAllHeaders(List<byte[]> startLocator) throws Exception {
        List<BlockHeader> all     = new ArrayList<>();
        List<byte[]>      locator = new ArrayList<>(startLocator);
        int batch = 0;

        System.out.println("  [" + peer.seed.ipAddress() + "] Starting header sync...");

        while (true) {
            List<BlockHeader> batchHeaders = getHeaders(locator, ZERO_HASH);
            if (batchHeaders.isEmpty()) break;

            all.addAll(batchHeaders);
            batch++;
            System.out.printf("  [%s] Batch %d: %d headers, total %d%n",
                    peer.seed.ipAddress(), batch,
                    batchHeaders.size(), all.size());

            if (batchHeaders.size() < MAX_HEADERS_RESULTS) break; // reached tip

            // Advance locator to the last received header's hash
            locator = List.of(batchHeaders.getLast().hash());
        }

        System.out.println("  [" + peer.seed.ipAddress()
                + "] Header sync complete. Total: " + all.size());
        return all;
    }

    /**
     * Sends a GETDATA request for a single block and waits for the BLOCK response.
     *
     * @param blockHash the 32-byte hash of the block to request
     * @return the parsed HNSBlock
     */
    @SuppressWarnings("unused") // used by wallet and on-demand block fetch (planned)
    public HNSBlock getBlock(byte[] blockHash) throws Exception {
        send(HNSMessage.TYPE_GETDATA, buildGetData(List.of(blockHash)));

        long deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;
        while (true) {
            if (System.currentTimeMillis() > deadline)
                throw new Exception("getBlock timed out.");
            HNSMessage.Message msg = readMessage();
            switch (msg.type) {
                case HNSMessage.TYPE_BLOCK:
                    return HNSBlock.parse(msg.payload);
                case HNSMessage.TYPE_NOTFOUND:
                    throw new Exception("Peer returned NOTFOUND for block: "
                            + bytesToHex(blockHash));
                case HNSMessage.TYPE_PING:
                    handlePing(msg.payload);
                    break;
                default:
                    // silently ignore unexpected messages while waiting for BLOCK
            }
        }
    }

    /**
     * Syncs full blocks for a range of heights, fetching each one by hash.
     * The hashes must be pre-fetched (e.g. from the local header database).
     *
     * Calls blockConsumer for each block as it arrives so the caller can
     * store or process blocks without buffering all of them in memory.
     *
     * @param blockHashes ordered list of block hashes to fetch
     * @param startHeight height of blockHashes.get(0) — used for logging only
     * @param blockConsumer called with (height, block) for each received block
     */
    public void syncBlocks(List<byte[]> blockHashes, int startHeight,
                           BlockConsumer blockConsumer) throws Exception {
        final int BATCH = 128;
        int total = blockHashes.size();

        // Drain any messages buffered since the version handshake
        // (SENDCMPCT, INV, etc.) before sending the first GETDATA
        drainPendingMessages();

        for (int base = 0; base < total; base += BATCH) {
            int end = Math.min(base + BATCH, total);
            List<byte[]> batch = blockHashes.subList(base, end);

            send(HNSMessage.TYPE_GETDATA, buildGetData(batch));

            int needed = end - base;
            int received = 0;
            long deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;

            while (received < needed) {
                if (System.currentTimeMillis() > deadline)
                    throw new Exception("syncBlocks timed out at height "
                            + (startHeight + base + received));
                HNSMessage.Message msg = readMessage();
                switch (msg.type) {
                    case HNSMessage.TYPE_BLOCK: {
                        HNSBlock block = HNSBlock.parse(msg.payload);
                        int height = startHeight + base + received;

                        // Validate: hash the received block header and compare
                        // against the expected hash from our trusted header chain.
                        BlockHeader receivedHeader = BlockHeader.parse(block.header, 0);
                        byte[] actualHash   = receivedHeader.hash();
                        byte[] expectedHash = blockHashes.get(base + received);
                        if (!Arrays.equals(actualHash, expectedHash)) {
                            throw new SecurityException(
                                    "Block hash mismatch at height " + height
                                            + ": expected " + bytesToHex(expectedHash)
                                            + " got "      + bytesToHex(actualHash));
                        }

                        blockConsumer.accept(height, block);
                        received++;
                        deadline = System.currentTimeMillis() + READ_TIMEOUT_MS;
                        if (height % 1000 == 0)
                            System.out.printf("  [%s] Block %d synced%n",
                                    peer.seed.ipAddress(), height);
                        break;
                    }
                    case HNSMessage.TYPE_NOTFOUND:
                        throw new Exception("Peer returned NOTFOUND at height "
                                + (startHeight + base));
                    case HNSMessage.TYPE_PING:
                        handlePing(msg.payload);
                        break;
                    default:
                        // Silently consume unsolicited messages (SENDCMPCT, INV, etc.)
                        // The nonce is correctly incremented by readMessage() for all types
                        break;
                }
            }
            // No drain between chunks — drainPendingMessages() with a timeout
            // can cause nonce desync if a partial message arrives during the drain.
            // All unsolicited messages are handled inline by the default case above.
        }
        System.out.println("  [" + peer.seed.ipAddress()
                + "] Block sync complete. Synced " + total + " blocks.");
    }

    /**
     * Functional interface for processing a block as it arrives,
     * avoiding the need to buffer all blocks in memory.
     */
    @FunctionalInterface
    public interface BlockConsumer {
        void accept(int height, HNSBlock block) throws Exception;
    }

    /**
     * Sends GETADDR and collects peer addresses from the ADDR response.
     *
     * NetAddress wire format (88 bytes each):
     *   time(8 LE) + services(4 LE) + hiServices(4 LE) +
     *   addrType(1) + raw(16) + reserved(20) + port(2 LE) + key(33)
     *
     * Only returns addresses that have a non-zero brontide key so we can
     * connect with full encryption.
     *
     * @param maxWait ms to wait for ADDR response before giving up
     * @return list of discovered peers as Seed objects
     */
    @SuppressWarnings("unused") // used by peer discovery (planned)
    public List<Seed> requestMorePeers(int maxWait) throws Exception {
        send(HNSMessage.TYPE_GETADDR, new byte[0]);

        List<Seed> discovered = new ArrayList<>();
        long deadline = System.currentTimeMillis() + maxWait;

        while (System.currentTimeMillis() < deadline) {
            HNSMessage.Message msg = readMessage();
            if (msg.type == HNSMessage.TYPE_ADDR) {
                discovered.addAll(parseAddrPayload(msg.payload));
                break; // one ADDR response is enough
            }
            if (msg.type == HNSMessage.TYPE_PING) handlePing(msg.payload);
            // ignore everything else while waiting
        }
        return discovered;
    }

    /**
     * Parses an ADDR payload into a list of Seed objects.
     * Each NetAddress entry is 88 bytes. Entries with a zero key are skipped
     * since we require brontide encryption for all connections.
     */
    private static List<Seed> parseAddrPayload(byte[] payload) {
        List<Seed> seeds = new ArrayList<>();
        if (payload.length < 1) return seeds;

        // Read varint count
        long[] vi = decodeVarint(payload, 0);
        int count = (int) vi[0];
        int pos   = (int) vi[1];

        @SuppressWarnings("MismatchedReadAndWriteOfArray") // intentional read-only zero sentinel
        byte[] ZERO_KEY = new byte[33]; // all zeros = no brontide key

        for (int i = 0; i < count && pos + 88 <= payload.length; i++) {
            // time(8) + services(4) + hiServices(4) = 16 bytes
            pos += 16;

            // addrType(1): 0 = IPv4, 1 = IPv6
            int addrType = payload[pos] & 0xFF; pos++;

            // raw(16): IPv4 is last 4 bytes if type=0
            byte[] raw = Arrays.copyOfRange(payload, pos, pos + 16); pos += 16;

            // reserved(20)
            pos += 20;

            // port(2 LE)
            int port = ((payload[pos] & 0xFF))
                    | ((payload[pos+1] & 0xFF) << 8);
            pos += 2;

            // key(33)
            byte[] key = Arrays.copyOfRange(payload, pos, pos + 33);
            pos += 33;

            // Skip IPv6 addresses and entries without a brontide key
            if (addrType != 0) continue;
            if (Arrays.equals(key, ZERO_KEY)) continue;
            if (port == 0) continue;

            // Extract IPv4 from last 4 bytes of raw
            // hsd stores IPv4 as ::ffff:x.x.x.x (last 4 bytes are the IPv4)
            String ip = (raw[12] & 0xFF) + "." + (raw[13] & 0xFF) + "."
                    + (raw[14] & 0xFF) + "." + (raw[15] & 0xFF);

            // Encode key as base32 for Seed
            String keyBase32 = base32Encode(key);
            seeds.add(new Seed(keyBase32, ip, port));
        }
        return seeds;
    }

    /** Base32 encoder (RFC 4648, a-z2-7) for brontide key encoding. */
    @SuppressWarnings("DuplicatedCode") // same algorithm in NodeIdentity — kept separate for independence
    private static String base32Encode(byte[] data) {
        final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0)
            sb.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        return sb.toString();
    }

    public void drainPendingMessages() {
        int savedTimeout;
        try {
            savedTimeout = peer.socket.getSoTimeout();
            peer.socket.setSoTimeout(500);
        } catch (Exception e) {
            return;
        }
        try {
            long deadline = System.currentTimeMillis() + 200;
            while (System.currentTimeMillis() < deadline) {
                HNSMessage.Message msg = readMessage();
                if (msg.type == HNSMessage.TYPE_PING)
                    handlePing(msg.payload);
                // all other queued messages are silently consumed
            }
        } catch (java.net.SocketTimeoutException e) {
            // expected — stream is empty
        } catch (Exception e) {
            // stream error — caller will catch on next real read
        } finally {
            try { peer.socket.setSoTimeout(savedTimeout); } catch (Exception ignored) {}
        }
    }

    public int    getPeerHeight() { return peerHeight; }
    public String getPeerAgent()  { return peerAgent;  }

    // -------------------------------------------------------------------------
    // Send helpers
    // -------------------------------------------------------------------------

    private void sendVersion() throws Exception {
        sendVersion(0);
    }

    private void sendVersion(int ourHeight) throws Exception {
        byte[] remoteIp  = peer.seed != null
                ? HNSMessage.parseIpv4(peer.seed.ipAddress())
                : new byte[4];
        byte[] remotePub = new byte[33]; // zero key
        byte[] payload   = HNSMessage.buildVersion(
                remoteIp,
                peer.seed != null ? peer.seed.port() : 44806,
                remotePub, ourHeight, USER_AGENT);
        send(HNSMessage.TYPE_VERSION, payload);
        versionSent = true;
    }

    private void sendVerack() throws Exception {
        send(HNSMessage.TYPE_VERACK, HNSMessage.buildVerack());
        verackSent = true;
    }

    private void sendGetHeaders(List<byte[]> locator, byte[] stopHash) throws Exception {
        send(HNSMessage.TYPE_GETHEADERS, buildGetHeaders(locator, stopHash));
    }

    void handlePing(byte[] payload) throws Exception {
        send(HNSMessage.TYPE_PONG, HNSMessage.buildPong(HNSMessage.parsePing(payload)));
    }

    void send(int type, byte[] payload) throws Exception {
        byte[] framed    = HNSMessage.frame(type, payload);
        byte[] encrypted = brontide.encryptMessage(framed);
        out.write(encrypted);
        out.flush();
    }

    // -------------------------------------------------------------------------
    // Receive helpers
    // -------------------------------------------------------------------------

    HNSMessage.Message readMessage() throws Exception {
        // Read 20-byte brontide transport header: encLen(4 LE) + lenTag(16)
        byte[] header = in.readNBytes(BrontideState.HEADER_SIZE);
        if (header.length != BrontideState.HEADER_SIZE)
            throw new Exception("Connection closed while reading header.");

        int bodyLen = brontide.decryptHeader(header);
        if (bodyLen < 0 || bodyLen > HNSMessage.MAX_MESSAGE + HNSMessage.HEADER_SIZE + 16)
            throw new Exception("Invalid body length: " + bodyLen);

        byte[] body = in.readNBytes(bodyLen + 16);
        if (body.length != bodyLen + 16)
            throw new Exception("Connection closed while reading body.");

        return HNSMessage.parse(brontide.decryptBody(body));
    }

    // -------------------------------------------------------------------------
    // Handshake state machine
    // -------------------------------------------------------------------------

    private void handleHandshakeMessage(HNSMessage.Message msg) throws Exception {
        switch (msg.type) {
            case HNSMessage.TYPE_VERSION: {
                HNSMessage.VersionInfo info = HNSMessage.parseVersion(msg.payload);
                peerHeight = info.height;
                peerAgent  = info.agent;
                versionReceived = true;
                sendVerack();
                break;
            }
            case HNSMessage.TYPE_VERACK:
                verackReceived = true;
                break;
            case HNSMessage.TYPE_PING:
                handlePing(msg.payload);
                break;
            default:
                System.out.println("  [" + peer.seed.ipAddress()
                        + "] Ignoring " + msg.typeName() + " during handshake");
        }
    }

    private boolean isHandshakePending() {
        return !(versionSent && versionReceived && verackSent && verackReceived);
    }

    // -------------------------------------------------------------------------
    // Payload builders
    // -------------------------------------------------------------------------

    /**
     * Builds a GETDATA payload for a list of block hashes.
     * Wire format (same as InvPacket):
     *   varint(count) + (type:4 LE + hash:32) * count
     */
    private static byte[] buildGetData(List<byte[]> hashes) {
        byte[] countVarint = encodeVarint(hashes.size());
        byte[] buf = new byte[countVarint.length + 36 * hashes.size()];
        int pos = 0;
        System.arraycopy(countVarint, 0, buf, pos, countVarint.length);
        pos += countVarint.length;
        for (byte[] hash : hashes) {
            buf[pos]   = (byte) INV_BLOCK; // type = 2 LE uint32
            buf[pos+1] = 0;
            buf[pos+2] = 0;
            buf[pos+3] = 0;
            pos += 4;
            System.arraycopy(hash, 0, buf, pos, 32);
            pos += 32;
        }
        return buf;
    }

    /**
     * Builds a GETHEADERS payload (same format as GETBLOCKS — GetBlocksPacket.write):
     *   locatorCount  varint
     *   locator[i]    bytes[32]  (most recent first)
     *   stopHash      bytes[32]
     */
    private static byte[] buildGetHeaders(List<byte[]> locator, byte[] stopHash) {
        byte[] countVarint = encodeVarint(locator.size());
        byte[] buf = new byte[countVarint.length + (32 * locator.size()) + 32];
        int pos = 0;
        System.arraycopy(countVarint, 0, buf, pos, countVarint.length);
        pos += countVarint.length;
        for (byte[] hash : locator) {
            System.arraycopy(hash, 0, buf, pos, 32);
            pos += 32;
        }
        System.arraycopy(stopHash, 0, buf, pos, 32);
        return buf;
    }

    // -------------------------------------------------------------------------
    // Header parsing
    // -------------------------------------------------------------------------

    /**
     * Parses a HEADERS payload (HeadersPacket.read):
     *   count        varint
     *   headers[i]   BlockHeader (HEADER_SIZE bytes each)
     */
    private static List<BlockHeader> parseHeaders(byte[] payload) {
        List<BlockHeader> result = new ArrayList<>();
        int pos = 0;

        long[] varint = decodeVarint(payload, pos);
        int count = (int) varint[0];
        pos += (int) varint[1];

        if (count > MAX_HEADERS_RESULTS)
            throw new IllegalArgumentException("Too many headers: " + count);

        for (int i = 0; i < count; i++) {
            if (pos + HEADER_SIZE > payload.length)
                throw new IllegalArgumentException("Payload truncated at header " + i);
            result.add(BlockHeader.parse(payload, pos));
            pos += HEADER_SIZE;
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // BlockHeader
    // -------------------------------------------------------------------------

    /**
     * A parsed Handshake block header (236 bytes).
     *
     * Wire layout (AbstractBlock.writeHead — abstractblock.js):
     *   Preheader:
     *     nonce        uint32 LE    4
     *     time         uint64 LE    8
     *     prevBlock    bytes[32]   32
     *     treeRoot     bytes[32]   32
     *   Subheader:
     *     extraNonce   bytes[24]   24   (NONCE_SIZE = 24)
     *     reservedRoot bytes[32]   32
     *     witnessRoot  bytes[32]   32
     *     merkleRoot   bytes[32]   32
     *     version      uint32 LE    4
     *     bits         uint32 LE    4
     *   Mask:
     *     mask         bytes[32]   32
     *   Total: 236 bytes
     *
     * Block hash algorithm (abstractblock.js powHash / shareHash):
     *   subHead    = extraNonce || reservedRoot || witnessRoot || merkleRoot
     *                || version || bits          (128 bytes)
     *   subHash    = blake2b256(subHead)
     *   maskHash   = blake2b256(prevBlock || mask)
     *   commitHash = blake2b256(subHash || maskHash)
     *   preHead    = nonce || time || padding(20) || prevBlock || treeRoot
     *                || commitHash                (128 bytes)
     *   left       = blake2b512(preHead)          (64 bytes)
     *   right      = sha3_256(preHead || padding(8))  (32 bytes)
     *   shareHash  = blake2b256(left || padding(32) || right)
     *   powHash    = shareHash XOR mask
     *
     * padding(n) = prevBlock[i%32] XOR treeRoot[i%32]  for i = 0..n-1
     */
    public static class BlockHeader {

        public final long   nonce;
        public final long   time;
        public final byte[] prevBlock;
        public final byte[] treeRoot;
        public final byte[] extraNonce;
        public final byte[] reservedRoot;
        public final byte[] witnessRoot;
        public final byte[] merkleRoot;
        public final int    version;
        public final int    bits;
        public final byte[] mask;

        private final byte[] raw; // preserved 236-byte header

        /** Returns the raw 236-byte header bytes. */
        public byte[] raw() { return raw; }

        public BlockHeader(long nonce, long time,
                           byte[] prevBlock,    byte[] treeRoot,
                           byte[] extraNonce,   byte[] reservedRoot,
                           byte[] witnessRoot,  byte[] merkleRoot,
                           int version, int bits, byte[] mask,
                           byte[] raw) {
            this.nonce        = nonce;
            this.time         = time;
            this.prevBlock    = prevBlock;
            this.treeRoot     = treeRoot;
            this.extraNonce   = extraNonce;
            this.reservedRoot = reservedRoot;
            this.witnessRoot  = witnessRoot;
            this.merkleRoot   = merkleRoot;
            this.version      = version;
            this.bits         = bits;
            this.mask         = mask;
            this.raw          = raw;
        }

        /** Returns a copy of the raw 236-byte header for storage. */
        @SuppressWarnings("unused") // used by database serialisation (planned)
        public byte[] toBytes() { return raw.clone(); }

        /**
         * Computes the block hash (powHash).
         * Verified correct against the genesis block.
         */
        public byte[] hash() {
            // Step 1: subHead (128 bytes)
            byte[] subHead = new byte[128];
            ByteBuffer sb = ByteBuffer.wrap(subHead).order(ByteOrder.LITTLE_ENDIAN);
            sb.put(extraNonce);
            sb.put(reservedRoot);
            sb.put(witnessRoot);
            sb.put(merkleRoot);
            sb.putInt(version);
            sb.putInt(bits);

            // Step 2: subHash = blake2b256(subHead)
            byte[] subHash = Blake2b.hash(subHead, 32);

            // Step 3: maskHash = blake2b256(prevBlock || mask)
            byte[] pm = new byte[64];
            System.arraycopy(prevBlock, 0, pm, 0,  32);
            System.arraycopy(mask,      0, pm, 32, 32);
            byte[] maskHash = Blake2b.hash(pm, 32);

            // Step 4: commitHash = blake2b256(subHash || maskHash)
            byte[] sm = new byte[64];
            System.arraycopy(subHash,  0, sm, 0,  32);
            System.arraycopy(maskHash, 0, sm, 32, 32);
            byte[] commitHash = Blake2b.hash(sm, 32);

            // Step 5: preHead (128 bytes)
            byte[] preHead = new byte[128];
            ByteBuffer pb = ByteBuffer.wrap(preHead).order(ByteOrder.LITTLE_ENDIAN);
            pb.putInt((int) nonce);
            pb.putLong(time);
            pb.put(padding(20));
            pb.put(prevBlock);
            pb.put(treeRoot);
            pb.put(commitHash);

            // Step 6: left = blake2b512(preHead) — 64 bytes
            byte[] left = Blake2b.hash(preHead, 64);

            // Step 7: right = sha3_256(preHead || padding(8)) — 32 bytes
            byte[] preHeadPad8 = new byte[128 + 8];
            System.arraycopy(preHead,  0, preHeadPad8, 0,   128);
            System.arraycopy(padding(8), 0, preHeadPad8, 128, 8);
            byte[] right = Keccak256.hash(preHeadPad8);

            // Step 8: shareHash = blake2b256(left || padding(32) || right)
            byte[] lpr = new byte[64 + 32 + 32];
            System.arraycopy(left,        0, lpr, 0,  64);
            System.arraycopy(padding(32), 0, lpr, 64, 32);
            System.arraycopy(right,       0, lpr, 96, 32);
            byte[] shareHash = Blake2b.hash(lpr, 32);

            // Step 9: powHash = shareHash XOR mask
            byte[] powHash = new byte[32];
            for (int i = 0; i < 32; i++)
                powHash[i] = (byte) (shareHash[i] ^ mask[i]);

            return powHash;
        }

        /**
         * Computes padding bytes: prevBlock[i%32] XOR treeRoot[i%32]
         */
        private byte[] padding(int size) {
            byte[] pad = new byte[size];
            for (int i = 0; i < size; i++)
                pad[i] = (byte) (prevBlock[i % 32] ^ treeRoot[i % 32]);
            return pad;
        }

        public static BlockHeader parse(byte[] data, int offset) {
            ByteBuffer buf = ByteBuffer.wrap(data, offset, HEADER_SIZE)
                    .order(ByteOrder.LITTLE_ENDIAN);

            long   nonce        = buf.getInt() & 0xFFFFFFFFL;
            long   time         = buf.getLong();
            byte[] prevBlock    = new byte[32]; buf.get(prevBlock);
            byte[] treeRoot     = new byte[32]; buf.get(treeRoot);
            byte[] extraNonce   = new byte[NONCE_SIZE]; buf.get(extraNonce);
            byte[] reservedRoot = new byte[32]; buf.get(reservedRoot);
            byte[] witnessRoot  = new byte[32]; buf.get(witnessRoot);
            byte[] merkleRoot   = new byte[32]; buf.get(merkleRoot);
            int    version      = buf.getInt();
            int    bits         = buf.getInt();
            byte[] mask         = new byte[32]; buf.get(mask);
            byte[] raw          = Arrays.copyOfRange(data, offset, offset + HEADER_SIZE);

            return new BlockHeader(nonce, time, prevBlock, treeRoot,
                    extraNonce, reservedRoot, witnessRoot, merkleRoot,
                    version, bits, mask, raw);
        }

        @Override
        public String toString() {
            return "BlockHeader{time=" + time
                    + ", bits=0x" + Integer.toHexString(bits)
                    + ", version=" + version
                    + ", hash=" + bytesToHex(hash()) + "}";
        }
    }

    // -------------------------------------------------------------------------
    // Varint encoding / decoding
    // -------------------------------------------------------------------------

    public static byte[] encodeVarint(long value) {
        if (value < 0xFDL) {
            return new byte[]{ (byte) value };
        } else if (value <= 0xFFFFL) {
            return new byte[]{
                    (byte) 0xFD,
                    (byte)  (value       & 0xFF),
                    (byte) ((value >> 8) & 0xFF)
            };
        } else if (value <= 0xFFFFFFFFL) {
            return new byte[]{
                    (byte) 0xFE,
                    (byte)  (value        & 0xFF),
                    (byte) ((value >>  8) & 0xFF),
                    (byte) ((value >> 16) & 0xFF),
                    (byte) ((value >> 24) & 0xFF)
            };
        } else {
            return new byte[]{
                    (byte) 0xFF,
                    (byte)  (value        & 0xFF),
                    (byte) ((value >>  8) & 0xFF),
                    (byte) ((value >> 16) & 0xFF),
                    (byte) ((value >> 24) & 0xFF),
                    (byte) ((value >> 32) & 0xFF),
                    (byte) ((value >> 40) & 0xFF),
                    (byte) ((value >> 48) & 0xFF),
                    (byte) ((value >> 56) & 0xFF)
            };
        }
    }

    public static long[] decodeVarint(byte[] buf, int offset) {
        int first = buf[offset] & 0xFF;
        if (first < 0xFD) {
            return new long[]{ first, 1 };
        } else if (first == 0xFD) {
            long v = (buf[offset+1] & 0xFFL)
                    | ((buf[offset+2] & 0xFFL) << 8);
            return new long[]{ v, 3 };
        } else if (first == 0xFE) {
            long v = (buf[offset+1] & 0xFFL)
                    | ((buf[offset+2] & 0xFFL) <<  8)
                    | ((buf[offset+3] & 0xFFL) << 16)
                    | ((buf[offset+4] & 0xFFL) << 24);
            return new long[]{ v, 5 };
        } else {
            long v = (buf[offset+1] & 0xFFL)
                    | ((buf[offset+2] & 0xFFL) <<  8)
                    | ((buf[offset+3] & 0xFFL) << 16)
                    | ((buf[offset+4] & 0xFFL) << 24)
                    | ((buf[offset+5] & 0xFFL) << 32)
                    | ((buf[offset+6] & 0xFFL) << 40)
                    | ((buf[offset+7] & 0xFFL) << 48)
                    | ((buf[offset+8] & 0xFFL) << 56);
            return new long[]{ v, 9 };
        }
    }

    // -------------------------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------------------------

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // BLAKE2b — pure Java, supports 32-byte (256-bit) and 64-byte (512-bit) output
    //
    // Test vectors (verified against bcrypto):
    //   blake2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    //   blake2b-256("abc") = bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
    //   blake2b-512("abc") = ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1
    //                        7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
    // -------------------------------------------------------------------------

    public static class Blake2b {

        private static final long[] IV = {
                0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
                0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
                0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        };

        private static final int[][] SIGMA = {
                { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
                {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
                {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
                { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
                { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
                { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
                {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
                {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
                { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
                {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
                { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
                {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
        };

        /**
         * Computes BLAKE2b hash with the given digest length (32 or 64 bytes).
         */
        public static byte[] hash(byte[] input, int digestLen) {
            long[] h = IV.clone();
            h[0] ^= 0x01010000L | digestLen; // parameter block

            int blockSize = 128;
            // Pad input to a multiple of blockSize; at least one block
            int numBlocks = Math.max(1, (input.length + blockSize - 1) / blockSize);
            byte[] padded = Arrays.copyOf(input, numBlocks * blockSize);

            for (int b = 0; b < numBlocks; b++) {
                long[] m  = new long[16];
                int    off = b * blockSize;
                for (int i = 0; i < 16; i++)
                    m[i] = leToLong(padded, off + i * 8);
                boolean isLast    = (b == numBlocks - 1);
                long    byteCount = isLast
                        ? (long) input.length
                        : (long)(b + 1) * blockSize;
                compress(h, m, byteCount, isLast);
            }

            byte[] digest = new byte[digestLen];
            for (int i = 0; i < digestLen; i++)
                digest[i] = (byte)((h[i / 8] >>> ((i % 8) * 8)) & 0xFF);
            return digest;
        }

        private static void compress(long[] h, long[] m,
                                     long byteCount, boolean isLast) {
            long[] v = new long[16];
            System.arraycopy(h,  0, v, 0, 8);
            System.arraycopy(IV, 0, v, 8, 8);
            v[12] ^= byteCount;
            if (isLast) v[14] ^= 0xFFFFFFFFFFFFFFFFL;

            for (int r = 0; r < 12; r++) {
                int[] s = SIGMA[r];
                G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
                G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
                G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
                G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
                G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
                G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
                G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
            }
            for (int i = 0; i < 8; i++)
                h[i] ^= v[i] ^ v[i + 8];
        }

        private static void G(long[] v, int a, int b, int c, int d,
                              long x, long y) {
            v[a] = v[a] + v[b] + x;
            v[d] = Long.rotateRight(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = Long.rotateRight(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = Long.rotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Long.rotateRight(v[b] ^ v[c], 63);
        }

        @SuppressWarnings("DuplicatedCode") // identical in Keccak256 — kept separate per class
        private static long leToLong(byte[] b, int off) {
            return (b[off  ] & 0xFFL)
                    | ((b[off+1] & 0xFFL) <<  8)
                    | ((b[off+2] & 0xFFL) << 16)
                    | ((b[off+3] & 0xFFL) << 24)
                    | ((b[off+4] & 0xFFL) << 32)
                    | ((b[off+5] & 0xFFL) << 40)
                    | ((b[off+6] & 0xFFL) << 48)
                    | ((b[off+7] & 0xFFL) << 56);
        }
    }

    // -------------------------------------------------------------------------
    // Keccak-256 (NIST SHA3-256 — uses 0x06 domain separation padding)
    //
    // Test vectors (verified against bcrypto sha3):
    //   sha3_256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    //   sha3_256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    // -------------------------------------------------------------------------

    public static class Keccak256 {

        private static final long[] RC = {
                0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL,
                0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
                0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL,
                0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
                0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
                0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
                0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L,
                0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        };

        private static final int[] RHO = {
                1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
                27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        private static final int[] PI = {
                10,  7, 11, 17, 18,  3,  5, 16,  8, 21,
                24,  4, 15, 23, 19, 13, 12,  2, 20, 14,
                22,  9,  6,  1
        };

        public static byte[] hash(byte[] input) {
            int rate      = 136;  // (1600 - 512) / 8 = 136 bytes for SHA3-256
            int outputLen = 32;

            // Padding: append 0x01, zero-pad to rate, set last byte |= 0x80
            int padded_len = input.length + 1;
            if (padded_len % rate != 0)
                padded_len += rate - (padded_len % rate);
            byte[] msg = Arrays.copyOf(input, padded_len);
            msg[input.length]  = 0x06;
            msg[padded_len - 1] |= (byte) 0x80;

            // Absorb
            long[] state = new long[25];
            for (int i = 0; i < msg.length / rate; i++) {
                for (int j = 0; j < rate / 8; j++) {
                    state[j] ^= leToLong(msg, i * rate + j * 8);
                }
                keccakF(state);
            }

            // Squeeze
            byte[] out = new byte[outputLen];
            for (int i = 0; i < outputLen; i++)
                out[i] = (byte)((state[i / 8] >>> ((i % 8) * 8)) & 0xFF);
            return out;
        }

        private static void keccakF(long[] a) {
            long[] c = new long[5];
            long[] d = new long[5];
            long[] b = new long[25];

            for (int round = 0; round < 24; round++) {
                // Theta
                for (int x = 0; x < 5; x++)
                    c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
                for (int x = 0; x < 5; x++)
                    d[x] = c[(x+4)%5] ^ Long.rotateLeft(c[(x+1)%5], 1);
                for (int x = 0; x < 5; x++)
                    for (int y = 0; y < 5; y++)
                        a[x + y*5] ^= d[x];

                // Rho and Pi
                long last = a[1];
                for (int i = 0; i < 24; i++) {
                    int j = PI[i];
                    long tmp = a[j];
                    a[j] = Long.rotateLeft(last, RHO[i]);
                    last = tmp;
                }

                // Chi
                for (int y = 0; y < 5; y++) {
                    //noinspection ManualArrayCopy — not a copy; saving values for XOR
                    for (int x = 0; x < 5; x++)
                        b[x] = a[x + y*5];
                    for (int x = 0; x < 5; x++)
                        a[x + y*5] = b[x] ^ (~b[(x+1)%5] & b[(x+2)%5]);
                }

                // Iota
                a[0] ^= RC[round];
            }
        }

        @SuppressWarnings("DuplicatedCode") // identical in Blake2b — kept separate per class
        private static long leToLong(byte[] b, int off) {
            return (b[off  ] & 0xFFL)
                    | ((b[off+1] & 0xFFL) <<  8)
                    | ((b[off+2] & 0xFFL) << 16)
                    | ((b[off+3] & 0xFFL) << 24)
                    | ((b[off+4] & 0xFFL) << 32)
                    | ((b[off+5] & 0xFFL) << 40)
                    | ((b[off+6] & 0xFFL) << 48)
                    | ((b[off+7] & 0xFFL) << 56);
        }
    }
}