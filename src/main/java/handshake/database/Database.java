package handshake.database;

import handshake.node.HNSBlock;
import handshake.node.HNSPeer;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Embedded key-value database using H2 MVStore.
 *
 * MVStore is the storage engine inside the H2 jar — no extra dependency needed.
 * It provides LevelDB-style storage with built-in LZ4 compression, giving
 * storage comparable to HSD's LevelDB backend (~3-5 GB vs 90+ GB with H2 SQL).
 *
 * Key design: uses Long and String keys (not byte[]) to avoid needing a
 * custom byte-array comparator in MVStore, which simplifies the API greatly.
 *
 * Maps:
 *   "headers"    Long(height)       → byte[236] raw header
 *   "hashes"     String(hexHash)    → Long(height)      reverse lookup
 *   "chainwork"  Long(height)       → byte[32] chainwork
 *   "blocks"     Long(height)       → byte[] raw block
 *   "utxo"       String(hexOutpoint)→ byte[] coin        unspent only
 *   "meta"       String key         → byte[] value
 */
public class Database implements AutoCloseable {

    // Map names
    private static final String MAP_HEADERS   = "headers";
    private static final String MAP_HASHES    = "hashes";
    private static final String MAP_CHAINWORK = "chainwork";
    private static final String MAP_BLOCKS    = "blocks";
    private static final String MAP_UTXO      = "utxo";
    private static final String MAP_META      = "meta";

    // Meta keys
    private static final String META_BLOCK_TIP  = "block_tip";
    private static final String META_HEADER_TIP = "header_tip";
    private static final String META_SCHEMA_VER = "schema_ver";

    private static final int SCHEMA_VERSION = 1;

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    private final MVStore             store;
    private final MVMap<Long, byte[]> headers;
    private final MVMap<String, Long> hashes;
    private final MVMap<Long, byte[]> chainwork;
    private final MVMap<Long, byte[]> blocks;
    private final MVMap<String, byte[]> utxo;
    private final MVMap<String, byte[]> meta;

    // Whether to store full raw block bytes (disable for minimal footprint)
    private final boolean storeBlocks;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /** Opens database with default settings (stores full blocks). */
    public Database(String path) {
        this(path, true);
    }

    /**
     * Opens database with configurable block storage.
     *
     * @param path        file path without extension
     * @param storeBlocks if false, raw block bytes are not stored (minimal mode).
     *                    UTXO set and headers are always stored.
     *                    Set false to minimize disk usage (~500 MB total).
     *                    Set true to serve historical blocks to peers (~20-40 GB).
     */
    public Database(String path, boolean storeBlocks) {
        this.storeBlocks = storeBlocks;
        File dir = new File(path).getParentFile();
        if (dir != null && !dir.exists()) dir.mkdirs();

        this.store = new MVStore.Builder()
                .fileName(path)
                .compress()
                .open();

        // Auto-commit every 1 second in the background
        this.store.setAutoCommitDelay(1000);

        this.headers   = store.openMap(MAP_HEADERS);
        this.hashes    = store.openMap(MAP_HASHES);
        this.chainwork = store.openMap(MAP_CHAINWORK);
        this.blocks    = store.openMap(MAP_BLOCKS);
        this.utxo      = store.openMap(MAP_UTXO);
        this.meta      = store.openMap(MAP_META);

        if (!meta.containsKey(META_SCHEMA_VER)) {
            meta.put(META_SCHEMA_VER, intToBytes(SCHEMA_VERSION));
            store.commit();
        }
    }

    // -------------------------------------------------------------------------
    // Header operations
    // -------------------------------------------------------------------------

    /**
     * Inserts parsed BlockHeader objects starting at startHeight.
     * Already-stored heights are skipped (idempotent).
     */
    public void insertHeaders(List<HNSPeer.BlockHeader> blockHeaders,
                              int startHeight) {
        BigInteger prevWork = BigInteger.ZERO;
        if (startHeight > 0) {
            byte[] pw = chainwork.get((long)(startHeight - 1));
            if (pw != null) prevWork = new BigInteger(1, pw);
        }

        int tipHeight = startHeight - 1;

        for (int i = 0; i < blockHeaders.size(); i++) {
            long height = startHeight + i;
            if (headers.containsKey(height)) {
                byte[] cw = chainwork.get(height);
                if (cw != null) prevWork = new BigInteger(1, cw);
                tipHeight = (int) height;
                continue;
            }

            byte[] raw  = blockHeaders.get(i).raw();
            headers.put(height, raw);

            // hash → height reverse index
            byte[] hash = computeHeaderHash(raw);
            hashes.put(toHex(hash), height);

            // accumulate chainwork
            long bits = readBitsFromHeader(raw);
            prevWork  = prevWork.add(blockWork(bits));
            chainwork.put(height, toBytes32(prevWork));

            tipHeight = (int) height;
        }

        Long currentTip = bytesToLong(meta.get(META_HEADER_TIP));
        if (tipHeight > currentTip)
            meta.put(META_HEADER_TIP, longToBytes(tipHeight));

        store.commit();
    }

    /** Returns the highest stored header height, or -1. */
    public int getTipHeight() {
        return (int) bytesToLong(meta.get(META_HEADER_TIP));
    }

    /** Returns total number of stored headers. */
    public long getHeaderCount() {
        return headers.sizeAsLong();
    }

    /** Returns raw 236-byte header at height, or null. */
    public byte[] getHeaderAtHeight(int height) {
        return headers.get((long) height);
    }

    /** Returns the block hash at height, or null. */
    public byte[] getHashAtHeight(int height) {
        byte[] raw = headers.get((long) height);
        return raw != null ? computeHeaderHash(raw) : null;
    }

    /** Returns the height for the given block hash, or -1. */
    public int getHeightForHash(byte[] hash) {
        Long h = hashes.get(toHex(hash));
        return h != null ? h.intValue() : -1;
    }

    // -------------------------------------------------------------------------
    // Block operations
    // -------------------------------------------------------------------------

    /**
     * Stores a full block, updates the UTXO set, and advances the block tip.
     */
    public void insertBlock(int height, HNSBlock block, byte[] rawBytes) {
        if (storeBlocks)
            blocks.put((long) height, rawBytes);
        updateUtxos(block);
        advanceBlockTip(height);
        store.commit();
    }

    /** Returns raw block bytes at height, or null. */
    public byte[] getRawBlock(int height) {
        return blocks.get((long) height);
    }

    /**
     * Returns the highest *contiguous* block height stored, or -1.
     * Updated atomically in insertBlock() — O(1) lookup, gap-safe.
     */
    public int getBlockDataTip() {
        return (int) bytesToLong(meta.get(META_BLOCK_TIP));
    }

    // -------------------------------------------------------------------------
    // UTXO operations
    // -------------------------------------------------------------------------

    private void updateUtxos(HNSBlock block) {
        for (HNSBlock.Tx tx : block.txs) {
            // Remove spent outputs
            for (HNSBlock.Input input : tx.inputs) {
                if (isZeroHash(input.prevHash)) continue;
                utxo.remove(outpointKey(input.prevHash, (int) input.prevIndex));
            }
            // Add new unspent outputs
            byte[] txid = computeTxId(tx);
            for (int i = 0; i < tx.outputs.size(); i++)
                utxo.put(outpointKey(txid, i), encodeCoin(tx.outputs.get(i)));
        }
    }

    /** Returns coin bytes for an unspent output, or null if spent. */
    public byte[] getUtxo(byte[] txHash, int outputIndex) {
        return utxo.get(outpointKey(txHash, outputIndex));
    }

    /** Returns the total number of UTXOs in the set. */
    public long getUtxoCount() {
        return utxo.sizeAsLong();
    }

    // -------------------------------------------------------------------------
    // Median time
    // -------------------------------------------------------------------------

    public long getMedianTime(int height) {
        List<Long> times = new ArrayList<>();
        for (int h = Math.max(0, height - 10); h <= height; h++) {
            byte[] raw = headers.get((long) h);
            if (raw != null) times.add(readTimeFromHeader(raw));
        }
        if (times.isEmpty()) return 0;
        times.sort(Long::compareTo);
        return times.get(times.size() / 2);
    }

    // -------------------------------------------------------------------------
    // Contiguous tip tracking
    // -------------------------------------------------------------------------

    private void advanceBlockTip(int height) {
        int currentTip = getBlockDataTip();
        if (height <= currentTip) return;
        if (height == currentTip + 1) {
            int newTip = height;
            // When storing blocks, scan forward through existing entries
            // When not storing blocks, just advance by 1 (gap detection via tip only)
            if (storeBlocks)
                while (blocks.containsKey((long)(newTip + 1))) newTip++;
            meta.put(META_BLOCK_TIP, longToBytes(newTip));
        }
    }

    // -------------------------------------------------------------------------
    // Store info
    // -------------------------------------------------------------------------

    /**
     * Compacts the MVStore file by rewriting chunks with low fill rate.
     * Reclaims space accumulated during bulk writes.
     * Called periodically during sync by the DB writer thread.
     */
    public void compact() {
        store.commit();
        // compact(targetFillRate, maxWriteBytes)
        // 50% fill rate target, write up to 4 MB per call
        store.compact(50, 4 * 1024 * 1024);
    }

    public long getStoreSize() {
        return store.getFileStore() != null ? store.getFileStore().size() : 0;
    }

    public void commit() { store.commit(); }

    // -------------------------------------------------------------------------
    // Encoding helpers — keys
    // -------------------------------------------------------------------------

    /** Converts a byte array to its lowercase hex string (used as map key). */
    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * Outpoint key: hex(txid) + ":" + index
     * e.g. "deadbeef...00:0"
     */
    private static String outpointKey(byte[] txid, int index) {
        return toHex(txid) + ":" + index;
    }

    // -------------------------------------------------------------------------
    // Encoding helpers — values
    // -------------------------------------------------------------------------

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v>>>24),(byte)(v>>>16),(byte)(v>>>8),(byte)v};
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return b;
    }

    private static long bytesToLong(byte[] b) {
        if (b == null) return -1L;
        if (b.length == 4) // int stored as 4 bytes
            return ((b[0]&0xFFL)<<24)|((b[1]&0xFFL)<<16)|((b[2]&0xFFL)<<8)|(b[3]&0xFF);
        long v = 0;
        for (byte x : b) v = (v << 8) | (x & 0xFF);
        return v;
    }

    /** Encodes a coin (TxOutput) as compact bytes for UTXO storage. */
    private static byte[] encodeCoin(HNSBlock.Output out) {
        int hashLen = out.addrHash != null ? out.addrHash.length : 0;
        byte[] coin = new byte[8 + 2 + hashLen + 1];
        long v = out.value;
        for (int i = 0; i < 8; i++) { coin[i] = (byte)(v & 0xFF); v >>= 8; }
        coin[8] = (byte) out.addrVersion;
        coin[9] = (byte) hashLen;
        if (hashLen > 0) System.arraycopy(out.addrHash, 0, coin, 10, hashLen);
        coin[10 + hashLen] = (byte)(out.covenant != null ? out.covenant.type : 0);
        return coin;
    }

    /** Computes txid = Blake2b-256 of the base (non-witness) tx bytes. */
    private static byte[] computeTxId(HNSBlock.Tx tx) {
        int witnessSize = 0;
        for (HNSBlock.Witness w : tx.witnesses) witnessSize += w.size;
        byte[] base = Arrays.copyOf(tx.raw, tx.raw.length - witnessSize);
        return handshake.node.crypto.CryptoUtils.blake2b256(base);
    }

    /** Returns true if all bytes in hash are zero (coinbase prevout). */
    private static boolean isZeroHash(byte[] hash) {
        if (hash == null || hash.length == 0) return true;
        for (byte b : hash) if (b != 0) return false;
        return true;
    }

    // -------------------------------------------------------------------------
    // Header field readers
    // -------------------------------------------------------------------------

    /** Reads `bits` (4 bytes LE) at offset 200 in a 236-byte header. */
    private static long readBitsFromHeader(byte[] raw) {
        // Layout: nonce(4)+extraNonce(24)+version(4)+prevBlock(32)+merkleRoot(32)
        //         +witnessRoot(32)+treeRoot(32)+reservedRoot(32)+time(8)+bits(4)+mask(32)
        //         = 4+24+4+32+32+32+32+32+8 = 200 before bits
        int off = 200;
        return  (raw[off]   & 0xFFL)
                | ((raw[off+1] & 0xFFL) <<  8)
                | ((raw[off+2] & 0xFFL) << 16)
                | ((raw[off+3] & 0xFFL) << 24);
    }

    /** Reads `time` (8 bytes LE) at offset 192 in a 236-byte header. */
    private static long readTimeFromHeader(byte[] raw) {
        int off = 192; // 4+24+4+32+32+32+32+32 = 192
        long t = 0;
        for (int i = 0; i < 8; i++) t |= (raw[off + i] & 0xFFL) << (8 * i);
        return t;
    }

    /** Computes the block powHash from a raw 236-byte header. */
    private static byte[] computeHeaderHash(byte[] raw) {
        return HNSPeer.BlockHeader.parse(raw, 0).hash();
    }

    // -------------------------------------------------------------------------
    // Chainwork
    // -------------------------------------------------------------------------

    /** Work = 2^256 / (target + 1), matching HSD's implementation. */
    public static BigInteger blockWork(long bits) {
        int exponent  = (int)((bits >> 24) & 0xFF);
        long mantissa = bits & 0x7FFFFFL;
        if (mantissa == 0) return BigInteger.ZERO;
        BigInteger target = BigInteger.valueOf(mantissa).shiftLeft(8*(exponent-3));
        if (target.signum() <= 0) return BigInteger.ZERO;
        return BigInteger.ONE.shiftLeft(256).divide(target.add(BigInteger.ONE));
    }

    private static byte[] toBytes32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        if (raw.length >= 32) System.arraycopy(raw, raw.length-32, out, 0, 32);
        else                  System.arraycopy(raw, 0, out, 32-raw.length, raw.length);
        return out;
    }

    // -------------------------------------------------------------------------
    // AutoCloseable
    // -------------------------------------------------------------------------

    @Override
    public void close() {
        if (!store.isClosed()) store.close();
    }
}