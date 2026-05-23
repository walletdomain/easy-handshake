package handshake.node;

import handshake.wallet.HNSTxBuilder;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory transaction mempool for Easy Handshake.
 *
 * Implements the core mempool functionality needed for:
 *   1. Storing pending transactions until they are mined
 *   2. Responding to P2P INV/GETDATA/MEMPOOL messages
 *   3. Announcing new transactions to connected peers via INV
 *   4. Feeding the miner with pending transactions (future)
 *
 * Wire protocol flow (from packets.js / mempool.js):
 *
 *   Receiving a tx from a peer:
 *     Peer → us: INV(type=TX, hash)
 *     Us → peer: GETDATA(type=TX, hash)
 *     Peer → us: TX(raw bytes)
 *     Us: add to mempool, announce via INV to other peers
 *
 *   Sending our tx to peers:
 *     Us: add tx to mempool
 *     Us → peers: INV(type=TX, hash)
 *     Peer → us: GETDATA(type=TX, hash)
 *     Us → peer: TX(raw bytes)
 *
 *   Responding to MEMPOOL message:
 *     Peer → us: MEMPOOL (empty payload)
 *     Us → peer: INV(all our tx hashes)
 *
 * Design decisions:
 *   - In-memory only (no persistence — txs re-enter when peers resend)
 *   - No orphan handling (inputs must exist on-chain)
 *   - No covenant validation (relies on relay node for that)
 *   - Max 5000 txs, evict oldest when full
 *   - Txs expire after 72 hours
 */
public class HNSMempool {

    private static final int    MAX_TXS       = 5000;
    private static final long   EXPIRY_MS     = 72 * 60 * 60 * 1000L; // 72 hours

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile HNSMempool instance;

    public static HNSMempool get() {
        if (instance == null) {
            synchronized (HNSMempool.class) {
                if (instance == null) instance = new HNSMempool();
            }
        }
        return instance;
    }

    // ── Data structures ───────────────────────────────────────────────────────

    /** txid(hex) → MempoolEntry */
    private final ConcurrentHashMap<String, MempoolEntry> map = new ConcurrentHashMap<>();

    /**
     * Spent outpoints: "txid:index" → spending txid
     * Used for double-spend detection.
     */
    private final ConcurrentHashMap<String, String> spents = new ConcurrentHashMap<>();

    /** Recently seen txids to avoid re-processing (rolling, max 10000) */
    private final LinkedHashMap<String, Boolean> seen = new LinkedHashMap<>(1000, 0.75f, true) {
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> e) {
            return size() > 10_000;
        }
    };

    /** Listeners notified when a new tx is added (for INV announcement) */
    private final List<TxListener> listeners = new ArrayList<>();

    private HNSMempool() {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Adds a raw transaction to the mempool.
     *
     * @param rawTx   raw serialized transaction bytes
     * @param txid    hex txid (caller computes this)
     * @param announce whether to notify listeners (announce via INV)
     * @return true if added, false if already known or invalid
     */
    public boolean addTx(byte[] rawTx, String txid, boolean announce) {
        if (txid == null || rawTx == null || rawTx.length == 0) return false;

        synchronized (seen) {
            if (seen.containsKey(txid)) return false;
            seen.put(txid, Boolean.TRUE);
        }

        if (map.containsKey(txid)) return false;

        // Parse to extract inputs for double-spend detection
        HNSBlock.Tx tx;
        try {
            tx = HNSBlock.Tx.parse(rawTx, 0);
        } catch (Exception e) {
            System.out.printf("[Mempool] Failed to parse tx %s: %s%n",
                    txid.substring(0, 8), e.getMessage());
            return false;
        }

        // Check for double spends
        for (HNSBlock.Input input : tx.inputs) {
            if (input.isCoinbase()) continue;
            String key = HNSTxBuilder.toHex(input.prevHash) + ":" + input.prevIndex;
            if (spents.containsKey(key)) {
                System.out.printf("[Mempool] Double spend detected for %s%n",
                        txid.substring(0, 8));
                return false;
            }
        }

        // Evict old entries if full
        if (map.size() >= MAX_TXS) evictOldest();

        MempoolEntry entry = new MempoolEntry(txid, rawTx, tx, System.currentTimeMillis());
        map.put(txid, entry);

        // Track spent outpoints
        for (HNSBlock.Input input : tx.inputs) {
            if (input.isCoinbase()) continue;
            String key = HNSTxBuilder.toHex(input.prevHash) + ":" + input.prevIndex;
            spents.put(key, txid);
        }

        System.out.printf("[Mempool] Added tx %s... (size=%d, pool=%d)%n",
                txid.substring(0, 16), rawTx.length, map.size());

        // Notify listeners (triggers INV announcement to peers)
        if (announce) {
            for (TxListener l : listeners) {
                try { l.onTxAdded(txid, rawTx); } catch (Exception ignored) {}
            }
        }

        return true;
    }

    /**
     * Removes transactions that were confirmed in a block.
     * Called by ChainFollower/BlockSyncCoordinator when a new block arrives.
     */
    public void removeConfirmed(List<String> confirmedTxids) {
        for (String txid : confirmedTxids) {
            MempoolEntry entry = map.remove(txid);
            if (entry != null) {
                // Remove spent outpoints for this tx
                for (HNSBlock.Input input : entry.tx.inputs) {
                    if (input.isCoinbase()) continue;
                    String key = HNSTxBuilder.toHex(input.prevHash)
                            + ":" + input.prevIndex;
                    spents.remove(key);
                }
                System.out.printf("[Mempool] Confirmed tx removed: %s...%n",
                        txid.substring(0, 16));
            }
        }
    }

    /** Returns the raw bytes of a tx, or null if not in mempool. */
    public byte[] getRawTx(String txid) {
        MempoolEntry entry = map.get(txid);
        return entry != null ? entry.raw : null;
    }

    /** Returns true if the txid is in the mempool. */
    public boolean hasTx(String txid) {
        return map.containsKey(txid);
    }

    /** Returns true if we've recently seen this txid (mempool or already processed). */
    public boolean hasSeenTx(String txid) {
        synchronized (seen) { return seen.containsKey(txid); }
    }

    /**
     * Returns all txids currently in the mempool.
     * Used to respond to MEMPOOL messages from peers.
     */
    public List<String> getSnapshot() {
        return new ArrayList<>(map.keySet());
    }

    /** Returns the number of transactions in the mempool. */
    public int size() { return map.size(); }

    /** Registers a listener for new transaction additions. */
    public void addListener(TxListener listener) {
        synchronized (listeners) { listeners.add(listener); }
    }

    /** Evicts expired and oldest transactions to stay under MAX_TXS. */
    void evictOldest() {
        long now = System.currentTimeMillis();
        // First remove expired entries
        map.entrySet().removeIf(e -> {
            if (now - e.getValue().addedAt > EXPIRY_MS) {
                removeSpentsFor(e.getValue());
                return true;
            }
            return false;
        });
        // If still full, remove oldest by time
        if (map.size() >= MAX_TXS) {
            map.entrySet().stream()
                    .sorted(Comparator.comparingLong(e -> e.getValue().addedAt))
                    .limit(map.size() - MAX_TXS + 100)
                    .forEach(e -> {
                        removeSpentsFor(e.getValue());
                        map.remove(e.getKey());
                    });
        }
    }

    private void removeSpentsFor(MempoolEntry entry) {
        for (HNSBlock.Input input : entry.tx.inputs) {
            if (input.isCoinbase()) continue;
            String key = HNSTxBuilder.toHex(input.prevHash) + ":" + input.prevIndex;
            spents.remove(key);
        }
    }

    // ── Wire format helpers ───────────────────────────────────────────────────

    /**
     * Builds an INV payload announcing a set of transaction hashes.
     *
     * From packets.js InvPacket:
     *   varint(count)
     *   [type(4 LE) + hash(32)] × count
     *
     * type=1 for TX (INV_TX)
     */
    public static byte[] buildInvTx(List<byte[]> txHashes) {
        if (txHashes.isEmpty()) return new byte[0];
        int count = Math.min(txHashes.size(), 50000); // MAX_INV
        byte[] varint = encodeVarint(count);
        byte[] buf = new byte[varint.length + 36 * count];
        int pos = 0;
        System.arraycopy(varint, 0, buf, pos, varint.length);
        pos += varint.length;
        for (int i = 0; i < count; i++) {
            buf[pos]   = 0x01; // INV_TX = 1
            buf[pos+1] = 0x00;
            buf[pos+2] = 0x00;
            buf[pos+3] = 0x00;
            pos += 4;
            byte[] hash = txHashes.get(i);
            System.arraycopy(hash, 0, buf, pos, 32);
            pos += 32;
        }
        return buf;
    }

    /**
     * Builds a GETDATA payload requesting a set of transaction hashes.
     * Same wire format as INV.
     */
    public static byte[] buildGetDataTx(List<byte[]> txHashes) {
        return buildInvTx(txHashes); // same format, type=1
    }

    /**
     * Parses an INV or GETDATA payload, returns list of (type, hash) pairs.
     * type=1 means TX, type=2 means BLOCK.
     */
    public static List<InvItem> parseInv(byte[] payload) {
        List<InvItem> items = new ArrayList<>();
        if (payload == null || payload.length < 1) return items;
        int pos = 0;
        // Read varint count
        long count = 0;
        int b = payload[pos] & 0xFF;
        if (b < 0xFD) {
            count = b; pos++;
        } else if (b == 0xFD) {
            count = ((payload[pos+1] & 0xFFL)) | ((payload[pos+2] & 0xFFL) << 8);
            pos += 3;
        } else if (b == 0xFE) {
            count = ((payload[pos+1] & 0xFFL))
                    | ((payload[pos+2] & 0xFFL) << 8)
                    | ((payload[pos+3] & 0xFFL) << 16)
                    | ((payload[pos+4] & 0xFFL) << 24);
            pos += 5;
        }
        count = Math.min(count, 50000);
        for (long i = 0; i < count && pos + 36 <= payload.length; i++) {
            int type = (payload[pos] & 0xFF)
                    | ((payload[pos+1] & 0xFF) << 8)
                    | ((payload[pos+2] & 0xFF) << 16)
                    | ((payload[pos+3] & 0xFF) << 24);
            pos += 4;
            byte[] hash = Arrays.copyOfRange(payload, pos, pos + 32);
            pos += 32;
            items.add(new InvItem(type, hash));
        }
        return items;
    }

    // ── Inner classes ─────────────────────────────────────────────────────────

    public static class MempoolEntry {
        public final String       txid;
        public final byte[]       raw;
        public final HNSBlock.Tx  tx;
        public final long         addedAt;

        MempoolEntry(String txid, byte[] raw, HNSBlock.Tx tx, long addedAt) {
            this.txid    = txid;
            this.raw     = raw;
            this.tx      = tx;
            this.addedAt = addedAt;
        }
    }

    public static class InvItem {
        public static final int TYPE_TX    = 1;
        public static final int TYPE_BLOCK = 2;

        public final int    type;
        public final byte[] hash;

        InvItem(int type, byte[] hash) {
            this.type = type;
            this.hash = hash;
        }

        public boolean isTx()    { return type == TYPE_TX;    }
        public boolean isBlock()  { return type == TYPE_BLOCK; }
    }

    public interface TxListener {
        void onTxAdded(String txid, byte[] rawTx);
    }

    // ── Varint encoding ───────────────────────────────────────────────────────

    static byte[] encodeVarint(long v) {
        if (v < 0xFD) return new byte[]{ (byte) v };
        if (v <= 0xFFFF) return new byte[]{
                (byte) 0xFD, (byte)(v & 0xFF), (byte)((v >> 8) & 0xFF) };
        return new byte[]{
                (byte) 0xFE,
                (byte)( v        & 0xFF), (byte)((v >>  8) & 0xFF),
                (byte)((v >> 16) & 0xFF), (byte)((v >> 24) & 0xFF) };
    }
}