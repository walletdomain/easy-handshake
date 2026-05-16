package handshake.node;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses a Handshake full block from raw wire bytes.
 *
 * Wire format (block.js write()):
 *   header(236) + varint(txCount) + TX[]
 *
 * TX wire format (tx.js write()):
 *   version(4 LE) + varint(inCount) + Input[] +
 *   varint(outCount) + Output[] + locktime(4 LE) +
 *   Witness[per-input]   ← witnesses come AFTER all outputs
 *
 * Input (input.js write()):
 *   prevHash(32) + prevIndex(4 LE) + sequence(4 LE) = 40 bytes fixed
 *
 * Output (output.js write()):
 *   value(8 LE) + addrVersion(1) + addrHashLen(1) + addrHash(N) +
 *   covenantType(1) + varint(itemCount) + VarBytes[]
 *
 * Witness (script/witness.js write()):
 *   varint(itemCount) + VarBytes[]  — one Witness per input
 *
 * VarBytes = varint(len) + bytes(len)
 *
 * Verified against block 1 on mainnet (351 bytes, 1 coinbase tx).
 */
public class HNSBlock {

    // -------------------------------------------------------------------------
    // Public fields
    // -------------------------------------------------------------------------

    /** The 236-byte block header (same format as HNSPeer.BlockHeader). */
    public final byte[] header;

    /** Parsed transactions. */
    public final List<Tx> txs;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    private HNSBlock(byte[] header, List<Tx> txs) {
        this.header = header;
        this.txs    = txs;
    }

    // -------------------------------------------------------------------------
    // Parse
    // -------------------------------------------------------------------------

    /**
     * Parses a complete block from raw wire bytes (the BLOCK message payload).
     */
    public static HNSBlock parse(byte[] data) {
        return parse(data, 0);
    }

    public static HNSBlock parse(byte[] data, int offset) {
        int pos = offset;

        // Header: 236 bytes
        byte[] header = Arrays.copyOfRange(data, pos, pos + HNSPeer.HEADER_SIZE);
        pos += HNSPeer.HEADER_SIZE;

        // Transaction count
        long[] varint = HNSPeer.decodeVarint(data, pos);
        int txCount = (int) varint[0];
        pos += (int) varint[1];

        List<Tx> txs = new ArrayList<>(txCount);
        for (int i = 0; i < txCount; i++) {
            Tx tx = Tx.parse(data, pos);
            txs.add(tx);
            pos += tx.rawSize;
        }

        return new HNSBlock(header, txs);
    }

    // -------------------------------------------------------------------------
    // Transaction
    // -------------------------------------------------------------------------

    public static class Tx {
        public final int         version;
        public final List<Input>  inputs;
        public final List<Output> outputs;
        public final long         locktime;
        public final List<Witness> witnesses; // one per input, after outputs
        public final byte[]       raw;        // full tx bytes for hashing
        public final int          rawSize;    // bytes consumed from wire

        private Tx(int version, List<Input> inputs, List<Output> outputs,
                   long locktime, List<Witness> witnesses,
                   byte[] raw, int rawSize) {
            this.version   = version;
            this.inputs    = inputs;
            this.outputs   = outputs;
            this.locktime  = locktime;
            this.witnesses = witnesses;
            this.raw       = raw;
            this.rawSize   = rawSize;
        }

        static Tx parse(byte[] data, int start) {
            int pos = start;
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

            // version (4 bytes LE)
            int version = buf.getInt(pos); pos += 4;

            // inputs
            long[] vi = HNSPeer.decodeVarint(data, pos);
            int inCount = (int) vi[0]; pos += (int) vi[1];
            List<Input> inputs = new ArrayList<>(inCount);
            for (int i = 0; i < inCount; i++) {
                inputs.add(Input.parse(data, pos));
                pos += Input.SIZE;
            }

            // outputs
            vi = HNSPeer.decodeVarint(data, pos);
            int outCount = (int) vi[0]; pos += (int) vi[1];
            List<Output> outputs = new ArrayList<>(outCount);
            for (int i = 0; i < outCount; i++) {
                Output out = Output.parse(data, pos);
                outputs.add(out);
                pos += out.size;
            }

            // locktime (4 bytes LE)
            long locktime = buf.getInt(pos) & 0xFFFFFFFFL; pos += 4;

            // witnesses — one per input, after all outputs
            List<Witness> witnesses = new ArrayList<>(inCount);
            for (int i = 0; i < inCount; i++) {
                Witness w = Witness.parse(data, pos);
                witnesses.add(w);
                pos += w.size;
            }

            int rawSize = pos - start;
            byte[] raw  = Arrays.copyOfRange(data, start, pos);
            return new Tx(version, inputs, outputs, locktime, witnesses, raw, rawSize);
        }

        @Override
        public String toString() {
            return "Tx{version=" + version
                    + ", inputs=" + inputs.size()
                    + ", outputs=" + outputs.size()
                    + ", locktime=" + locktime + "}";
        }
    }

    // -------------------------------------------------------------------------
    // Input  — fixed 40 bytes
    // -------------------------------------------------------------------------

    public static class Input {
        /** Fixed wire size: prevHash(32) + prevIndex(4) + sequence(4). */
        public static final int SIZE = 40;

        public final byte[] prevHash;
        public final long   prevIndex;  // uint32
        public final long   sequence;   // uint32

        private Input(byte[] prevHash, long prevIndex, long sequence) {
            this.prevHash  = prevHash;
            this.prevIndex = prevIndex;
            this.sequence  = sequence;
        }

        static Input parse(byte[] data, int pos) {
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            byte[] hash = Arrays.copyOfRange(data, pos, pos + 32);
            long index  = buf.getInt(pos + 32) & 0xFFFFFFFFL;
            long seq    = buf.getInt(pos + 36) & 0xFFFFFFFFL;
            return new Input(hash, index, seq);
        }

        /** Returns true if this is a coinbase input (prevHash=0, prevIndex=0xFFFFFFFF). */
        public boolean isCoinbase() {
            for (byte b : prevHash) if (b != 0) return false;
            return prevIndex == 0xFFFFFFFFL;
        }

        @Override
        public String toString() {
            return "Input{prevIndex=" + prevIndex
                    + (isCoinbase() ? " [COINBASE]" : "") + "}";
        }
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    public static class Output {
        public final long     value;       // HNS dollarydoos (uint64)
        public final int      addrVersion; // address version byte
        public final byte[]   addrHash;    // address hash (2-40 bytes)
        public final Covenant covenant;
        public final int      size;        // bytes consumed

        private Output(long value, int addrVersion, byte[] addrHash,
                       Covenant covenant, int size) {
            this.value       = value;
            this.addrVersion = addrVersion;
            this.addrHash    = addrHash;
            this.covenant    = covenant;
            this.size        = size;
        }

        static Output parse(byte[] data, int start) {
            int pos = start;
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

            // value: uint64 LE
            long value = buf.getLong(pos); pos += 8;

            // address: version(1) + hashLen(1) + hash(hashLen)
            int addrVersion = data[pos] & 0xFF; pos++;
            int addrHashLen = data[pos] & 0xFF; pos++;
            byte[] addrHash = Arrays.copyOfRange(data, pos, pos + addrHashLen);
            pos += addrHashLen;

            // covenant
            Covenant cov = Covenant.parse(data, pos);
            pos += cov.size;

            return new Output(value, addrVersion, addrHash, cov, pos - start);
        }

        /** Returns value in HNS (dollarydoos / 1_000_000). */
        public double valueHNS() {
            return value / 1_000_000.0;
        }

        @Override
        public String toString() {
            return "Output{value=" + valueHNS() + " HNS"
                    + ", covenant=" + covenant.type + "}";
        }
    }

    // -------------------------------------------------------------------------
    // Covenant  (Handshake name auction data)
    // -------------------------------------------------------------------------

    public static class Covenant {
        public final int         type;   // covenant type (0=NONE, 1=CLAIM, 2=OPEN, etc.)
        public final List<byte[]> items;
        public final int         size;   // bytes consumed

        // Covenant types (from covenant.js)
        public static final int NONE    = 0;
        public static final int CLAIM   = 1;
        public static final int OPEN    = 2;
        public static final int BID     = 3;
        public static final int REVEAL  = 4;
        public static final int REDEEM  = 5;
        public static final int REGISTER = 6;
        public static final int UPDATE  = 7;
        public static final int RENEW   = 8;
        public static final int TRANSFER = 9;
        public static final int FINALIZE = 10;
        public static final int REVOKE  = 11;

        private Covenant(int type, List<byte[]> items, int size) {
            this.type  = type;
            this.items = items;
            this.size  = size;
        }

        static Covenant parse(byte[] data, int start) {
            int pos = start;

            // type: 1 byte
            int type = data[pos] & 0xFF; pos++;

            // item count: varint
            long[] vi = HNSPeer.decodeVarint(data, pos);
            int itemCount = (int) vi[0]; pos += (int) vi[1];

            // items: VarBytes[]
            List<byte[]> items = new ArrayList<>(itemCount);
            for (int i = 0; i < itemCount; i++) {
                long[] vb = HNSPeer.decodeVarint(data, pos);
                int itemLen = (int) vb[0]; pos += (int) vb[1];
                items.add(Arrays.copyOfRange(data, pos, pos + itemLen));
                pos += itemLen;
            }

            return new Covenant(type, items, pos - start);
        }
    }

    // -------------------------------------------------------------------------
    // Witness  (per-input witness stack)
    // -------------------------------------------------------------------------

    public static class Witness {
        public final List<byte[]> items;
        public final int          size; // bytes consumed

        private Witness(List<byte[]> items, int size) {
            this.items = items;
            this.size  = size;
        }

        static Witness parse(byte[] data, int start) {
            int pos = start;

            // item count: varint
            long[] vi = HNSPeer.decodeVarint(data, pos);
            int itemCount = (int) vi[0]; pos += (int) vi[1];

            List<byte[]> items = new ArrayList<>(itemCount);
            for (int i = 0; i < itemCount; i++) {
                long[] vb = HNSPeer.decodeVarint(data, pos);
                int itemLen = (int) vb[0]; pos += (int) vb[1];
                items.add(Arrays.copyOfRange(data, pos, pos + itemLen));
                pos += itemLen;
            }

            return new Witness(items, pos - start);
        }
    }

    // -------------------------------------------------------------------------
    // toString
    // -------------------------------------------------------------------------

    @Override
    public String toString() {
        return "HNSBlock{txs=" + txs.size() + "}";
    }
}