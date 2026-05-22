package handshake.wallet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Arrays;
import java.util.List;

/**
 * Builds, signs, and serializes Handshake transactions.
 *
 * Handshake is 100% SegWit — there is never a scriptSig.
 * All authorization goes in the witness stack per input.
 *
 * Wire format (from hsd tx.js write()):
 *   version(4 LE) + varint(inCount) + Input[] +
 *   varint(outCount) + Output[] +
 *   locktime(4 LE) + Witness[per-input]
 *
 * Input  = prevHash(32) + prevIndex(4 LE) + sequence(4 LE) = 40 bytes
 *
 * Output = value(8 LE) + address.write() + covenant.write()
 *   address.write() = version(1) + hashLen(1) + hash(20) = 22 bytes
 *   covenant NONE   = type(1) + varint(0)                =  2 bytes
 *   total output                                         = 32 bytes
 *
 * Witness per input = varint(2) + VarBytes(sig65) + VarBytes(pubkey33)
 *   sig65 = DER-encoded sig (71-72 bytes) + sighash_type(1)  ← total ~73 bytes
 *   Note: hsd isSignatureEncoding() expects exactly 65 bytes.
 *   Looking at the actual source: sig is written as secp256k1.sign() output
 *   (64-byte compact) + 1 sighash byte = 65 bytes total. NOT DER encoding!
 *
 * Sighash preimage (from hsd tx.js signatureHash(), SIGHASH_ALL):
 *   version(4 LE)
 *   hashPrevouts(32)        — blake2b of all (prevHash + prevIndex)
 *   hashSequence(32)        — blake2b of all sequences
 *   prevHash(32)            — this input's prevHash
 *   prevIndex(4 LE)         — this input's prevIndex
 *   scriptCode(varint+25)   — VarBytes: OP_DUP OP_BLAKE160 <hash20> OP_EQUALVERIFY OP_CHECKSIG
 *   value(8 LE)             — value of UTXO being spent
 *   sequence(4 LE)          — this input's sequence
 *   hashOutputs(32)         — blake2b of all serialized outputs
 *   locktime(4 LE)
 *   sighashType(4 LE)       — 0x01 = SIGHASH_ALL
 *
 * txid = blake2b(base_tx) where base_tx excludes witnesses
 *
 * References: hsd/lib/primitives/tx.js, output.js, script/script.js, script/common.js
 */
public class HNSTxBuilder {

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int  VERSION      = 0;
    public static final long SEQUENCE     = 0xFFFFFFFFL;
    public static final int  SIGHASH_ALL  = 1;

    // P2WPKH address version (version=0, hash length=20)
    public static final int  ADDR_VERSION = 0;

    // P2PKH script opcodes (Handshake uses OP_BLAKE160=0xc0, not OP_HASH160=0xa9)
    static final byte OP_DUP         = 0x76;
    static final byte OP_BLAKE160    = (byte) 0xc0;
    static final byte OP_EQUALVERIFY = (byte) 0x88;
    static final byte OP_CHECKSIG    = (byte) 0xac;

    public static final long MIN_RELAY_FEE = 1000L;  // dollarydoos/kvb
    public static final long DUST_LIMIT    = 546L;

    // ── Data classes ──────────────────────────────────────────────────────────

    /**
     * A UTXO to be spent as a transaction input.
     */
    public static class UtxoInput {
        public final byte[] prevHash;   // 32-byte txid (as stored, NOT reversed)
        public final int    prevIndex;
        public final long   value;      // dollarydoos
        public final byte[] addrHash;   // 20-byte pubkey hash (blake2b-160 of pubkey)
        public final byte[] privateKey; // 32-byte HD-derived private key
        public final byte[] publicKey;  // 33-byte compressed public key

        public UtxoInput(byte[] prevHash, int prevIndex, long value,
                         byte[] addrHash, byte[] privateKey, byte[] publicKey) {
            this.prevHash   = prevHash;
            this.prevIndex  = prevIndex;
            this.value      = value;
            this.addrHash   = addrHash;
            this.privateKey = privateKey;
            this.publicKey  = publicKey;
        }
    }

    /**
     * A transaction output (recipient + amount).
     */
    public static class TxOutput {
        public final byte[] addrHash; // 20-byte pubkey hash
        public final long   value;    // dollarydoos

        public TxOutput(byte[] addrHash, long value) {
            this.addrHash = addrHash;
            this.value    = value;
        }
    }

    /**
     * A fully signed, serialized transaction ready for broadcast.
     */
    public static class SignedTx {
        public final byte[] raw;  // complete wire-format bytes
        public final String txid; // hex txid
        public final long   fee;  // fee in dollarydoos

        public SignedTx(byte[] raw, String txid, long fee) {
            this.raw  = raw;
            this.txid = txid;
            this.fee  = fee;
        }

        @Override
        public String toString() {
            return "SignedTx{txid=" + txid
                    + ", fee=" + fee + " dollarydoos"
                    + ", size=" + raw.length + " bytes}";
        }
    }

    // ── Main build entry point ─────────────────────────────────────────────────

    /**
     * Builds and signs a simple HNS send transaction.
     *
     * @param inputs        UTXOs to spend (must cover amount + fee)
     * @param recipientHash 20-byte address hash of recipient
     * @param amount        dollarydoos to send
     * @param changeHash    20-byte address hash for change output
     * @param feePerKb      fee rate in dollarydoos per 1000 virtual bytes (0 = use default)
     */
    public static SignedTx buildSend(List<UtxoInput> inputs,
                                     byte[] recipientHash,
                                     long   amount,
                                     byte[] changeHash,
                                     long   feePerKb) throws IOException {
        if (feePerKb <= 0) feePerKb = MIN_RELAY_FEE;

        // Estimate size:
        // Base: 4 + varint(nIn) + 40*nIn + varint(nOut) + 32*nOut + 4
        // Witness per input: varint(2) + varint(65) + 65 + varint(33) + 33 = 101 bytes
        int  nIn      = inputs.size();
        int  nOut     = 2;
        long baseSize = 4L + varIntSize(nIn) + 40L * nIn
                + varIntSize(nOut) + 32L * nOut + 4L;
        long witSize  = (long) nIn * 101;
        // Virtual size = ceil((base*3 + total) / 4)
        long vsize    = ((baseSize * 3 + baseSize + witSize) + 3) / 4;
        long fee      = Math.max(MIN_RELAY_FEE, (vsize * feePerKb) / 1000);

        long totalIn = inputs.stream().mapToLong(u -> u.value).sum();
        long change  = totalIn - amount - fee;

        if (change < 0)
            throw new IllegalArgumentException(
                    "Insufficient funds: have " + totalIn
                            + ", need " + (amount + fee)
                            + " (amount=" + amount + " fee=" + fee + ")");

        List<TxOutput> outputs = new ArrayList<>();
        outputs.add(new TxOutput(recipientHash, amount));
        if (change >= DUST_LIMIT)
            outputs.add(new TxOutput(changeHash, change));
        else
            fee += change; // absorb dust

        return buildAndSign(inputs, outputs, fee);
    }

    // ── Core sign + serialize ─────────────────────────────────────────────────

    static SignedTx buildAndSign(List<UtxoInput> inputs,
                                 List<TxOutput>  outputs,
                                 long            fee) throws IOException {
        // Pre-compute hash caches shared across all inputs
        byte[] hashPrevouts = computeHashPrevouts(inputs);
        byte[] hashSequence = computeHashSequence(inputs);
        byte[] hashOutputs  = computeHashOutputs(outputs);

        System.out.printf("[TxBuilder] hashPrevouts = %s%n", toHex(hashPrevouts));
        System.out.printf("[TxBuilder] hashSequence = %s%n", toHex(hashSequence));
        System.out.printf("[TxBuilder] hashOutputs  = %s%n", toHex(hashOutputs));

        // Sign each input
        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < inputs.size(); i++) {
            byte[] preimage = buildSighashPreimage(
                    inputs, outputs, i, hashPrevouts, hashSequence, hashOutputs);
            byte[] hash     = blake256(preimage);
            System.out.printf("[TxBuilder] input[%d] preimage(%d bytes) hash=%s%n",
                    i, preimage.length, toHex(hash));
            System.out.printf("[TxBuilder] input[%d] preimage hex=%s%n",
                    i, toHex(preimage));
            // hsd uses compact 64-byte secp256k1 signatures, not DER
            byte[] sigRaw   = Secp256k1.signCompact(inputs.get(i).privateKey, hash);
            // Append sighash type byte → 65 bytes total
            byte[] sig65    = Arrays.copyOf(sigRaw, 65);
            sig65[64]       = (byte) SIGHASH_ALL;
            System.out.printf("[TxBuilder] input[%d] sig=%s%n", i, toHex(sig65));
            System.out.printf("[TxBuilder] input[%d] pubkey=%s%n",
                    i, toHex(inputs.get(i).publicKey));
            sigs.add(sig65);
        }

        byte[] raw     = serialize(inputs, outputs, sigs);
        byte[] baseTx  = serializeBase(inputs, outputs);
        byte[] txidRaw = blake256(baseTx);
        // txid is displayed as little-endian (reversed)
        reverseInPlace(txidRaw);
        String txid = toHex(txidRaw);

        System.out.printf("[TxBuilder] raw tx (%d bytes) = %s%n",
                raw.length, toHex(raw));
        System.out.printf("[TxBuilder] txid = %s%n", txid);
        System.out.printf("[TxBuilder] fee  = %d dollarydoos (%.6f HNS)%n",
                fee, fee / 1_000_000.0);

        return new SignedTx(raw, txid, fee);
    }

    // ── Sighash preimage ──────────────────────────────────────────────────────

    /**
     * Builds the per-input sighash preimage per hsd tx.js signatureHash().
     *
     * From source:
     *   bw.writeU32(version)
     *   bw.writeBytes(prevouts)       32
     *   bw.writeBytes(sequences)      32
     *   bw.writeHash(prevout.hash)    32
     *   bw.writeU32(prevout.index)     4
     *   bw.writeVarBytes(prev.encode()) ← P2PKH script: 1 varint + 25 bytes = 26
     *   bw.writeU64(value)             8
     *   bw.writeU32(sequence)          4
     *   bw.writeBytes(outputs)        32
     *   bw.writeU32(locktime)          4
     *   bw.writeU32(type)              4
     */
    static byte[] buildSighashPreimage(List<UtxoInput> inputs,
                                       List<TxOutput>  outputs,
                                       int             idx,
                                       byte[]          hashPrevouts,
                                       byte[]          hashSequence,
                                       byte[]          hashOutputs)
            throws IOException {
        UtxoInput in = inputs.get(idx);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(4+32+32+32+4+26+8+4+32+4+4);

        writeU32LE(bos, VERSION);
        bos.write(hashPrevouts);
        bos.write(hashSequence);
        bos.write(in.prevHash);
        writeU32LE(bos, in.prevIndex);
        writeVarBytes(bos, p2pkhScript(in.addrHash)); // scriptCode
        writeU64LE(bos, in.value);
        writeU32LE(bos, SEQUENCE);
        bos.write(hashOutputs);
        writeU32LE(bos, 0);          // locktime
        writeU32LE(bos, SIGHASH_ALL);

        return bos.toByteArray();
    }

    // ── P2PKH script ──────────────────────────────────────────────────────────

    /**
     * Builds the Handshake P2PKH redeem script for an address hash.
     *
     * From hsd script.js fromPubkeyhash():
     *   OP_DUP (0x76)
     *   OP_BLAKE160 (0xc0)   ← Handshake uses BLAKE2b-160, NOT RIPEMD160
     *   0x14 (push 20 bytes)
     *   <20-byte-hash>
     *   OP_EQUALVERIFY (0x88)
     *   OP_CHECKSIG (0xac)
     *
     * = 25 bytes total
     */
    static byte[] p2pkhScript(byte[] addrHash) {
        byte[] script = new byte[25];
        script[0]  = OP_DUP;
        script[1]  = OP_BLAKE160;
        script[2]  = 0x14; // push 20 bytes
        System.arraycopy(addrHash, 0, script, 3, 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        return script;
    }

    // ── Hash caches ───────────────────────────────────────────────────────────

    /** blake256 of all (prevHash + prevIndex) concatenated */
    static byte[] computeHashPrevouts(List<UtxoInput> inputs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(inputs.size() * 36);
        for (UtxoInput in : inputs) {
            bos.write(in.prevHash);
            writeU32LE(bos, in.prevIndex);
        }
        return blake256(bos.toByteArray());
    }

    /** blake256 of all sequences concatenated */
    static byte[] computeHashSequence(List<UtxoInput> inputs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(inputs.size() * 4);
        for (UtxoInput ignored : inputs) writeU32LE(bos, SEQUENCE);
        return blake256(bos.toByteArray());
    }

    /**
     * blake256 of all serialized outputs concatenated.
     * Uses output.write() which is: value(8) + address.write() + covenant.write()
     */
    static byte[] computeHashOutputs(List<TxOutput> outputs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(outputs.size() * 32);
        for (TxOutput out : outputs) serializeOutput(bos, out);
        return blake256(bos.toByteArray());
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /** Full transaction with witnesses */
    static byte[] serialize(List<UtxoInput> inputs,
                            List<TxOutput>  outputs,
                            List<byte[]>    sigs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeU32LE(bos, VERSION);

        writeVarInt(bos, inputs.size());
        for (UtxoInput in : inputs) {
            bos.write(in.prevHash);
            writeU32LE(bos, in.prevIndex);
            writeU32LE(bos, SEQUENCE);
        }

        writeVarInt(bos, outputs.size());
        for (TxOutput out : outputs) serializeOutput(bos, out);

        writeU32LE(bos, 0); // locktime

        // Witnesses after locktime (one per input)
        for (int i = 0; i < inputs.size(); i++) {
            writeVarInt(bos, 2);                        // 2 stack items
            writeVarBytes(bos, sigs.get(i));            // sig (65 bytes)
            writeVarBytes(bos, inputs.get(i).publicKey); // pubkey (33 bytes)
        }

        return bos.toByteArray();
    }

    /** Base transaction (no witnesses) — used for txid calculation */
    static byte[] serializeBase(List<UtxoInput> inputs,
                                List<TxOutput>  outputs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeU32LE(bos, VERSION);

        writeVarInt(bos, inputs.size());
        for (UtxoInput in : inputs) {
            bos.write(in.prevHash);
            writeU32LE(bos, in.prevIndex);
            writeU32LE(bos, SEQUENCE);
        }

        writeVarInt(bos, outputs.size());
        for (TxOutput out : outputs) serializeOutput(bos, out);

        writeU32LE(bos, 0); // locktime
        return bos.toByteArray();
    }

    /**
     * Serializes one output per hsd output.js write():
     *   bw.writeU64(value)
     *   this.address.write(bw)    → version(1) + hashLen(1) + hash(20)
     *   this.covenant.write(bw)   → type(1) + varint(0)  [for NONE]
     */
    static void serializeOutput(ByteArrayOutputStream bos,
                                TxOutput out) throws IOException {
        writeU64LE(bos, out.value);
        // address.write(): version(1) + hashLen(1) + hash(20)
        bos.write(ADDR_VERSION);
        bos.write(out.addrHash.length); // = 20
        bos.write(out.addrHash);
        // covenant NONE: type(1) + varint(0 items)
        bos.write(0x00); // covenant type NONE
        bos.write(0x00); // varint(0) items
    }

    // ── BLAKE2b-256 ───────────────────────────────────────────────────────────

    public static byte[] blake256(byte[] data) {
        return BLAKE2b.hash(data, 32);
    }

    // ── Wire encoding helpers ─────────────────────────────────────────────────

    static void writeU32LE(ByteArrayOutputStream bos, long v) {
        bos.write((int)( v        & 0xFF));
        bos.write((int)((v >>  8) & 0xFF));
        bos.write((int)((v >> 16) & 0xFF));
        bos.write((int)((v >> 24) & 0xFF));
    }

    static void writeU64LE(ByteArrayOutputStream bos, long v) {
        for (int i = 0; i < 8; i++)
            bos.write((int)((v >> (i * 8)) & 0xFF));
    }

    static void writeVarInt(ByteArrayOutputStream bos, long v) {
        if (v < 0xFD) {
            bos.write((int) v);
        } else if (v <= 0xFFFF) {
            bos.write(0xFD);
            bos.write((int)( v       & 0xFF));
            bos.write((int)((v >> 8) & 0xFF));
        } else if (v <= 0xFFFFFFFFL) {
            bos.write(0xFE);
            writeU32LE(bos, v);
        } else {
            bos.write(0xFF);
            writeU64LE(bos, v);
        }
    }

    static void writeVarBytes(ByteArrayOutputStream bos, byte[] data)
            throws IOException {
        writeVarInt(bos, data.length);
        bos.write(data);
    }

    static int varIntSize(long v) {
        if (v < 0xFD)          return 1;
        if (v <= 0xFFFF)       return 3;
        if (v <= 0xFFFFFFFFL)  return 5;
        return 9;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    static void reverseInPlace(byte[] b) {
        for (int i = 0, j = b.length - 1; i < j; i++, j--) {
            byte t = b[i]; b[i] = b[j]; b[j] = t;
        }
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private HNSTxBuilder() {}
}