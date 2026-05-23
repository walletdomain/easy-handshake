package handshake.wallet;

import handshake.node.HNSPeer.Blake2b;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Builds TRANSFER and FINALIZE covenant transactions for Handshake name transfers.
 *
 * A name transfer is a two-step process:
 *
 * Step 1 — TRANSFER transaction:
 *   - Input:  name UTXO (REGISTER, UPDATE, RENEW, or FINALIZE covenant)
 *   - Output: same address, same value, TRANSFER covenant
 *   - Covenant: [nameHash(32), height(4), version(1), recipientAddrHash(20)]
 *   - Must wait ~2 days (288 blocks) before finalizing
 *
 * Step 2 — FINALIZE transaction (after lockup period):
 *   - Input:  TRANSFER UTXO
 *   - Output: recipient address, same value, FINALIZE covenant
 *   - Covenant: [nameHash(32), height(4), name(var), flags(1),
 *                claimHeight(4), renewalCount(4), blockHash(32)]
 *
 * Key rules from rules.js verifyCovenants():
 *   - output.value must equal coin.value (locked forever)
 *   - For TRANSFER: output.address must match coin.address (current owner)
 *   - For FINALIZE: output.address must match transfer covenant's recipient
 *   - nameHash and height must match across all steps
 *
 * Sighash is identical to simple HNS sends (tx.js signatureHash()).
 * Covenant data is committed via hashOutputs (output.write() includes covenant).
 */
public class HNSTransferBuilder {

    // Covenant type constants
    public static final int COV_NONE     = 0;
    public static final int COV_TRANSFER = 9;
    public static final int COV_FINALIZE = 10;

    // ── TRANSFER transaction ───────────────────────────────────────────────────

    /**
     * Builds and signs a TRANSFER covenant transaction.
     *
     * @param name          the name being transferred (e.g. "example")
     * @param nameRecord    the NameRecord from WalletDB (has utxoTxHash, nameHash, etc.)
     * @param utxoValue     dollarydoos locked in the name UTXO
     * @param ownerAddrHash 20-byte hash of current owner address
     * @param ownerPrivKey  32-byte private key of current owner
     * @param ownerPubKey   33-byte compressed public key of current owner
     * @param recipientAddrHash 20-byte hash of recipient address
     * @param feeSource     a separate spendable UTXO to pay the fee from
     * @return signed transaction ready to broadcast
     */
    public static HNSTxBuilder.SignedTx buildTransfer(
            String name,
            WalletDB.NameRecord nameRecord,
            long   utxoValue,
            byte[] ownerAddrHash,
            byte[] ownerPrivKey,
            byte[] ownerPubKey,
            byte[] recipientAddrHash,
            HNSTxBuilder.UtxoInput feeSource) throws IOException {

        // Compute nameHash = SHA3-256 of name bytes (if not stored)
        byte[] nameHash = nameRecord.nameHash != null && !nameRecord.nameHash.isEmpty()
                ? fromHex(nameRecord.nameHash)
                : sha3_256(name.getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        // claimHeight = original registration height stored in covenant items[1]
        byte[] claimHeightBytes = toLE32(nameRecord.claimHeight);

        // The name's UTXO prevHash
        byte[] namePrevHash = fromHex(nameRecord.utxoTxHash);

        // Build TRANSFER covenant: [nameHash(32), claimHeight(4), version(1), recipientHash(20)]
        byte[] transferCovenant = buildTransferCovenant(
                nameHash, claimHeightBytes, (byte) 0, recipientAddrHash);

        // Build outputs:
        // Output 0: name output — same address, same value, TRANSFER covenant
        // Output 1: change from fee UTXO (fee UTXO value minus fee)
        long fee    = HNSTxBuilder.MIN_RELAY_FEE;
        long change = feeSource.value - fee;

        // We need two inputs and two outputs:
        // Input 0: name UTXO (spending the locked name)
        // Input 1: fee UTXO  (paying the transaction fee)
        // Output 0: name output (TRANSFER covenant, owner address, same value)
        // Output 1: change output (NONE covenant, change address)

        byte[] rawTx = buildTransferTx(
                namePrevHash, nameRecord.utxoIndex, utxoValue,
                ownerAddrHash, transferCovenant,
                feeSource, change,
                ownerPrivKey, ownerPubKey,
                name, nameHash, claimHeightBytes);

        // Compute txid
        handshake.node.HNSBlock.Tx parsed =
                handshake.node.HNSBlock.Tx.parse(rawTx, 0);
        byte[] base = Arrays.copyOf(rawTx, parsed.baseSize);
        byte[] txidRaw = HNSTxBuilder.blake256(base);
        HNSTxBuilder.reverseInPlace(txidRaw);
        String txid = HNSTxBuilder.toHex(txidRaw);

        System.out.printf("[Transfer] Built TRANSFER tx for .%s txid=%s%n", name, txid);
        return new HNSTxBuilder.SignedTx(rawTx, txid, fee);
    }

    // ── Internal transaction builder ───────────────────────────────────────────

    private static byte[] buildTransferTx(
            byte[] namePrevHash, int nameOutIdx, long nameValue,
            byte[] ownerAddrHash, byte[] transferCovenant,
            HNSTxBuilder.UtxoInput feeUtxo, long change,
            byte[] ownerPrivKey, byte[] ownerPubKey,
            String name, byte[] nameHash, byte[] claimHeightBytes)
            throws IOException {

        // ── Pre-compute hash caches ────────────────────────────────────────────
        // hashPrevouts = blake256(prevHash0 + index0 + prevHash1 + index1)
        ByteArrayOutputStream prevoutsBuf = new ByteArrayOutputStream();
        prevoutsBuf.write(namePrevHash);
        writeU32LE(prevoutsBuf, nameOutIdx);
        prevoutsBuf.write(feeUtxo.prevHash);
        writeU32LE(prevoutsBuf, feeUtxo.prevIndex);
        byte[] hashPrevouts = HNSTxBuilder.blake256(prevoutsBuf.toByteArray());

        // hashSequence = blake256(seq0 + seq1)
        ByteArrayOutputStream seqBuf = new ByteArrayOutputStream();
        writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        byte[] hashSequence = HNSTxBuilder.blake256(seqBuf.toByteArray());

        // hashOutputs = blake256(output0 + output1)
        ByteArrayOutputStream outsBuf = new ByteArrayOutputStream();
        serializeNameOutput(outsBuf, nameValue, ownerAddrHash, transferCovenant);
        serializeSimpleOutput(outsBuf, change, feeUtxo.addrHash);
        byte[] hashOutputs = HNSTxBuilder.blake256(outsBuf.toByteArray());

        System.out.printf("[Transfer] hashPrevouts=%s%n", HNSTxBuilder.toHex(hashPrevouts));
        System.out.printf("[Transfer] hashOutputs=%s%n", HNSTxBuilder.toHex(hashOutputs));

        // ── Sign input 0: name UTXO ────────────────────────────────────────────
        byte[] preimage0 = buildSighashPreimage(
                hashPrevouts, hashSequence, namePrevHash, nameOutIdx,
                ownerAddrHash, nameValue, hashOutputs);
        byte[] hash0 = HNSTxBuilder.blake256(preimage0);
        byte[] sig0Raw = Secp256k1.signCompact(ownerPrivKey, hash0);
        byte[] sig0 = Arrays.copyOf(sig0Raw, 65);
        sig0[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // ── Sign input 1: fee UTXO ─────────────────────────────────────────────
        byte[] preimage1 = buildSighashPreimage(
                hashPrevouts, hashSequence, feeUtxo.prevHash, feeUtxo.prevIndex,
                feeUtxo.addrHash, feeUtxo.value, hashOutputs);
        byte[] hash1 = HNSTxBuilder.blake256(preimage1);
        byte[] sig1Raw = Secp256k1.signCompact(feeUtxo.privateKey, hash1);
        byte[] sig1 = Arrays.copyOf(sig1Raw, 65);
        sig1[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // ── Serialize transaction ──────────────────────────────────────────────
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeU32LE(bos, HNSTxBuilder.VERSION);

        // 2 inputs
        HNSTxBuilder.writeVarInt(bos, 2);
        bos.write(namePrevHash);
        writeU32LE(bos, nameOutIdx);
        writeU32LE(bos, HNSTxBuilder.SEQUENCE);
        bos.write(feeUtxo.prevHash);
        writeU32LE(bos, feeUtxo.prevIndex);
        writeU32LE(bos, HNSTxBuilder.SEQUENCE);

        // 2 outputs
        HNSTxBuilder.writeVarInt(bos, 2);
        serializeNameOutput(bos, nameValue, ownerAddrHash, transferCovenant);
        serializeSimpleOutput(bos, change, feeUtxo.addrHash);

        writeU32LE(bos, 0); // locktime

        // Witnesses
        HNSTxBuilder.writeVarInt(bos, 2); // input 0: 2 items
        HNSTxBuilder.writeVarBytes(bos, sig0);
        HNSTxBuilder.writeVarBytes(bos, ownerPubKey);
        HNSTxBuilder.writeVarInt(bos, 2); // input 1: 2 items
        HNSTxBuilder.writeVarBytes(bos, sig1);
        HNSTxBuilder.writeVarBytes(bos, feeUtxo.publicKey);

        return bos.toByteArray();
    }

    // ── Sighash preimage ──────────────────────────────────────────────────────

    static byte[] buildSighashPreimage(
            byte[] hashPrevouts, byte[] hashSequence,
            byte[] prevHash, int prevIndex,
            byte[] addrHash, long value,
            byte[] hashOutputs) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(182);
        writeU32LE(bos, HNSTxBuilder.VERSION);
        bos.write(hashPrevouts);
        bos.write(hashSequence);
        bos.write(prevHash);
        writeU32LE(bos, prevIndex);
        HNSTxBuilder.writeVarBytes(bos, HNSTxBuilder.p2pkhScript(addrHash));
        writeU64LE(bos, value);
        writeU32LE(bos, HNSTxBuilder.SEQUENCE);
        bos.write(hashOutputs);
        writeU32LE(bos, 0);                         // locktime
        writeU32LE(bos, HNSTxBuilder.SIGHASH_ALL);
        return bos.toByteArray();
    }

    // ── Covenant serialization ─────────────────────────────────────────────────

    /**
     * Builds TRANSFER covenant bytes:
     *   type(1) + varint(4 items)
     *   + VarBytes(nameHash) + VarBytes(height) + VarBytes(version) + VarBytes(addrHash)
     *
     * From rules.js hasSaneCovenants() TRANSFER:
     *   items[0] = nameHash (32 bytes)
     *   items[1] = height   (4 bytes LE)
     *   items[2] = version  (1 byte)
     *   items[3] = hash     (20 bytes for standard address)
     */
    static byte[] buildTransferCovenant(byte[] nameHash, byte[] heightBytes,
                                        byte version, byte[] recipientHash)
            throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(COV_TRANSFER);     // type byte
        HNSTxBuilder.writeVarInt(bos, 4); // 4 items
        writeVarBytes(bos, nameHash);
        writeVarBytes(bos, heightBytes);
        writeVarBytes(bos, new byte[]{ version });
        writeVarBytes(bos, recipientHash);
        return bos.toByteArray();
    }

    /**
     * Builds and signs a FINALIZE covenant transaction.
     * Called automatically by ChainFollower when finalizeAfterHeight is reached.
     *
     * @param nameRecord    the NameRecord with pending finalize data
     * @param nameUtxoHash  txid of the TRANSFER UTXO (output of TRANSFER tx)
     * @param nameUtxoIndex output index of the TRANSFER UTXO
     * @param nameValue     dollarydoos locked in the name
     * @param blockHash     a recent block hash (from around current height)
     */
    public static HNSTxBuilder.SignedTx buildFinalize(
            WalletDB.NameRecord nameRecord,
            byte[] nameUtxoHash,
            int    nameUtxoIndex,
            long   nameValue,
            byte[] blockHash) throws IOException {

        byte[] nameHash       = fromHex(nameRecord.nameHash);
        byte[] heightBytes    = toLE32(nameRecord.claimHeight);
        byte[] nameBytes      = nameRecord.name.getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
        byte[] recipientHash  = HNSAddress.decode(nameRecord.recipientAddress);
        byte[] renewalBytes   = toLE32(nameRecord.renewalCount);

        // Restore owner keys
        byte[] ownerPrivKey   = fromHex(nameRecord.ownerPrivKeyHex);
        byte[] ownerPubKey    = fromHex(nameRecord.ownerPubKeyHex);

        // Restore fee UTXO
        byte[] feePrevHash    = fromHex(nameRecord.feePrevHash);
        byte[] feeAddrHash    = fromHex(nameRecord.feeAddrHash);
        byte[] feePrivKey     = fromHex(nameRecord.feePrivKeyHex);
        byte[] feePubKey      = fromHex(nameRecord.feePubKeyHex);

        // Build FINALIZE covenant
        byte[] finalizeCovenant = buildFinalizeCovenant(
                nameHash, heightBytes, nameBytes, (byte) 0,
                heightBytes,    // claimHeight = same as registration height
                renewalBytes, blockHash);

        // Fee
        long fee    = HNSTxBuilder.MIN_RELAY_FEE;
        long change = nameRecord.feeValue - fee;

        // Build and sign
        byte[] rawTx = buildFinalizeTx(
                nameUtxoHash, nameUtxoIndex, nameValue,
                recipientHash, finalizeCovenant,
                feePrevHash, nameRecord.feePrevIndex,
                nameRecord.feeValue, feeAddrHash, change,
                ownerPrivKey, ownerPubKey,
                feePrivKey, feePubKey);

        // Compute txid
        handshake.node.HNSBlock.Tx parsed =
                handshake.node.HNSBlock.Tx.parse(rawTx, 0);
        byte[] base = Arrays.copyOf(rawTx, parsed.baseSize);
        byte[] txidRaw = HNSTxBuilder.blake256(base);
        HNSTxBuilder.reverseInPlace(txidRaw);
        String txid = HNSTxBuilder.toHex(txidRaw);

        System.out.printf("[Finalize] Built FINALIZE tx for .%s txid=%s%n",
                nameRecord.name, txid);
        return new HNSTxBuilder.SignedTx(rawTx, txid, fee);
    }

    private static byte[] buildFinalizeTx(
            byte[] namePrevHash, int nameOutIdx, long nameValue,
            byte[] recipientAddrHash, byte[] finalizeCovenant,
            byte[] feePrevHash, int feePrevIdx, long feeValue,
            byte[] feeAddrHash, long change,
            byte[] ownerPrivKey, byte[] ownerPubKey,
            byte[] feePrivKey, byte[] feePubKey) throws IOException {

        // hashPrevouts
        ByteArrayOutputStream prevoutsBuf = new ByteArrayOutputStream();
        prevoutsBuf.write(namePrevHash);
        writeU32LE(prevoutsBuf, nameOutIdx);
        prevoutsBuf.write(feePrevHash);
        writeU32LE(prevoutsBuf, feePrevIdx);
        byte[] hashPrevouts = HNSTxBuilder.blake256(prevoutsBuf.toByteArray());

        // hashSequence
        ByteArrayOutputStream seqBuf = new ByteArrayOutputStream();
        writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        byte[] hashSequence = HNSTxBuilder.blake256(seqBuf.toByteArray());

        // hashOutputs
        ByteArrayOutputStream outsBuf = new ByteArrayOutputStream();
        serializeNameOutput(outsBuf, nameValue, recipientAddrHash, finalizeCovenant);
        serializeSimpleOutput(outsBuf, change, feeAddrHash);
        byte[] hashOutputs = HNSTxBuilder.blake256(outsBuf.toByteArray());

        // Sign input 0: name UTXO (owned by sender's address)
        // For FINALIZE, the input comes from the TRANSFER output which has
        // the SENDER's address — so we sign with owner's key
        byte[] preimage0 = buildSighashPreimage(
                hashPrevouts, hashSequence, namePrevHash, nameOutIdx,
                // The TRANSFER output address is the sender's address
                // We need to decode it — it's stored in nameRecord.ownerAddress
                // but we don't have it here. Use ownerPubKey to derive addrHash.
                blake2b160(ownerPubKey),
                nameValue, hashOutputs);
        byte[] hash0 = HNSTxBuilder.blake256(preimage0);
        byte[] sig0Raw = Secp256k1.signCompact(ownerPrivKey, hash0);
        byte[] sig0 = Arrays.copyOf(sig0Raw, 65);
        sig0[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // Sign input 1: fee UTXO
        byte[] preimage1 = buildSighashPreimage(
                hashPrevouts, hashSequence, feePrevHash, feePrevIdx,
                feeAddrHash, feeValue, hashOutputs);
        byte[] hash1 = HNSTxBuilder.blake256(preimage1);
        byte[] sig1Raw = Secp256k1.signCompact(feePrivKey, hash1);
        byte[] sig1 = Arrays.copyOf(sig1Raw, 65);
        sig1[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // Serialize
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeU32LE(bos, HNSTxBuilder.VERSION);

        HNSTxBuilder.writeVarInt(bos, 2);
        bos.write(namePrevHash);
        writeU32LE(bos, nameOutIdx);
        writeU32LE(bos, HNSTxBuilder.SEQUENCE);
        bos.write(feePrevHash);
        writeU32LE(bos, feePrevIdx);
        writeU32LE(bos, HNSTxBuilder.SEQUENCE);

        HNSTxBuilder.writeVarInt(bos, 2);
        serializeNameOutput(bos, nameValue, recipientAddrHash, finalizeCovenant);
        serializeSimpleOutput(bos, change, feeAddrHash);

        writeU32LE(bos, 0); // locktime

        // Witnesses
        HNSTxBuilder.writeVarInt(bos, 2);
        HNSTxBuilder.writeVarBytes(bos, sig0);
        HNSTxBuilder.writeVarBytes(bos, ownerPubKey);
        HNSTxBuilder.writeVarInt(bos, 2);
        HNSTxBuilder.writeVarBytes(bos, sig1);
        HNSTxBuilder.writeVarBytes(bos, feePubKey);

        return bos.toByteArray();
    }

    /** blake2b-160 of pubkey = address hash */
    static byte[] blake2b160(byte[] pubkey) {
        return Blake2b.hash(pubkey, 20);
    }

    /**
     * Builds FINALIZE covenant bytes:
     *   type(1) + varint(7 items)
     *   + nameHash(32) + height(4) + name(var) + flags(1)
     *   + claimHeight(4) + renewalCount(4) + blockHash(32)
     */
    static byte[] buildFinalizeCovenant(byte[] nameHash, byte[] heightBytes,
                                        byte[] nameBytes, byte flags,
                                        byte[] claimHeightBytes,
                                        byte[] renewalCountBytes,
                                        byte[] blockHash) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(COV_FINALIZE);
        HNSTxBuilder.writeVarInt(bos, 7);
        writeVarBytes(bos, nameHash);
        writeVarBytes(bos, heightBytes);
        writeVarBytes(bos, nameBytes);
        writeVarBytes(bos, new byte[]{ flags });
        writeVarBytes(bos, claimHeightBytes);
        writeVarBytes(bos, renewalCountBytes);
        writeVarBytes(bos, blockHash);
        return bos.toByteArray();
    }

    // ── Output serialization ───────────────────────────────────────────────────

    /**
     * Serializes a name output (with covenant).
     * output.write() = value(8) + address.write() + covenant.write()
     * covenant.write() = the raw covenant bytes we built above
     */
    static void serializeNameOutput(ByteArrayOutputStream bos, long value,
                                    byte[] addrHash, byte[] covenantBytes)
            throws IOException {
        writeU64LE(bos, value);
        bos.write(HNSTxBuilder.ADDR_VERSION);
        bos.write(addrHash.length);
        bos.write(addrHash);
        bos.write(covenantBytes);
    }

    /** Serializes a simple NONE-covenant output (HNS payment). */
    static void serializeSimpleOutput(ByteArrayOutputStream bos, long value,
                                      byte[] addrHash) throws IOException {
        writeU64LE(bos, value);
        bos.write(HNSTxBuilder.ADDR_VERSION);
        bos.write(addrHash.length);
        bos.write(addrHash);
        bos.write(0x00); // covenant type NONE
        bos.write(0x00); // varint(0) items
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** SHA3-256 of data (used for nameHash). */
    public static byte[] sha3_256(byte[] data) {
        try {
            // Java's SHA3-256
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }

    static byte[] fromHex(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
        return b;
    }

    static byte[] toLE32(int v) {
        return new byte[]{
                (byte)(v & 0xFF), (byte)((v >> 8) & 0xFF),
                (byte)((v >> 16) & 0xFF), (byte)((v >> 24) & 0xFF)};
    }

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

    static void writeVarBytes(ByteArrayOutputStream bos, byte[] data)
            throws IOException {
        HNSTxBuilder.writeVarInt(bos, data.length);
        bos.write(data);
    }

    private HNSTransferBuilder() {}
}