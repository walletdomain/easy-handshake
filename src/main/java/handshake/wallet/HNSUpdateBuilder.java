package handshake.wallet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Builds UPDATE covenant transactions for Handshake DNS record management.
 *
 * UPDATE covenant structure (from rules.js hasSaneCovenants):
 *   items[0] = nameHash (32 bytes) — SHA3-256 of name
 *   items[1] = height   (4 bytes LE) — registration height
 *   items[2] = data     (0-512 bytes) — encoded resource records
 *
 * UPDATE can spend from: REGISTER, UPDATE, RENEW, or FINALIZE outputs.
 *
 * Rules from verifyCovenants():
 *   - output.value must equal coin.value (locked forever)
 *   - output.address must equal coin.address (stays at same address)
 *   - nameHash and height must match the input covenant
 *
 * Sighash is identical to HNS sends (same signatureHash() method).
 */
public class HNSUpdateBuilder {

    public static final int COV_UPDATE = 7;

    /**
     * Builds and signs an UPDATE covenant transaction.
     *
     * @param nameRecord    the NameRecord from WalletDB
     * @param nameUtxoValue dollarydoos locked in the name UTXO
     * @param ownerAddrHash 20-byte hash of owner address
     * @param ownerPrivKey  32-byte private key
     * @param ownerPubKey   33-byte compressed public key
     * @param records       DNS resource records to store on-chain
     * @param feeSource     separate spendable UTXO for fee
     */
    public static HNSTxBuilder.SignedTx buildUpdate(
            WalletDB.NameRecord nameRecord,
            long   nameUtxoValue,
            byte[] ownerAddrHash,
            byte[] ownerPrivKey,
            byte[] ownerPubKey,
            List<HNSResource.Record> records,
            HNSTxBuilder.UtxoInput feeSource) throws IOException {

        byte[] nameHash    = HNSTransferBuilder.fromHex(nameRecord.nameHash);
        byte[] heightBytes = HNSTransferBuilder.toLE32(nameRecord.claimHeight);
        byte[] resourceData = HNSResource.encode(records);
        byte[] namePrevHash = HNSTransferBuilder.fromHex(nameRecord.utxoTxHash);

        // Build UPDATE covenant: [nameHash(32), height(4), data(0-512)]
        byte[] updateCovenant = buildUpdateCovenant(nameHash, heightBytes, resourceData);

        long fee    = HNSTxBuilder.MIN_RELAY_FEE;
        long change = feeSource.value - fee;

        byte[] rawTx = buildUpdateTx(
                namePrevHash, nameRecord.utxoIndex, nameUtxoValue,
                ownerAddrHash, updateCovenant,
                feeSource, change,
                ownerPrivKey, ownerPubKey);

        // Compute txid
        handshake.node.HNSBlock.Tx parsed =
                handshake.node.HNSBlock.Tx.parse(rawTx, 0);
        byte[] base    = Arrays.copyOf(rawTx, parsed.baseSize);
        byte[] txidRaw = HNSTxBuilder.blake256(base);
        HNSTxBuilder.reverseInPlace(txidRaw);
        String txid = HNSTxBuilder.toHex(txidRaw);

        System.out.printf("[Update] Built UPDATE tx for .%s txid=%s records=%d%n",
                nameRecord.name, txid, records.size());
        return new HNSTxBuilder.SignedTx(rawTx, txid, fee);
    }

    // ── UPDATE covenant ───────────────────────────────────────────────────────

    static byte[] buildUpdateCovenant(byte[] nameHash, byte[] heightBytes,
                                      byte[] resourceData) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(COV_UPDATE);           // covenant type
        HNSTxBuilder.writeVarInt(bos, 3); // 3 items
        writeVarBytes(bos, nameHash);
        writeVarBytes(bos, heightBytes);
        writeVarBytes(bos, resourceData);
        return bos.toByteArray();
    }

    // ── Transaction builder ───────────────────────────────────────────────────

    private static byte[] buildUpdateTx(
            byte[] namePrevHash, int nameOutIdx, long nameValue,
            byte[] ownerAddrHash, byte[] updateCovenant,
            HNSTxBuilder.UtxoInput feeUtxo, long change,
            byte[] ownerPrivKey, byte[] ownerPubKey) throws IOException {

        // hashPrevouts
        ByteArrayOutputStream prevoutsBuf = new ByteArrayOutputStream();
        prevoutsBuf.write(namePrevHash);
        HNSTransferBuilder.writeU32LE(prevoutsBuf, nameOutIdx);
        prevoutsBuf.write(feeUtxo.prevHash);
        HNSTransferBuilder.writeU32LE(prevoutsBuf, feeUtxo.prevIndex);
        byte[] hashPrevouts = HNSTxBuilder.blake256(prevoutsBuf.toByteArray());

        // hashSequence
        ByteArrayOutputStream seqBuf = new ByteArrayOutputStream();
        HNSTransferBuilder.writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        HNSTransferBuilder.writeU32LE(seqBuf, HNSTxBuilder.SEQUENCE);
        byte[] hashSequence = HNSTxBuilder.blake256(seqBuf.toByteArray());

        // hashOutputs — name output + change output
        ByteArrayOutputStream outsBuf = new ByteArrayOutputStream();
        serializeNameOutput(outsBuf, nameValue, ownerAddrHash, updateCovenant);
        HNSTransferBuilder.serializeSimpleOutput(outsBuf, change, feeUtxo.addrHash);
        byte[] hashOutputs = HNSTxBuilder.blake256(outsBuf.toByteArray());

        // Sign input 0: name UTXO
        byte[] preimage0 = HNSTransferBuilder.buildSighashPreimage(
                hashPrevouts, hashSequence, namePrevHash, nameOutIdx,
                ownerAddrHash, nameValue, hashOutputs);
        byte[] hash0  = HNSTxBuilder.blake256(preimage0);
        byte[] sig0   = Arrays.copyOf(Secp256k1.signCompact(ownerPrivKey, hash0), 65);
        sig0[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // Sign input 1: fee UTXO
        byte[] preimage1 = HNSTransferBuilder.buildSighashPreimage(
                hashPrevouts, hashSequence, feeUtxo.prevHash, feeUtxo.prevIndex,
                feeUtxo.addrHash, feeUtxo.value, hashOutputs);
        byte[] hash1  = HNSTxBuilder.blake256(preimage1);
        byte[] sig1   = Arrays.copyOf(Secp256k1.signCompact(feeUtxo.privateKey, hash1), 65);
        sig1[64] = (byte) HNSTxBuilder.SIGHASH_ALL;

        // Serialize
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HNSTransferBuilder.writeU32LE(bos, HNSTxBuilder.VERSION);

        HNSTxBuilder.writeVarInt(bos, 2);
        bos.write(namePrevHash);
        HNSTransferBuilder.writeU32LE(bos, nameOutIdx);
        HNSTransferBuilder.writeU32LE(bos, HNSTxBuilder.SEQUENCE);
        bos.write(feeUtxo.prevHash);
        HNSTransferBuilder.writeU32LE(bos, feeUtxo.prevIndex);
        HNSTransferBuilder.writeU32LE(bos, HNSTxBuilder.SEQUENCE);

        HNSTxBuilder.writeVarInt(bos, 2);
        serializeNameOutput(bos, nameValue, ownerAddrHash, updateCovenant);
        HNSTransferBuilder.serializeSimpleOutput(bos, change, feeUtxo.addrHash);

        HNSTransferBuilder.writeU32LE(bos, 0); // locktime

        // Witnesses
        HNSTxBuilder.writeVarInt(bos, 2);
        HNSTxBuilder.writeVarBytes(bos, sig0);
        HNSTxBuilder.writeVarBytes(bos, ownerPubKey);
        HNSTxBuilder.writeVarInt(bos, 2);
        HNSTxBuilder.writeVarBytes(bos, sig1);
        HNSTxBuilder.writeVarBytes(bos, feeUtxo.publicKey);

        return bos.toByteArray();
    }

    static void serializeNameOutput(ByteArrayOutputStream bos, long value,
                                    byte[] addrHash, byte[] covenantBytes)
            throws IOException {
        HNSTransferBuilder.writeU64LE(bos, value);
        bos.write(HNSTxBuilder.ADDR_VERSION);
        bos.write(addrHash.length);
        bos.write(addrHash);
        bos.write(covenantBytes);
    }

    static void writeVarBytes(ByteArrayOutputStream bos, byte[] data)
            throws IOException {
        HNSTxBuilder.writeVarInt(bos, data.length);
        bos.write(data);
    }
}