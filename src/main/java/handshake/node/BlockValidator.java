package handshake.node;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Validates new blocks before they are written to the database.
 *
 * Three checks are applied in order of increasing cost:
 *
 *   1. Block hash    — cheapest: one hash comparison against stored header
 *   2. Proof of work — cheap: compare hash against difficulty target from bits
 *   3. Merkle root   — moderate: hash all transactions and verify root
 *
 * These checks are most important for new blocks arriving via ChainFollower
 * every ~10 minutes. Historical blocks during initial sync were already
 * validated by the block hash check in HNSPeer.syncBlocks().
 */
public class BlockValidator {

    /**
     * Validates a block fully before it is written to the database.
     *
     * @param block         the parsed block
     * @param header        the trusted block header from our database
     * @param height        block height (for error messages)
     * @throws SecurityException if any validation check fails
     */
    public static void validate(HNSBlock block,
                                HNSPeer.BlockHeader header,
                                int height) {
        verifyBlockHash(block, header, height);
        verifyProofOfWork(header, height);
        verifyMerkleRoot(block, header, height);
    }

    // -------------------------------------------------------------------------
    // Check 1 — Block hash
    // -------------------------------------------------------------------------

    /**
     * Verifies that the block's header hashes to the expected value.
     * This is the primary chain membership check — if it passes, the block
     * belongs to our chain.
     */
    private static void verifyBlockHash(HNSBlock block,
                                        HNSPeer.BlockHeader header,
                                        int height) {
        // Parse the header from the block's raw header bytes
        HNSPeer.BlockHeader blockHeader = HNSPeer.BlockHeader.parse(block.header, 0);
        byte[] actualHash   = blockHeader.hash();
        byte[] expectedHash = header.hash();

        if (!Arrays.equals(actualHash, expectedHash))
            throw new SecurityException(
                    "Block hash mismatch at height " + height
                            + ": expected " + toHex(expectedHash)
                            + " got "       + toHex(actualHash));
    }

    // -------------------------------------------------------------------------
    // Check 2 — Proof of work
    // -------------------------------------------------------------------------

    /**
     * Verifies that the block hash meets the difficulty target encoded in bits.
     *
     * The target is derived from bits using the compact encoding:
     *   target = mantissa × 2^(8 × (exponent - 3))
     *
     * The block hash (as a big-endian integer) must be ≤ target.
     * This matches HSD's consensus.verifyPOW() implementation.
     */
    private static void verifyProofOfWork(HNSPeer.BlockHeader header, int height) {
        BigInteger target = fromCompact(header.bits);

        if (target.signum() <= 0 || target.bitLength() > 256)
            throw new SecurityException(
                    "Invalid difficulty target at height " + height
                            + ": bits=0x" + Integer.toHexString(header.bits));

        // Block hash interpreted as big-endian unsigned integer
        byte[] hashBytes = header.hash();
        BigInteger hashInt = new BigInteger(1, hashBytes);

        if (hashInt.compareTo(target) > 0)
            throw new SecurityException(
                    "Proof of work failed at height " + height
                            + ": hash " + toHex(hashBytes)
                            + " exceeds target " + target.toString(16));
    }

    /**
     * Decodes a compact difficulty target (same as Bitcoin's nBits / HSD's bits).
     * Format: top byte = exponent, lower 23 bits = mantissa.
     */
    private static BigInteger fromCompact(int compact) {
        int exponent  = (compact >>> 24) & 0xFF;
        int negative  = (compact >>> 23) & 0x01;
        long mantissa = compact & 0x7FFFFFL;

        if (mantissa == 0) return BigInteger.ZERO;

        BigInteger target;
        if (exponent <= 3) {
            mantissa >>= 8 * (3 - exponent);
            target = BigInteger.valueOf(mantissa);
        } else {
            target = BigInteger.valueOf(mantissa)
                    .shiftLeft(8 * (exponent - 3));
        }

        if (negative != 0) target = target.negate();
        return target;
    }

    // -------------------------------------------------------------------------
    // Check 3 — Merkle root
    // -------------------------------------------------------------------------

    /**
     * Verifies that the transactions in the block hash to the merkle root
     * stored in the header.
     *
     * Handshake uses Blake2b-256 for txid computation (base tx only, no witness).
     * The merkle tree is computed by repeatedly hashing pairs of txids until
     * a single root remains, matching Bitcoin's merkle tree construction.
     */
    private static void verifyMerkleRoot(HNSBlock block,
                                         HNSPeer.BlockHeader header,
                                         int height) {
        if (block.txs.isEmpty()) {
            if (!Arrays.equals(header.merkleRoot, new byte[32]))
                throw new SecurityException(
                        "Empty block has non-zero merkle root at height " + height);
            return;
        }

        byte[][] txids = new byte[block.txs.size()][];
        for (int i = 0; i < block.txs.size(); i++)
            txids[i] = computeTxId(block.txs.get(i));

        byte[] computedRoot = buildMerkleRoot(txids);

        if (!Arrays.equals(computedRoot, header.merkleRoot))
            throw new SecurityException(
                    "Merkle root mismatch at height " + height
                            + ": expected " + toHex(header.merkleRoot)
                            + " got "       + toHex(computedRoot));
    }

    /**
     * Computes the txid (Blake2b-256 of the base/non-witness transaction bytes).
     * Witness bytes are excluded, matching HSD's TX.hash() implementation.
     */
    private static byte[] computeTxId(HNSBlock.Tx tx) {
        // baseSize is recorded during parsing — exact byte count before witnesses
        byte[] base = Arrays.copyOf(tx.raw, tx.baseSize);
        return HNSPeer.Blake2b.hash(base, 32);
    }

    /**
     * EMPTY_HASH = blake2b(empty buffer) per hsd-dev.org/protocol/merkle.html
     */
    private static final byte[] EMPTY_HASH =
            HNSPeer.Blake2b.hash(new byte[0], 32);

    /**
     * Builds a Handshake merkle root from an array of txids.
     *
     * Follows RFC 6962 + RFC 7574 per hsd-dev.org/protocol/merkle.html:
     *   EMPTY_HASH = blake2b(empty buffer)
     *   Leaf:     blake2b(0x00 || txid)
     *   Internal: blake2b(0x01 || left || right)
     *   Odd node: paired with EMPTY_HASH at each level (NOT power-of-2 padding)
     *
     * For n=5: leaves a,b,c,d,e
     *   Level 0: a=H(0x00||d0), b=H(0x00||d1), c=H(0x00||d2), d=H(0x00||d3), e=H(0x00||d4)
     *   Level 1: f=H(0x01||a||b), g=H(0x01||c||d), h=H(0x01||e||EMPTY_HASH)
     *   Level 2: i=H(0x01||f||g), j=H(0x01||h||EMPTY_HASH)
     *   Root:    H(0x01||i||j)
     */
    private static byte[] buildMerkleRoot(byte[][] txids) {
        if (txids.length == 0) return EMPTY_HASH.clone();

        // Step 1: hash each leaf as blake2b(0x00 || txid)
        byte[][] level = new byte[txids.length][];
        for (int i = 0; i < txids.length; i++) {
            byte[] leaf = new byte[33];
            leaf[0] = 0x00;
            System.arraycopy(txids[i], 0, leaf, 1, 32);
            level[i] = HNSPeer.Blake2b.hash(leaf, 32);
        }

        // Step 2: reduce level by level
        // At each level, pair adjacent nodes. If odd count, last node
        // is paired with EMPTY_HASH (not duplicated, not power-of-2 padded)
        while (level.length > 1) {
            int pairCount = (level.length + 1) / 2;
            byte[][] next = new byte[pairCount][];
            for (int i = 0; i < pairCount; i++) {
                byte[] left  = level[i * 2];
                byte[] right = (i * 2 + 1 < level.length)
                        ? level[i * 2 + 1]
                        : EMPTY_HASH;
                byte[] node = new byte[65];
                node[0] = 0x01;
                System.arraycopy(left,  0, node,  1, 32);
                System.arraycopy(right, 0, node, 33, 32);
                next[i] = HNSPeer.Blake2b.hash(node, 32);
            }
            level = next;
        }
        return level[0];
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}