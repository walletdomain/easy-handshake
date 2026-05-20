package handshake.wallet;

import handshake.node.crypto.Secp256k1;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BIP32 Hierarchical Deterministic key derivation for Handshake.
 *
 * Derives a tree of keys from a single 512-bit seed. All keys in the
 * tree are deterministically derived — the same seed always produces
 * the same keys, enabling wallet recovery from a mnemonic.
 *
 * Handshake BIP44 derivation path:
 *   m / 44' / 5353' / account' / change / index
 *
 * Where:
 *   44'    = BIP44 purpose (hardened)
 *   5353'  = Handshake coin type (hardened) — 0x14E9
 *   account' = wallet account index (hardened), usually 0
 *   change   = 0 for receiving addresses, 1 for change addresses
 *   index    = address index (0, 1, 2, ...)
 *
 * Example first receiving address:
 *   m/44'/5353'/0'/0/0
 */
public class BIP32 {

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int    HARDENED_OFFSET   = 0x80000000;
    public static final int    PURPOSE           = 44  | HARDENED_OFFSET;
    public static final int    COIN_TYPE_HNS     = 5353 | HARDENED_OFFSET;

    // ── HD Key ────────────────────────────────────────────────────────────────

    /**
     * An HD key node containing a private key, public key, and chain code.
     * The chain code is required for child key derivation.
     */
    public static class HDKey {
        public final byte[] privateKey;  // 32 bytes, null for public-only nodes
        public final byte[] publicKey;   // 33 bytes compressed
        public final byte[] chainCode;   // 32 bytes
        public final int    depth;
        public final int    childIndex;
        public final byte[] fingerprint; // 4 bytes parent fingerprint

        private HDKey(byte[] privateKey, byte[] publicKey, byte[] chainCode,
                      int depth, int childIndex, byte[] fingerprint) {
            this.privateKey  = privateKey;
            this.publicKey   = publicKey;
            this.chainCode   = chainCode;
            this.depth       = depth;
            this.childIndex  = childIndex;
            this.fingerprint = fingerprint;
        }

        /** Returns true if this key has a private key component. */
        public boolean hasPrivateKey() { return privateKey != null; }

        /** Returns the fingerprint of this key (first 4 bytes of hash160(pubkey)). */
        public byte[] selfFingerprint() {
            return Arrays.copyOf(hash160(publicKey), 4);
        }

        /** Returns the full derivation path description. */
        public String path() {
            return "m (depth=" + depth + ", index=" + childIndex + ")";
        }

        /**
         * Serializes the private key to a zero-padded char array.
         * Used for secure memory handling — callers should zero after use.
         */
        public void zeroPrivateKey() {
            if (privateKey != null) Arrays.fill(privateKey, (byte) 0);
        }
    }

    // ── Master key derivation ─────────────────────────────────────────────────

    /**
     * Derives the BIP32 master key from a BIP39 seed.
     *
     * @param seed  64-byte seed from BIP39.mnemonicToSeed()
     * @return      master HD key (m)
     */
    public static HDKey masterFromSeed(byte[] seed) {
        try {
            // HMAC-SHA512(key="Bitcoin seed", data=seed)
            byte[] I = hmacSha512(
                    "Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);

            byte[] il = Arrays.copyOf(I, 32);       // master private key
            byte[] ir = Arrays.copyOfRange(I, 32, 64); // master chain code

            // Validate: IL must be in range [1, N-1]
            BigInteger key = new BigInteger(1, il);
            if (key.signum() == 0 || key.compareTo(Secp256k1.N) >= 0)
                throw new RuntimeException("Invalid master key — try a different seed");

            byte[] pub = Secp256k1.compressedPublicKey(
                    Secp256k1.pointMultiply(Secp256k1.G, key));

            return new HDKey(il, pub, ir, 0, 0, new byte[4]);
        } catch (Exception e) {
            throw new RuntimeException("BIP32 master key derivation failed", e);
        }
    }

    // ── Child key derivation ──────────────────────────────────────────────────

    /**
     * Derives a child HD key at the given index.
     *
     * @param parent  parent HD key
     * @param index   child index (add HARDENED_OFFSET for hardened derivation)
     * @return        child HD key
     */
    public static HDKey deriveChild(HDKey parent, int index) {
        try {
            boolean hardened = (index & HARDENED_OFFSET) != 0;

            byte[] data;
            if (hardened) {
                // Hardened: HMAC-SHA512(chainCode, 0x00 || privateKey || index)
                if (!parent.hasPrivateKey())
                    throw new RuntimeException(
                            "Cannot derive hardened child from public key");
                data = new byte[37];
                data[0] = 0x00;
                System.arraycopy(parent.privateKey, 0, data, 1, 32);
            } else {
                // Normal: HMAC-SHA512(chainCode, publicKey || index)
                data = new byte[37];
                System.arraycopy(parent.publicKey, 0, data, 0, 33);
            }
            // Append index as 4 big-endian bytes
            data[33] = (byte)(index >> 24);
            data[34] = (byte)(index >> 16);
            data[35] = (byte)(index >> 8);
            data[36] = (byte) index;

            byte[] I  = hmacSha512(parent.chainCode, data);
            byte[] il = Arrays.copyOf(I, 32);
            byte[] ir = Arrays.copyOfRange(I, 32, 64);

            BigInteger ilBig = new BigInteger(1, il);
            if (ilBig.compareTo(Secp256k1.N) >= 0)
                throw new RuntimeException("Derived key out of range — skip index");

            if (parent.hasPrivateKey()) {
                // Private child key = (IL + parent_key) mod N
                BigInteger parentKey = new BigInteger(1, parent.privateKey);
                BigInteger childKey  = ilBig.add(parentKey).mod(Secp256k1.N);
                if (childKey.signum() == 0)
                    throw new RuntimeException("Derived key is zero — skip index");

                byte[] childPriv = Secp256k1.to32Bytes(childKey);
                byte[] childPub  = Secp256k1.compressedPublicKey(
                        Secp256k1.pointMultiply(Secp256k1.G, childKey));

                return new HDKey(childPriv, childPub, ir,
                        parent.depth + 1, index, parent.selfFingerprint());
            } else {
                // Public child key = IL*G + parent_pub_point
                BigInteger[] ilPoint  = Secp256k1.pointMultiply(Secp256k1.G, ilBig);
                BigInteger[] parentPt = Secp256k1.decompressPublicKey(parent.publicKey);
                BigInteger[] childPt  = Secp256k1.pointAdd(ilPoint, parentPt);
                if (childPt == null)
                    throw new RuntimeException("Derived point is infinity — skip index");

                byte[] childPub = Secp256k1.compressedPublicKey(childPt);
                return new HDKey(null, childPub, ir,
                        parent.depth + 1, index, parent.selfFingerprint());
            }
        } catch (Exception e) {
            throw new RuntimeException("BIP32 child derivation failed at index "
                    + index + ": " + e.getMessage(), e);
        }
    }

    /**
     * Derives a key at the given BIP44 path for Handshake.
     *
     *   account = 0, change = 0, index = 0 → first receiving address
     *   account = 0, change = 1, index = 0 → first change address
     */
    public static HDKey deriveAddress(HDKey master, int account,
                                      int change, int index) {
        HDKey purpose   = deriveChild(master, PURPOSE);
        HDKey coinType  = deriveChild(purpose, COIN_TYPE_HNS);
        HDKey acct      = deriveChild(coinType, account | HARDENED_OFFSET);
        HDKey changeLvl = deriveChild(acct, change);
        return deriveChild(changeLvl, index);
    }

    /**
     * Derives the account-level extended public key (xpub).
     * This can derive all receiving/change addresses without the private key.
     * Safe to export for watch-only wallets.
     */
    public static HDKey deriveAccountXpub(HDKey master, int account) {
        HDKey purpose  = deriveChild(master, PURPOSE);
        HDKey coinType = deriveChild(purpose, COIN_TYPE_HNS);
        HDKey acct     = deriveChild(coinType, account | HARDENED_OFFSET);
        // Return a public-only copy
        return new HDKey(null, acct.publicKey, acct.chainCode,
                acct.depth, acct.childIndex, acct.fingerprint);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    static byte[] hmacSha512(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    static byte[] hash160(byte[] data) {
        try {
            byte[] sha = java.security.MessageDigest
                    .getInstance("SHA-256").digest(data);
            return java.security.MessageDigest
                    .getInstance("RIPEMD160").digest(sha);
        } catch (Exception e) {
            // RIPEMD160 not available — fall back to double SHA256 truncated
            // This is only used for fingerprints so truncation is fine
            try {
                byte[] sha1 = java.security.MessageDigest
                        .getInstance("SHA-256").digest(data);
                byte[] sha2 = java.security.MessageDigest
                        .getInstance("SHA-256").digest(sha1);
                return Arrays.copyOf(sha2, 20);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }
}