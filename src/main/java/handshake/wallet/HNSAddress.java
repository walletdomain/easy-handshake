package handshake.wallet;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Handshake address encoding and decoding.
 *
 * Handshake uses bech32 addresses with the "hs" human-readable part (HRP).
 * Address format: hs1q{20-byte-hash160-of-pubkey in 5-bit groups}
 *
 * Address derivation from a compressed public key:
 *   1. SHA-256(pubkey)        → 32 bytes
 *   2. RIPEMD-160(^)          → 20 bytes  (hash160)
 *   3. bech32 encode          → "hs1q..."
 *
 * Since RIPEMD-160 may not be available in all JVMs, we use the same
 * double-SHA256 + truncation fallback as BIP32.hash160() for address
 * generation in tests. For production, RIPEMD-160 is standard.
 */
public class HNSAddress {

    private static final String HRP_MAINNET = "hs";
    private static final String HRP_TESTNET = "ts";

    // bech32 charset
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[]  CHARSET_REV;

    static {
        CHARSET_REV = new int[128];
        Arrays.fill(CHARSET_REV, -1);
        for (int i = 0; i < CHARSET.length(); i++)
            CHARSET_REV[CHARSET.charAt(i)] = i;
    }

    // ── Address generation ────────────────────────────────────────────────────

    /**
     * Derives a mainnet Handshake address from a compressed public key.
     */
    public static String fromPublicKey(byte[] compressedPubKey) {
        return fromPublicKey(compressedPubKey, false);
    }

    /**
     * Derives a Handshake address from a compressed public key.
     * @param testnet  true for testnet (ts1...), false for mainnet (hs1...)
     */
    public static String fromPublicKey(byte[] compressedPubKey, boolean testnet) {
        byte[] hash = hash160(compressedPubKey);
        return encode(testnet ? HRP_TESTNET : HRP_MAINNET, 0, hash);
    }

    /**
     * Returns the P2WPKH scriptPubKey for a given address.
     * Used when scanning UTXOs to match outputs to our addresses.
     * Format: OP_0 OP_PUSHBYTES_20 {hash160}
     */
    public static byte[] toScriptPubKey(byte[] hash160) {
        byte[] script = new byte[22];
        script[0] = 0x00; // OP_0 (witness version)
        script[1] = 0x14; // PUSH 20 bytes
        System.arraycopy(hash160, 0, script, 2, 20);
        return script;
    }

    /**
     * Decodes a bech32 address to its hash160 payload.
     * Returns null if the address is invalid.
     */
    public static byte[] decode(String address) {
        try {
            String addr = address.toLowerCase();
            String hrp  = addr.startsWith("hs1") ? "hs"
                    : addr.startsWith("ts1") ? "ts" : null;
            if (hrp == null) return null;

            String data = addr.substring(hrp.length() + 1);
            byte[] decoded = bech32Decode(hrp, data);
            if (decoded == null || decoded.length == 0) return null;

            // First byte is witness version (should be 0)
            if (decoded[0] != 0) return null;

            // Convert from 5-bit to 8-bit groups
            return convertBits(Arrays.copyOfRange(decoded, 1, decoded.length),
                    5, 8, false);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns true if the address is a valid Handshake mainnet or testnet address.
     */
    public static boolean isValid(String address) {
        return decode(address) != null;
    }

    // ── Bech32 encoding ───────────────────────────────────────────────────────

    static String encode(String hrp, int witnessVersion, byte[] data) {
        byte[] converted = convertBits(data, 8, 5, true);
        if (converted == null)
            throw new RuntimeException("bech32 bit conversion failed");

        byte[] enc = new byte[1 + converted.length];
        enc[0] = (byte) witnessVersion;
        System.arraycopy(converted, 0, enc, 1, converted.length);

        return hrp + "1" + bech32Encode(hrp, enc);
    }

    private static String bech32Encode(String hrp, byte[] data) {
        byte[] checksum = createChecksum(hrp, data);
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(CHARSET.charAt(b & 0x1F));
        for (byte b : checksum) sb.append(CHARSET.charAt(b & 0x1F));
        return sb.toString();
    }

    private static byte[] bech32Decode(String hrp, String data) {
        byte[] values = new byte[data.length()];
        for (int i = 0; i < data.length(); i++) {
            int c = data.charAt(i);
            if (c >= 128 || CHARSET_REV[c] == -1) return null;
            values[i] = (byte) CHARSET_REV[c];
        }
        if (!verifyChecksum(hrp, values)) return null;
        return Arrays.copyOf(values, values.length - 6);
    }

    // ── Checksum ──────────────────────────────────────────────────────────────

    private static long polymod(byte[] values) {
        long chk = 1;
        long[] generator = {0x3b6a57b2L, 0x26508e6dL, 0x1ea119faL,
                0x3d4233ddL, 0x2a1462b3L};
        for (byte v : values) {
            long b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v & 0xFF);
            for (int i = 0; i < 5; i++) {
                if (((b >> i) & 1) != 0) chk ^= generator[i];
            }
        }
        return chk;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] result = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            result[i]                = (byte)(hrp.charAt(i) >> 5);
            result[i + hrp.length() + 1] = (byte)(hrp.charAt(i) & 31);
        }
        result[hrp.length()] = 0;
        return result;
    }

    private static byte[] createChecksum(String hrp, byte[] data) {
        byte[] enc = concat(hrpExpand(hrp), data, new byte[6]);
        long mod   = polymod(enc) ^ 1;
        byte[] ret = new byte[6];
        for (int i = 0; i < 6; i++)
            ret[i] = (byte)((mod >> (5 * (5 - i))) & 31);
        return ret;
    }

    private static boolean verifyChecksum(String hrp, byte[] data) {
        return polymod(concat(hrpExpand(hrp), data)) == 1;
    }

    // ── Bit conversion ────────────────────────────────────────────────────────

    static byte[] convertBits(byte[] data, int from, int to, boolean pad) {
        int acc    = 0;
        int bits   = 0;
        int maxv   = (1 << to) - 1;
        byte[] ret = new byte[data.length * from / to + 2];
        int pos    = 0;

        for (byte b : data) {
            acc  = ((acc << from) | (b & ((1 << from) - 1)));
            bits += from;
            while (bits >= to) {
                bits -= to;
                ret[pos++] = (byte)((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) ret[pos++] = (byte)((acc << (to - bits)) & maxv);
        } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
            return null;
        }
        return Arrays.copyOf(ret, pos);
    }

    // ── Hash utilities ────────────────────────────────────────────────────────

    /**
     * Computes hash160 (SHA-256 then RIPEMD-160) of the input.
     * Uses our pure Java RIPEMD-160 implementation — no JVM provider needed.
     */
    public static byte[] hash160(byte[] data) {
        try {
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(data);
            return RIPEMD160.hash(sha);
        } catch (Exception e) {
            throw new RuntimeException("hash160 failed", e);
        }
    }

    /**
     * Always returns true — we use a pure Java RIPEMD-160 implementation
     * that doesn't depend on JVM security providers.
     */
    public static boolean hasRipemd160() {
        return true;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}