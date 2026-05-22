package handshake.wallet;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Pure Java secp256k1 elliptic curve implementation.
 *
 * Curve equation: y² = x³ + 7  (mod p)
 *
 * Used for:
 *   - ECDSA signing of Handshake transactions
 *   - Public key derivation (already used in BIP32 via compressed pubkey)
 *   - Signature verification
 *
 * All field arithmetic is mod p (prime field).
 * All scalar arithmetic is mod n (curve order).
 *
 * References:
 *   https://en.bitcoin.it/wiki/Secp256k1
 *   https://www.secg.org/sec2-v2.pdf
 */
public final class Secp256k1 {

    // ── Curve parameters ──────────────────────────────────────────────────────

    /** Field prime: p = 2^256 - 2^32 - 977 */
    static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    /** Curve order (number of points on the curve) */
    static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /** Generator point X coordinate */
    static final BigInteger GX = new BigInteger(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);

    /** Generator point Y coordinate */
    static final BigInteger GY = new BigInteger(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    /** Generator point G */
    static final Point G = new Point(GX, GY);

    /** Half of curve order — used for low-S normalization */
    private static final BigInteger HALF_N = N.shiftRight(1);

    static final BigInteger ZERO = BigInteger.ZERO;
    static final BigInteger ONE  = BigInteger.ONE;
    static final BigInteger TWO  = BigInteger.TWO;
    static final BigInteger THREE = BigInteger.valueOf(3);

    // ── Point ─────────────────────────────────────────────────────────────────

    /**
     * An affine point on secp256k1.
     * The point at infinity is represented as (null, null).
     */
    public static final class Point {
        public final BigInteger x;
        public final BigInteger y;

        public static final Point INFINITY = new Point(null, null);

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public boolean isInfinity() { return x == null; }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Point)) return false;
            Point p = (Point) o;
            if (isInfinity() && p.isInfinity()) return true;
            if (isInfinity() || p.isInfinity()) return false;
            return x.equals(p.x) && y.equals(p.y);
        }

        @Override
        public String toString() {
            if (isInfinity()) return "Point(INFINITY)";
            return "Point(" + x.toString(16) + ", " + y.toString(16) + ")";
        }
    }

    // ── Point arithmetic ──────────────────────────────────────────────────────

    /**
     * Point addition: R = P + Q
     * Handles the case where P == Q (doubling) and P == -Q (infinity).
     */
    public static Point add(Point p, Point q) {
        if (p.isInfinity()) return q;
        if (q.isInfinity()) return p;

        if (p.x.equals(q.x)) {
            if (!p.y.equals(q.y)) return Point.INFINITY; // P == -Q
            return doublePoint(p);
        }

        // lambda = (y2 - y1) / (x2 - x1) mod p
        BigInteger lam = q.y.subtract(p.y)
                .multiply(q.x.subtract(p.x).modInverse(P))
                .mod(P);

        BigInteger xr = lam.multiply(lam).subtract(p.x).subtract(q.x).mod(P);
        BigInteger yr = lam.multiply(p.x.subtract(xr)).subtract(p.y).mod(P);

        return new Point(xr, yr);
    }

    /**
     * Point doubling: R = 2P
     */
    public static Point doublePoint(Point p) {
        if (p.isInfinity()) return p;

        // lambda = (3x² + a) / (2y) mod p  — a=0 for secp256k1
        BigInteger lam = THREE.multiply(p.x).multiply(p.x)
                .multiply(TWO.multiply(p.y).modInverse(P))
                .mod(P);

        BigInteger xr = lam.multiply(lam).subtract(TWO.multiply(p.x)).mod(P);
        BigInteger yr = lam.multiply(p.x.subtract(xr)).subtract(p.y).mod(P);

        return new Point(xr, yr);
    }

    /**
     * Scalar multiplication: R = k * P
     * Uses double-and-add with a left-to-right binary method.
     * Constant-time variant is not required here (server-side key ops).
     */
    public static Point multiply(BigInteger k, Point p) {
        k = k.mod(N);
        if (k.equals(ZERO) || p.isInfinity()) return Point.INFINITY;

        Point result = Point.INFINITY;
        Point addend = p;

        while (k.signum() > 0) {
            if (k.testBit(0)) result = add(result, addend);
            addend = doublePoint(addend);
            k = k.shiftRight(1);
        }

        return result;
    }

    // ── Key operations ────────────────────────────────────────────────────────

    /**
     * Derives the compressed public key (33 bytes) from a 32-byte private key.
     * Format: 0x02 or 0x03 prefix byte + 32-byte X coordinate.
     */
    public static byte[] privateKeyToPublicKey(byte[] privateKey) {
        BigInteger d = new BigInteger(1, privateKey);
        Point Q = multiply(d, G);
        return compressPoint(Q);
    }

    /**
     * Encodes a curve point as a 33-byte compressed public key.
     */
    public static byte[] compressPoint(Point p) {
        byte[] x = toBytes32(p.x);
        byte[] result = new byte[33];
        result[0] = (byte)(p.y.testBit(0) ? 0x03 : 0x02);
        System.arraycopy(x, 0, result, 1, 32);
        return result;
    }

    // ── ECDSA signing ─────────────────────────────────────────────────────────

    /**
     * Signs a 32-byte hash with a 32-byte private key.
     * Returns a 64-byte compact signature (r || s), NOT DER encoded.
     * This matches hsd's secp256k1.sign() which returns 64 bytes.
     * Low-S normalization applied per BIP62.
     */
    public static byte[] signCompact(byte[] privateKey, byte[] hash) {
        BigInteger d = new BigInteger(1, privateKey);
        BigInteger z = new BigInteger(1, hash);
        BigInteger k = generateK(privateKey, hash);

        Point R = multiply(k, G);
        BigInteger r = R.x.mod(N);
        if (r.equals(ZERO)) throw new RuntimeException("r == 0, bad nonce");

        BigInteger s = k.modInverse(N)
                .multiply(z.add(r.multiply(d)))
                .mod(N);

        if (s.compareTo(HALF_N) > 0) s = N.subtract(s);
        if (s.equals(ZERO)) throw new RuntimeException("s == 0");

        // Return 64-byte compact: r (32 bytes) || s (32 bytes)
        byte[] out = new byte[64];
        byte[] rb  = toBytes32(r);
        byte[] sb  = toBytes32(s);
        System.arraycopy(rb, 0, out,  0, 32);
        System.arraycopy(sb, 0, out, 32, 32);
        return out;
    }

    /**
     * Signs a 32-byte hash with a 32-byte private key.
     * Uses RFC 6979 deterministic nonce generation.
     * Returns a DER-encoded signature with low-S normalization.
     */
    public static byte[] sign(byte[] privateKey, byte[] hash) {
        BigInteger d = new BigInteger(1, privateKey);
        BigInteger z = new BigInteger(1, hash);

        // Generate deterministic nonce k via RFC 6979
        BigInteger k = generateK(privateKey, hash);

        // R = k * G
        Point R = multiply(k, G);
        BigInteger r = R.x.mod(N);
        if (r.equals(ZERO)) throw new RuntimeException("r == 0, bad nonce");

        // s = k^-1 * (z + r*d) mod n
        BigInteger s = k.modInverse(N)
                .multiply(z.add(r.multiply(d)))
                .mod(N);

        // Low-S normalization (BIP62 / Handshake requirement)
        if (s.compareTo(HALF_N) > 0) s = N.subtract(s);
        if (s.equals(ZERO)) throw new RuntimeException("s == 0, bad signature");

        return derEncode(r, s);
    }

    /**
     * Verifies a DER-encoded ECDSA signature.
     */
    public static boolean verify(byte[] publicKey, byte[] hash, byte[] derSig) {
        BigInteger[] rs = derDecode(derSig);
        BigInteger r = rs[0], s = rs[1], z = new BigInteger(1, hash);

        if (r.signum() <= 0 || r.compareTo(N) >= 0) return false;
        if (s.signum() <= 0 || s.compareTo(N) >= 0) return false;

        Point Q = decodePublicKey(publicKey);
        BigInteger sInv = s.modInverse(N);
        BigInteger u1   = z.multiply(sInv).mod(N);
        BigInteger u2   = r.multiply(sInv).mod(N);
        Point point = add(multiply(u1, G), multiply(u2, Q));

        if (point.isInfinity()) return false;
        return point.x.mod(N).equals(r);
    }

    // ── RFC 6979 deterministic nonce ──────────────────────────────────────────

    /**
     * Generates a deterministic nonce k for ECDSA per RFC 6979.
     * This ensures signatures are reproducible and avoids weak RNG issues.
     */
    static BigInteger generateK(byte[] privateKey, byte[] hash) {
        // Initial V and K
        byte[] v = new byte[32]; Arrays.fill(v, (byte) 0x01);
        byte[] k = new byte[32]; Arrays.fill(k, (byte) 0x00);

        // K = HMAC-SHA256(K, V || 0x00 || privKey || hash)
        k = hmacSha256(k, concat(v, new byte[]{0x00}, privateKey, hash));
        v = hmacSha256(k, v);

        // K = HMAC-SHA256(K, V || 0x01 || privKey || hash)
        k = hmacSha256(k, concat(v, new byte[]{0x01}, privateKey, hash));
        v = hmacSha256(k, v);

        // Generate candidate k values
        for (int attempt = 0; attempt < 1000; attempt++) {
            v = hmacSha256(k, v);
            BigInteger candidate = new BigInteger(1, v);
            if (candidate.signum() > 0 && candidate.compareTo(N) < 0)
                return candidate;
            k = hmacSha256(k, concat(v, new byte[]{0x00}));
            v = hmacSha256(k, v);
        }
        throw new RuntimeException("RFC 6979 failed to generate valid k");
    }

    // ── DER encoding ──────────────────────────────────────────────────────────

    /**
     * DER-encodes an ECDSA (r, s) signature pair.
     * Format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
     */
    public static byte[] derEncode(BigInteger r, BigInteger s) {
        byte[] rb = toUnsignedBytes(r);
        byte[] sb = toUnsignedBytes(s);
        int len = 2 + rb.length + 2 + sb.length;
        byte[] out = new byte[2 + len];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = (byte) len;
        out[i++] = 0x02;
        out[i++] = (byte) rb.length;
        System.arraycopy(rb, 0, out, i, rb.length); i += rb.length;
        out[i++] = 0x02;
        out[i++] = (byte) sb.length;
        System.arraycopy(sb, 0, out, i, sb.length);
        return out;
    }

    /**
     * Decodes a DER-encoded signature to (r, s).
     */
    public static BigInteger[] derDecode(byte[] der) {
        int i = 0;
        if (der[i++] != 0x30) throw new IllegalArgumentException("Bad DER prefix");
        i++; // skip total length
        if (der[i++] != 0x02) throw new IllegalArgumentException("Bad DER r marker");
        int rLen = der[i++] & 0xFF;
        byte[] r = Arrays.copyOfRange(der, i, i + rLen); i += rLen;
        if (der[i++] != 0x02) throw new IllegalArgumentException("Bad DER s marker");
        int sLen = der[i++] & 0xFF;
        byte[] s = Arrays.copyOfRange(der, i, i + sLen);
        return new BigInteger[]{new BigInteger(1, r), new BigInteger(1, s)};
    }

    // ── Public key decoding ───────────────────────────────────────────────────

    /**
     * Decodes a compressed (33-byte) or uncompressed (65-byte) public key.
     */
    public static Point decodePublicKey(byte[] pubKey) {
        if (pubKey.length == 33) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubKey, 1, 33));
            // y² = x³ + 7 mod p
            BigInteger y2 = x.modPow(THREE, P).add(BigInteger.valueOf(7)).mod(P);
            BigInteger y  = y2.modPow(P.add(ONE).divide(BigInteger.valueOf(4)), P);
            boolean odd = (pubKey[0] == 0x03);
            if (y.testBit(0) != odd) y = P.subtract(y);
            return new Point(x, y);
        } else if (pubKey.length == 65) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubKey, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubKey, 33, 65));
            return new Point(x, y);
        }
        throw new IllegalArgumentException("Invalid public key length: " + pubKey.length);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** Encodes a BigInteger as exactly 32 bytes (zero-padded). */
    public static byte[] toBytes32(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        if (b.length == 33 && b[0] == 0) return Arrays.copyOfRange(b, 1, 33);
        byte[] out = new byte[32];
        int src = Math.max(0, b.length - 32);
        int dst = Math.max(0, 32 - b.length);
        System.arraycopy(b, src, out, dst, Math.min(b.length, 32));
        return out;
    }

    /** Encodes BigInteger as minimal unsigned bytes (no leading zero unless needed for sign). */
    static byte[] toUnsignedBytes(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b[0] == 0) return Arrays.copyOfRange(b, 1, b.length);
        return b;
    }

    /** Concatenates multiple byte arrays. */
    static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, out, pos, a.length); pos += a.length; }
        return out;
    }

    /** HMAC-SHA256 */
    static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HmacSHA256 failed", e);
        }
    }

    private Secp256k1() {}
}