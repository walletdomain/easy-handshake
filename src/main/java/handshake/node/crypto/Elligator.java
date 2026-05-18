package handshake.node.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Elligator Squared encoding using the Shallue-van de Woestijne (SvdW) map
 * for secp256k1. This is the exact algorithm used by bcrypto/hsd brontide.
 *
 * Source: bcrypto/lib/js/elliptic.js _svdwf(), _svdw(), _svdwi()
 *
 * secp256k1 parameters: a=0, b=7, z=1, c=sqrt(-3)
 *   g(x) = x^3 + 7
 *   g(z) = g(1) = 8
 *
 * Forward map _svdwf(u) -> (x, yy):
 *   t1  = u^2 + gz
 *   t2  = 1 / (u^2 * t1)     (or 0 if denom is 0)
 *   t3  = u^4 * t2 * c
 *   t4  = t1^3 * t2 * z3
 *   x1  = (c - z)/2 - t3
 *   x2  = t3 - (c + z)/2
 *   x3  = z - t4
 *   i   = ((jacobi(g(x1))-1) * jacobi(g(x2))) mod 3
 *   return [x_i, g(x_i)]
 *
 * Inverse map _svdwi(p, hint) -> u  (hint selects which of 4 preimages)
 *
 * pointToHash  (encode): u1||u2 where svdw(u1)+svdw(u2) = point
 * pointFromHash (decode): svdw(u1) + svdw(u2)
 */
public class Elligator {

    private static final BigInteger P         = Secp256k1.P;
    private static final BigInteger P_PLUS_ONE = Secp256k1.P_PLUS_ONE;

    // SvdW constants for secp256k1 (z=1, c=sqrt(-3))
    private static final BigInteger SVDW_C = new BigInteger(
            "0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852", 16);
    private static final BigInteger SVDW_GZ = BigInteger.valueOf(8);       // g(z) = 1+7 = 8
    private static final BigInteger SVDW_Z  = BigInteger.ONE;              // z = 1
    private static final BigInteger SVDW_Z3 = BigInteger.valueOf(3).modInverse(P); // 1/(3z^2)
    private static final BigInteger SVDW_A  =                              // (c-z)/2
            SVDW_C.subtract(BigInteger.ONE).mod(P)
                    .multiply(BigInteger.TWO.modInverse(P)).mod(P);
    private static final BigInteger SVDW_B  =                              // (c+z)/2
            SVDW_C.add(BigInteger.ONE).mod(P)
                    .multiply(BigInteger.TWO.modInverse(P)).mod(P);

    private static final SecureRandom RNG = new SecureRandom();

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Decodes 64 uniform bytes to a curve point.
     * u1 = bytes[0..32] mod p, u2 = bytes[32..64] mod p
     * returns svdw(u1) + svdw(u2)
     */
    public static BigInteger[] decode(byte[] uniform) {
        BigInteger u1 = new BigInteger(1, Arrays.copyOfRange(uniform, 0,  32)).mod(P);
        BigInteger u2 = new BigInteger(1, Arrays.copyOfRange(uniform, 32, 64)).mod(P);
        BigInteger[] p1 = svdw(u1);
        BigInteger[] p2 = svdw(u2);
        return Secp256k1.pointAdd(p1, p2);
    }

    /**
     * Encodes a curve point to 64 uniform bytes.
     * Picks random u1, finds u2 such that svdw(u1)+svdw(u2) = point.
     */
    public static byte[] encode(BigInteger[] point) {
        for (int attempt = 0; attempt < 1000; attempt++) {
            byte[] u1Bytes = new byte[32];
            RNG.nextBytes(u1Bytes);
            BigInteger u1 = new BigInteger(1, u1Bytes).mod(P);
            if (u1.signum() == 0) continue;

            BigInteger[] p1;
            try { p1 = svdw(u1); } catch (Exception e) { continue; }

            if (p1[1].signum() == 0) continue; // skip 2-torsion points

            // p2 = point - p1 = point + (-p1)
            BigInteger[] negP1 = new BigInteger[]{ p1[0], P.subtract(p1[1]).mod(P) };
            BigInteger[] p2 = Secp256k1.pointAdd(point, negP1);
            if (p2 == null) continue; // point at infinity

            // Try all 4 hint values for the inverse map
            int hint = RNG.nextInt(4);
            for (int h = 0; h < 4; h++) {
                try {
                    BigInteger u2 = svdwi(p2, (hint + h) & 3);
                    byte[] result = new byte[64];
                    System.arraycopy(Secp256k1.to32Bytes(u1), 0, result, 0,  32);
                    System.arraycopy(Secp256k1.to32Bytes(u2), 0, result, 32, 32);
                    return result;
                } catch (Exception ignored) {}
            }
        }
        throw new RuntimeException("Elligator encode failed after 1000 attempts");
    }

    // -------------------------------------------------------------------------
    // SvdW forward map
    // -------------------------------------------------------------------------

    // Returns [x, yy] where yy = g(x) = x^3 + 7 — caller must take sqrt and fix parity
    static BigInteger[] svdwf(BigInteger u) {
        BigInteger u2   = u.multiply(u).mod(P);
        BigInteger u4   = u2.multiply(u2).mod(P);
        BigInteger t1   = u2.add(SVDW_GZ).mod(P);
        BigInteger u2t1 = u2.multiply(t1).mod(P);
        BigInteger t2   = u2t1.signum() == 0 ? BigInteger.ZERO : u2t1.modInverse(P);
        BigInteger t3   = u4.multiply(t2).mod(P).multiply(SVDW_C).mod(P);
        BigInteger t4   = t1.multiply(t1).mod(P).multiply(t1).mod(P)
                .multiply(t2).mod(P).multiply(SVDW_Z3).mod(P);

        BigInteger x1 = SVDW_A.subtract(t3).mod(P);
        BigInteger x2 = t3.subtract(SVDW_B).mod(P);
        BigInteger x3 = SVDW_Z.subtract(t4).mod(P);

        BigInteger y1 = x1.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y2 = x2.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y3 = x3.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);

        int alpha = jacobiSymbol(y1) | 1;
        int beta  = jacobiSymbol(y2) | 1;
        int i     = Math.floorMod((alpha - 1) * beta, 3);

        BigInteger[] xs  = { x1, x2, x3 };
        BigInteger[] yys = { y1, y2, y3 };
        return new BigInteger[]{ xs[i], yys[i] };
    }

    // Returns curve point; y parity matches u parity
    static BigInteger[] svdw(BigInteger u) {
        BigInteger[] xy = svdwf(u);
        BigInteger y = modSqrt(xy[1]);
        if (y == null) throw new RuntimeException("SvdW: g(x) not a QR");
        if (y.testBit(0) != u.testBit(0)) y = P.subtract(y);
        return new BigInteger[]{ xy[0], y };
    }

    // -------------------------------------------------------------------------
    // SvdW inverse map
    // -------------------------------------------------------------------------

    // Given point p and hint (0..3), finds u such that svdw(u) = p.
    // Throws if the chosen hint candidate is not valid for this point.
    static BigInteger svdwi(BigInteger[] p, int hint) {
        BigInteger x  = p[0];
        BigInteger y  = p[1];
        int r = hint & 3;

        BigInteger z2  = SVDW_Z.multiply(SVDW_Z).mod(P);
        BigInteger z3  = z2.multiply(SVDW_Z).mod(P);
        BigInteger z4  = z2.multiply(z2).mod(P);
        BigInteger gz  = z3.add(BigInteger.valueOf(7)).mod(P);
        BigInteger gz2 = gz.multiply(BigInteger.TWO).mod(P);

        BigInteger xx  = x.multiply(x).mod(P);
        BigInteger x2z = x.multiply(BigInteger.TWO).mod(P).add(SVDW_Z).mod(P);
        BigInteger xz2 = x.multiply(z2).mod(P);
        BigInteger c0  = SVDW_C.subtract(x2z).mod(P);
        BigInteger c1  = SVDW_C.add(x2z).mod(P);

        BigInteger t0  = xx.multiply(z2).mod(P).add(z4).mod(P)
                .multiply(BigInteger.valueOf(9)).mod(P);
        BigInteger t1  = x.multiply(z3).mod(P)
                .multiply(BigInteger.valueOf(18)).mod(P);
        BigInteger t2  = gz.multiply(x.subtract(SVDW_Z).mod(P)).mod(P)
                .multiply(BigInteger.valueOf(12)).mod(P);

        BigInteger t4;
        if (r >= 2) {
            BigInteger inner = t0.subtract(t1).mod(P).add(t2).mod(P);
            BigInteger t3 = modSqrt(inner);
            if (t3 == null) throw new RuntimeException("Invalid point.");
            t4 = t3.multiply(SVDW_Z).mod(P);
        } else {
            t4 = BigInteger.ZERO;
        }

        BigInteger t5 = z3.subtract(xz2).mod(P)
                .multiply(BigInteger.valueOf(3)).mod(P).subtract(gz2).mod(P);

        BigInteger[] ns = { gz.multiply(c0).mod(P), gz.multiply(c1).mod(P),
                t5.add(t4).mod(P),       t5.subtract(t4).mod(P) };
        BigInteger[] ds = { c1, c0, BigInteger.TWO, BigInteger.TWO };

        BigInteger n = ns[r];
        BigInteger d = ds[r];

        BigInteger u = modSqrt(n.multiply(d.modInverse(P)).mod(P));
        if (u == null) throw new RuntimeException("Invalid point.");

        // Verify forward map gives same x
        BigInteger[] check = svdwf(u);
        if (!check[0].equals(x)) {
            u = P.subtract(u);
            check = svdwf(u);
            if (!check[0].equals(x)) throw new RuntimeException("Invalid point.");
        }

        // u parity matches y parity
        if (u.testBit(0) != y.testBit(0)) u = P.subtract(u);
        return u;
    }

    // -------------------------------------------------------------------------
    // Field helpers
    // -------------------------------------------------------------------------

    // Jacobi symbol (a/p): returns -1, 0, or 1
    static int jacobiSymbol(BigInteger a) {
        a = a.mod(P);
        if (a.signum() == 0) return 0;
        BigInteger exp    = P.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        BigInteger result = a.modPow(exp, P);
        if (result.equals(BigInteger.ONE)) return 1;
        if (result.signum() == 0) return 0;
        return -1;
    }

    // Modular square root (p ≡ 3 mod 4): sqrt = n^((p+1)/4), null if not a QR
    static BigInteger modSqrt(BigInteger n) {
        n = n.mod(P);
        if (n.signum() == 0) return BigInteger.ZERO;
        BigInteger sqrt = n.modPow(P_PLUS_ONE.divide(BigInteger.valueOf(4)), P);
        return sqrt.multiply(sqrt).mod(P).equals(n) ? sqrt : null;
    }
}