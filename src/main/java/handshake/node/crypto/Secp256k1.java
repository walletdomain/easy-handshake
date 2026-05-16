package handshake.node.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * secp256k1 elliptic curve arithmetic and ECDH.
 * All points are represented as BigInteger[]{x, y}, with null meaning the point at infinity.
 */
public class Secp256k1 {

    public static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final BigInteger Gx = new BigInteger(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    public static final BigInteger Gy = new BigInteger(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    public static final BigInteger[] G = { Gx, Gy };
    public static final BigInteger P_PLUS_ONE = P.add(BigInteger.ONE);

    // -------------------------------------------------------------------------
    // Point arithmetic
    // -------------------------------------------------------------------------

    public static BigInteger[] pointAdd(BigInteger[] p1, BigInteger[] p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        // Equal x-coordinates: either same point (double) or inverse (infinity)
        if (p1[0].equals(p2[0])) {
            if (p1[1].equals(p2[1])) return pointDouble(p1);
            return null; // point at infinity
        }
        BigInteger dx     = p2[0].subtract(p1[0]).mod(P);
        BigInteger dy     = p2[1].subtract(p1[1]).mod(P);
        BigInteger lambda = dy.multiply(dx.modInverse(P)).mod(P);
        BigInteger x3     = lambda.pow(2).subtract(p1[0]).subtract(p2[0]).mod(P);
        BigInteger y3     = lambda.multiply(p1[0].subtract(x3)).subtract(p1[1]).mod(P);
        return new BigInteger[]{ x3.mod(P), y3.mod(P) };
    }

    public static BigInteger[] pointDouble(BigInteger[] p) {
        BigInteger lambda = p[0].pow(2).multiply(BigInteger.valueOf(3))
                .multiply(p[1].multiply(BigInteger.TWO).modInverse(P)).mod(P);
        BigInteger x3 = lambda.pow(2).subtract(p[0].multiply(BigInteger.TWO)).mod(P);
        BigInteger y3 = lambda.multiply(p[0].subtract(x3)).subtract(p[1]).mod(P);
        return new BigInteger[]{ x3.mod(P), y3.mod(P) };
    }

    public static BigInteger[] pointMultiply(BigInteger[] point, BigInteger scalar) {
        BigInteger[] result = null;
        BigInteger[] addend = point;
        scalar = scalar.mod(N);
        while (scalar.signum() > 0) {
            if (scalar.testBit(0))
                result = pointAdd(result, addend);
            if (addend != null)
                addend = pointDouble(addend);
            scalar = scalar.shiftRight(1);
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Key encoding
    // -------------------------------------------------------------------------

    public static byte[] compressedPublicKey(BigInteger[] point) {
        byte[] x   = to32Bytes(point[0]);
        byte[] pub = new byte[33];
        pub[0] = point[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(x, 0, pub, 1, 32);
        return pub;
    }

    public static BigInteger[] decompressPublicKey(byte[] pub) {
        BigInteger x  = new BigInteger(1, Arrays.copyOfRange(pub, 1, 33));
        BigInteger y2 = x.pow(3).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y  = y2.modPow(P_PLUS_ONE.divide(BigInteger.valueOf(4)), P);
        if (y.testBit(0) != ((pub[0] & 1) == 1))
            y = P.subtract(y);
        return new BigInteger[]{ x, y };
    }

    // -------------------------------------------------------------------------
    // ECDH
    // Matches bcrypto secp256k1.derive(): returns sha256(compressed shared point).
    // -------------------------------------------------------------------------

    public static byte[] ecdh(byte[] theirPub, byte[] ourPriv) {
        BigInteger[] point  = decompressPublicKey(theirPub);
        BigInteger   scalar = new BigInteger(1, ourPriv);
        BigInteger[] result = pointMultiply(point, scalar);
        return CryptoUtils.sha256(compressedPublicKey(result));
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    public static byte[] to32Bytes(BigInteger value) {
        byte[] raw    = value.toByteArray();
        byte[] result = new byte[32];
        if (raw.length >= 32)
            System.arraycopy(raw, raw.length - 32, result, 0, 32);
        else
            System.arraycopy(raw, 0, result, 32 - raw.length, raw.length);
        return result;
    }
}