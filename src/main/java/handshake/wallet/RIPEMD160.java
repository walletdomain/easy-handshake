package handshake.wallet;

/**
 * Pure Java implementation of RIPEMD-160.
 *
 * Needed because JDK 17+ removed RIPEMD-160 from the default security
 * providers. This implementation is used for Handshake address generation
 * (hash160 = SHA-256 then RIPEMD-160).
 *
 * Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */
public final class RIPEMD160 {

    public static byte[] hash(byte[] message) {
        // Initial hash values
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;

        // Pad message
        byte[] padded = pad(message);
        int[] X = new int[16];

        for (int offset = 0; offset < padded.length; offset += 64) {
            // Load block as little-endian 32-bit words
            for (int i = 0; i < 16; i++) {
                int o = offset + i * 4;
                X[i] = (padded[o] & 0xFF)
                        | ((padded[o+1] & 0xFF) << 8)
                        | ((padded[o+2] & 0xFF) << 16)
                        | ((padded[o+3] & 0xFF) << 24);
            }

            int al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            int ar = h0, br = h1, cr = h2, dr = h3, er = h4;
            int t;

            // Left rounds
            for (int j = 0; j < 80; j++) {
                t = rotl(al + fl(j, bl, cl, dl) + X[RL[j]] + KL[j/16], SL[j]) + el;
                al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
            }
            // Right rounds
            for (int j = 0; j < 80; j++) {
                t = rotl(ar + fr(j, br, cr, dr) + X[RR[j]] + KR[j/16], SR[j]) + er;
                ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
            }

            t  = h1 + cl + dr;
            h1 = h2 + dl + er;
            h2 = h3 + el + ar;
            h3 = h4 + al + br;
            h4 = h0 + bl + cr;
            h0 = t;
        }

        // Output as bytes (little-endian)
        byte[] digest = new byte[20];
        intToLE(h0, digest, 0);
        intToLE(h1, digest, 4);
        intToLE(h2, digest, 8);
        intToLE(h3, digest, 12);
        intToLE(h4, digest, 16);
        return digest;
    }

    // ── Padding ───────────────────────────────────────────────────────────────

    private static byte[] pad(byte[] msg) {
        int len     = msg.length;
        int bitLen  = len * 8;
        int padLen  = (len % 64 < 56) ? 56 - len % 64 : 120 - len % 64;
        byte[] out  = new byte[len + padLen + 8];
        System.arraycopy(msg, 0, out, 0, len);
        out[len] = (byte) 0x80;
        // Append length as 64-bit little-endian
        long bits = (long) len * 8;
        for (int i = 0; i < 8; i++)
            out[len + padLen + i] = (byte)(bits >> (8 * i));
        return out;
    }

    // ── Boolean functions ─────────────────────────────────────────────────────

    private static int fl(int j, int x, int y, int z) {
        if (j < 16) return x ^ y ^ z;
        if (j < 32) return (x & y) | (~x & z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }

    private static int fr(int j, int x, int y, int z) {
        if (j < 16) return x ^ (y | ~z);
        if (j < 32) return (x & z) | (y & ~z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & y) | (~x & z);
        return x ^ y ^ z;
    }

    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    private static void intToLE(int v, byte[] b, int off) {
        b[off]   = (byte) v;
        b[off+1] = (byte)(v >> 8);
        b[off+2] = (byte)(v >> 16);
        b[off+3] = (byte)(v >> 24);
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final int[] KL = {
            0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
    };
    private static final int[] KR = {
            0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
    };

    private static final int[] RL = {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
            1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
    };
    private static final int[] RR = {
            5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
            6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
            8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
    };
    private static final int[] SL = {
            11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
            7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
            11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
    };
    private static final int[] SR = {
            8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
            9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
            15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
    };
}