package handshake.wallet;

import java.util.Arrays;

/**
 * Pure Java implementation of BLAKE2b.
 *
 * Used for Handshake address generation:
 *   address = bech32(blake2b(publicKey, outputLength=20))
 *
 * Reference: https://blake2.net/blake2.pdf
 * https://tools.ietf.org/html/rfc7693
 */
public final class BLAKE2b {

    // ── Initialization vectors (first 8 primes' square roots) ────────────────

    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // ── Sigma permutations ────────────────────────────────────────────────────

    private static final int[][] SIGMA = {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
            {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
            {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
            { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
            { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
            { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
            {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
            {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
            { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
            {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    };

    /**
     * Computes BLAKE2b hash with the specified output length.
     *
     * @param data         input bytes
     * @param outputLength desired output length in bytes (1-64)
     * @return hash bytes of the specified length
     */
    public static byte[] hash(byte[] data, int outputLength) {
        return hash(data, outputLength, null);
    }

    /**
     * Computes BLAKE2b hash with optional key.
     */
    public static byte[] hash(byte[] data, int outputLength, byte[] key) {
        if (outputLength < 1 || outputLength > 64)
            throw new IllegalArgumentException("Output length must be 1-64");

        int keyLen = key != null ? key.length : 0;
        if (keyLen > 64)
            throw new IllegalArgumentException("Key length must be 0-64");

        // State
        long[] h = Arrays.copyOf(IV, 8);

        // Parameter block: bytes 0-7
        // byte 0: digest size
        // byte 1: key length
        // byte 2: fanout = 1
        // byte 3: max depth = 1
        h[0] ^= 0x01010000L ^ ((long)keyLen << 8) ^ outputLength;

        long[] v = new long[16];
        long[] m = new long[16];

        // If keyed, prepend key block
        byte[] input;
        int offset = 0;
        if (keyLen > 0) {
            input = new byte[data.length + 128];
            System.arraycopy(key, 0, input, 0, keyLen);
            System.arraycopy(data, 0, input, 128, data.length);
        } else {
            input = data;
        }

        int dataLen = input.length;
        long byteCount = 0;

        // Process all blocks except the last
        while (dataLen - offset > 64) {
            byteCount += 64;
            loadBlock(m, input, offset);
            compress(h, v, m, byteCount, false);
            offset += 64;
        }

        // Last block (pad with zeros)
        byte[] lastBlock = new byte[64];
        int remaining = dataLen - offset;
        if (remaining > 0)
            System.arraycopy(input, offset, lastBlock, 0, remaining);
        byteCount += remaining;
        loadBlock(m, lastBlock, 0);
        compress(h, v, m, byteCount, true);

        // Extract output
        byte[] out = new byte[outputLength];
        for (int i = 0; i < outputLength; i++)
            out[i] = (byte)(h[i >>> 3] >>> (8 * (i & 7)));
        return out;
    }

    // ── Compression function ──────────────────────────────────────────────────

    private static void compress(long[] h, long[] v, long[] m,
                                 long byteCount, boolean isLast) {
        // Init working vars
        for (int i = 0; i < 8; i++) v[i] = h[i];
        for (int i = 0; i < 8; i++) v[i + 8] = IV[i];

        v[12] ^= byteCount;          // low word of byte counter
        // v[13] ^= (byteCount >> 64) — always 0 for inputs < 2^64 bytes
        if (isLast) v[14] ^= -1L;    // finalization flag

        // 12 rounds
        for (int r = 0; r < 12; r++) {
            int[] s = SIGMA[r];
            G(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
            G(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
            G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }

        // Update state
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private static void G(long[] v, int a, int b, int c, int d,
                          long x, long y) {
        v[a] += v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] += v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] += v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static void loadBlock(long[] m, byte[] data, int offset) {
        for (int i = 0; i < 16; i++) {
            int o = offset + i * 8;
            m[i] = 0;
            for (int j = 0; j < 8 && o + j < data.length; j++)
                m[i] |= ((long)(data[o + j] & 0xFF)) << (8 * j);
        }
    }
}