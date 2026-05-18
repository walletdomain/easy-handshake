import handshake.node.HNSPeer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Verifies the HNSPeer crypto implementations against known bcrypto test vectors.
 *
 * Run: javac VerifyHNSPeer.java && java handshake.VerifyHNSPeer
 *
 * Expected output: all tests PASS.
 */
public class VerifyPeer {

    static int pass = 0, fail = 0;

    public static void main(String[] args) {

        // ---------------------------------------------------------------
        // Test 1: BLAKE2b-256
        // Vectors from: node probe_sha3.js /usr/local/hsd
        // ---------------------------------------------------------------
        System.out.println("=== Test 1: BLAKE2b-256 ===");
        check("blake2b-256(\"\")",
                hex(HNSPeer.Blake2b.hash(new byte[0], 32)),
                "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        check("blake2b-256(\"abc\")",
                hex(HNSPeer.Blake2b.hash("abc".getBytes(), 32)),
                "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
        // multi("ab","cd") = digest("abcd")
        check("blake2b-256(\"abcd\")",
                hex(HNSPeer.Blake2b.hash("abcd".getBytes(), 32)),
                "9cc3912a042827e45983ed53df3c759f4574added1d07c6d0c7fe0bc3ecf9c42");

        // ---------------------------------------------------------------
        // Test 2: BLAKE2b-512
        // ---------------------------------------------------------------
        System.out.println("\n=== Test 2: BLAKE2b-512 ===");
        check("blake2b-512(\"abc\")",
                hex(HNSPeer.Blake2b.hash("abc".getBytes(), 64)),
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                        + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

        // ---------------------------------------------------------------
        // Test 3: Keccak-256 (SHA3)
        // ---------------------------------------------------------------
        System.out.println("\n=== Test 3: Keccak-256 ===");
        check("keccak256(\"\")",
                hex(HNSPeer.Keccak256.hash(new byte[0])),
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        check("keccak256(\"abc\")",
                hex(HNSPeer.Keccak256.hash("abc".getBytes())),
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        // multi("ab","cd") = digest("abcd")
        check("keccak256(\"abcd\")",
                hex(HNSPeer.Keccak256.hash("abcd".getBytes())),
                "6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177");

        // ---------------------------------------------------------------
        // Test 4: Genesis block header parse and hash
        //
        // Genesis header bytes from probe_sha3.js output:
        //   subHead: 0000...001a2c60b9...8e4c9756...00000000ffff001c
        //   preHead: 000000007641385e...f1c47b3b...
        // We reconstruct the genesis header from known field values and
        // verify BlockHeader.hash() == genesis block hash.
        // ---------------------------------------------------------------
        System.out.println("\n=== Test 4: Genesis block header hash ===");

        // Known genesis field values from probe_nonce.js / probe_sha3.js
        long   nonce        = 0;
        long   time         = 1580745078L;
        byte[] prevBlock    = new byte[32]; // all zeros
        byte[] treeRoot     = new byte[32]; // all zeros
        byte[] extraNonce   = new byte[HNSPeer.NONCE_SIZE]; // all zeros
        byte[] reservedRoot = new byte[32]; // all zeros
        byte[] witnessRoot  = fromHex(
                "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351");
        byte[] merkleRoot   = fromHex(
                "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15");
        byte[] mask         = new byte[32]; // all zeros
        int    version      = 0;
        int    bits         = 0x1c00ffff;

        // Build raw 236-byte header (writeHead format)
        byte[] raw = new byte[HNSPeer.HEADER_SIZE];
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) nonce);
        buf.putLong(time);
        buf.put(prevBlock);
        buf.put(treeRoot);
        buf.put(extraNonce);
        buf.put(reservedRoot);
        buf.put(witnessRoot);
        buf.put(merkleRoot);
        buf.putInt(version);
        buf.putInt(bits);
        buf.put(mask);

        // Verify expected subHead from probe output
        String nonceTimeCheck = hex(Arrays.copyOf(raw, 8)).equals("000000007641385e")
                ? "PASS (nonce/time match)" : "FAIL (nonce/time mismatch)";
        System.out.println("  " + nonceTimeCheck);

        // Parse and hash
        HNSPeer.BlockHeader genesis = HNSPeer.BlockHeader.parse(raw, 0);
        String gotHash = hex(genesis.hash());
        String expHash = "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0";
        check("genesis powHash", gotHash, expHash);

        // Also verify intermediate values from probe_sha3.js
        System.out.println("\n=== Test 5: Intermediate hash values ===");

        // subHash = blake2b256(subHead)
        byte[] subHead = new byte[128];
        ByteBuffer sb  = ByteBuffer.wrap(subHead).order(ByteOrder.LITTLE_ENDIAN);
        sb.put(extraNonce); sb.put(reservedRoot); sb.put(witnessRoot);
        sb.put(merkleRoot); sb.putInt(version); sb.putInt(bits);
        check("subHash",
                hex(HNSPeer.Blake2b.hash(subHead, 32)),
                "f90512f15a517f6c5331fafc33f533626008bc9d076dc654451cf3821262aba8");

        // maskHash = blake2b256(prevBlock || mask)
        byte[] pm = new byte[64];
        System.arraycopy(prevBlock, 0, pm, 0,  32);
        System.arraycopy(mask,      0, pm, 32, 32);
        check("maskHash",
                hex(HNSPeer.Blake2b.hash(pm, 32)),
                "0eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761");

        // commitHash = blake2b256(subHash || maskHash)
        byte[] subHash  = HNSPeer.Blake2b.hash(subHead, 32);
        byte[] maskHash = HNSPeer.Blake2b.hash(pm, 32);
        byte[] sm = new byte[64];
        System.arraycopy(subHash,  0, sm, 0,  32);
        System.arraycopy(maskHash, 0, sm, 32, 32);
        check("commitHash",
                hex(HNSPeer.Blake2b.hash(sm, 32)),
                "f1c47b3b9ad5922a79487d5752c4e405c2479e39c11766eaf24998ec28928bda");

        // left = blake2b512(preHead) — check first 16 bytes
        byte[] preHead = Arrays.copyOfRange(raw, 0, 76); // first 76 bytes
        // Rebuild full 128-byte preHead as done in BlockHeader.hash()
        byte[] commitHash = HNSPeer.Blake2b.hash(sm, 32);
        byte[] fullPreHead = new byte[128];
        ByteBuffer pb = ByteBuffer.wrap(fullPreHead).order(ByteOrder.LITTLE_ENDIAN);
        pb.putInt((int) nonce);
        pb.putLong(time);
        pb.put(new byte[20]); // padding(20) = all zeros (prevBlock XOR treeRoot, both zero)
        pb.put(prevBlock);
        pb.put(treeRoot);
        pb.put(commitHash);
        check("left (blake2b-512, first 32 bytes)",
                hex(Arrays.copyOf(HNSPeer.Blake2b.hash(fullPreHead, 64), 32)),
                "283a74e19b061ff2db5e3678324b2e651b0f251c15e08b117cd3899dfb46fc41");

        // right = sha3(preHead || padding(8)) = sha3(preHead || zeros)
        byte[] preHeadPad8 = new byte[136];
        System.arraycopy(fullPreHead, 0, preHeadPad8, 0, 128);
        // padding(8) = all zeros for genesis
        check("right (keccak256)",
                hex(HNSPeer.Keccak256.hash(preHeadPad8)),
                "53ace844227e7077d5ff3de7e13c8f7a2a28c93d412e85ec6feacb573d54ec48");

        // ---------------------------------------------------------------
        // Test 6: Varint encoding
        // ---------------------------------------------------------------
        System.out.println("\n=== Test 6: Varint ===");
        checkVarint(0,       "00");
        checkVarint(1,       "01");
        checkVarint(252,     "fc");
        checkVarint(253,     "fdfd00");
        checkVarint(65535,   "fdffff");
        checkVarint(65536,   "fe00000100");
        checkVarint(2000,    "fdd007");

        // ---------------------------------------------------------------
        // Summary
        // ---------------------------------------------------------------
        System.out.println("\n=== Results: " + pass + " passed, " + fail + " failed ===");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    static void check(String name, String got, String expected) {
        if (got.equals(expected)) {
            System.out.println("  PASS: " + name);
            pass++;
        } else {
            System.out.println("  FAIL: " + name);
            System.out.println("    got:      " + got);
            System.out.println("    expected: " + expected);
            fail++;
        }
    }

    static void checkVarint(long value, String expectedHex) {
        String got = hex(HNSPeer.encodeVarint(value));
        check("varint(" + value + ")", got, expectedHex);

        // Also verify decode round-trips
        byte[] encoded = HNSPeer.encodeVarint(value);
        long[] decoded = HNSPeer.decodeVarint(encoded, 0);
        if (decoded[0] != value || decoded[1] != encoded.length) {
            System.out.println("  FAIL: varint decode(" + value + ")"
                    + " got=" + decoded[0] + " len=" + decoded[1]);
            fail++;
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static byte[] fromHex(String h) {
        byte[] r = new byte[h.length() / 2];
        for (int i = 0; i < r.length; i++)
            r[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return r;
    }
}