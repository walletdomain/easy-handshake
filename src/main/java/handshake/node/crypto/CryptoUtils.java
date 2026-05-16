package handshake.node.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Symmetric cryptographic primitives used by the brontide handshake:
 * SHA-256, HKDF (RFC 5869, empty info, 64-byte output), and ChaCha20-Poly1305.
 */
public class CryptoUtils {

    // -------------------------------------------------------------------------
    // SHA-256
    // -------------------------------------------------------------------------

    /** Returns the Blake2b-256 hash of the given data. */
    public static byte[] blake2b256(byte[] data) {
        return handshake.node.HNSPeer.Blake2b.hash(data, 32);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256Concat(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts)
                if (part != null) md.update(part);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // -------------------------------------------------------------------------
    // HKDF
    // Matches hsd's expand(secret, salt, info=EMPTY):
    //   prk = HMAC-SHA256(key=salt, data=secret)
    //   T1  = HMAC-SHA256(key=prk, data=0x01)
    //   T2  = HMAC-SHA256(key=prk, data=T1 || 0x02)
    //   returns [T1, T2]
    // -------------------------------------------------------------------------

    public static byte[][] hkdfExpand(byte[] secret, byte[] salt) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            // Extract: prk = HMAC-SHA256(key=salt, data=secret)
            byte[] saltKey = (salt == null || salt.length == 0) ? new byte[32] : salt;
            mac.init(new SecretKeySpec(saltKey, "HmacSHA256"));
            byte[] prk = mac.doFinal(secret);

            // T1 = HMAC-SHA256(key=prk, data=0x01)
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] t1 = mac.doFinal(new byte[]{ 0x01 });

            // T2 = HMAC-SHA256(key=prk, data=T1 || 0x02)
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(t1);
            byte[] t2 = mac.doFinal(new byte[]{ 0x02 });

            return new byte[][]{ t1, t2 };
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // -------------------------------------------------------------------------
    // ChaCha20-Poly1305
    // -------------------------------------------------------------------------

    /**
     * Encrypts pt in-place and returns the 16-byte Poly1305 tag.
     * nonce is 12 bytes; the counter sits as a little-endian uint32 at bytes 4-7.
     */
    public static byte[] chachaEncrypt(byte[] key, byte[] nonce, byte[] pt, byte[] ad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
            if (ad != null && ad.length > 0) cipher.updateAAD(ad);
            byte[] out = cipher.doFinal(pt);
            // out = ciphertext (pt.length bytes) + tag (16 bytes)
            if (pt.length > 0)
                System.arraycopy(out, 0, pt, 0, pt.length);
            return Arrays.copyOfRange(out, out.length - 16, out.length);
        } catch (Exception e) {
            throw new RuntimeException("chachaEncrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts ct using the provided tag and returns true if the tag is valid.
     */
    public static boolean chachaDecrypt(byte[] key, byte[] nonce,
                                        byte[] ct, byte[] tag, byte[] ad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
            if (ad != null && ad.length > 0) cipher.updateAAD(ad);
            byte[] combined = new byte[ct.length + 16];
            System.arraycopy(ct,  0, combined, 0,         ct.length);
            System.arraycopy(tag, 0, combined, ct.length, 16);
            byte[] plaintext = cipher.doFinal(combined);
            // Copy decrypted plaintext back into ct (in-place, matching hsd behaviour)
            if (ct.length > 0)
                System.arraycopy(plaintext, 0, ct, 0, ct.length);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}