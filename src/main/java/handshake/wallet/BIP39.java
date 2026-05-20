package handshake.wallet;

import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * BIP39 mnemonic generation and BIP39 seed derivation.
 *
 * Generates 12 or 24 word mnemonics from cryptographically secure entropy,
 * validates existing mnemonics, and derives the 512-bit BIP39 seed used
 * as input to BIP32 HD key derivation.
 *
 * The BIP39 seed is derived as:
 *   PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 iterations)
 *
 * Note: the BIP39 passphrase is separate from the wallet encryption password.
 * Most users leave the passphrase empty. The encryption password protects
 * the mnemonic at rest; the passphrase modifies the derived keys themselves.
 */
public class BIP39 {

    private static final int PBKDF2_ITERATIONS = 2048;
    private static final int SEED_LENGTH_BYTES = 64; // 512 bits

    // ── Mnemonic generation ───────────────────────────────────────────────────

    /**
     * Generates a new 24-word mnemonic (256 bits of entropy).
     * Use 24 words for maximum security — recommended for a real wallet.
     */
    public static String generateMnemonic24() {
        return generateMnemonic(256);
    }

    /**
     * Generates a new 12-word mnemonic (128 bits of entropy).
     * Suitable for testing or lower-security use cases.
     */
    public static String generateMnemonic12() {
        return generateMnemonic(128);
    }

    /**
     * Generates a mnemonic from the given entropy bit count.
     * entropyBits must be one of: 128, 160, 192, 224, 256
     */
    public static String generateMnemonic(int entropyBits) {
        if (entropyBits % 32 != 0 || entropyBits < 128 || entropyBits > 256)
            throw new IllegalArgumentException("Entropy bits must be 128-256 and divisible by 32");

        // Generate random entropy
        byte[] entropy = new byte[entropyBits / 8];
        new SecureRandom().nextBytes(entropy);
        return entropyToMnemonic(entropy);
    }

    /**
     * Converts raw entropy bytes to a BIP39 mnemonic string.
     */
    public static String entropyToMnemonic(byte[] entropy) {
        List<String> wordList = Arrays.asList(BIP39English.WORDS);

        // Compute SHA-256 checksum
        byte[] hash     = sha256(entropy);
        int checksumBits = entropy.length * 8 / 32;

        // Concatenate entropy + checksum bits
        int totalBits = entropy.length * 8 + checksumBits;
        byte[] combined = Arrays.copyOf(entropy, (totalBits + 7) / 8);
        // OR in the first checksumBits of the hash
        combined[entropy.length] = (byte)(hash[0] & (0xFF << (8 - checksumBits)));

        // Split into 11-bit groups to get word indices
        int wordCount = totalBits / 11;
        String[] words = new String[wordCount];
        for (int i = 0; i < wordCount; i++) {
            int index = extractBits(combined, i * 11, 11);
            words[i] = wordList.get(index);
        }
        return String.join(" ", words);
    }

    // ── Mnemonic validation ───────────────────────────────────────────────────

    /**
     * Returns true if the mnemonic is valid (correct words and checksum).
     */
    public static boolean isValid(String mnemonic) {
        try {
            mnemonicToEntropy(mnemonic);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Converts a mnemonic back to entropy bytes, validating the checksum.
     * Throws IllegalArgumentException if invalid.
     */
    public static byte[] mnemonicToEntropy(String mnemonic) {
        List<String> wordList = Arrays.asList(BIP39English.WORDS);
        String[] words = mnemonic.trim().toLowerCase().split("\\s+");

        // Validate word count
        if (words.length != 12 && words.length != 15 &&
                words.length != 18 && words.length != 21 && words.length != 24)
            throw new IllegalArgumentException(
                    "Invalid mnemonic: must be 12, 15, 18, 21, or 24 words");

        // Convert words to bit array
        int totalBits = words.length * 11;
        byte[] bits   = new byte[(totalBits + 7) / 8];

        for (int i = 0; i < words.length; i++) {
            int index = wordList.indexOf(words[i]);
            if (index < 0)
                throw new IllegalArgumentException(
                        "Unknown word: " + words[i]);
            for (int b = 0; b < 11; b++) {
                if ((index & (1 << (10 - b))) != 0)
                    bits[(i * 11 + b) / 8] |= (1 << (7 - (i * 11 + b) % 8));
            }
        }

        // Split entropy and checksum
        int checksumBits  = words.length / 3;
        int entropyBits   = totalBits - checksumBits;
        byte[] entropy    = Arrays.copyOf(bits, entropyBits / 8);

        // Verify checksum
        byte[] hash          = sha256(entropy);
        byte[] expectedCheck = new byte[1];
        expectedCheck[0]     = (byte)(hash[0] & (0xFF << (8 - checksumBits)));
        byte[] actualCheck   = new byte[1];
        actualCheck[0]       = (byte)(bits[entropyBits / 8] & (0xFF << (8 - checksumBits)));

        if (expectedCheck[0] != actualCheck[0])
            throw new IllegalArgumentException("Invalid mnemonic: checksum mismatch");

        return entropy;
    }

    // ── Seed derivation ───────────────────────────────────────────────────────

    /**
     * Derives the 512-bit BIP39 seed from a mnemonic and optional passphrase.
     *
     * @param mnemonic    the BIP39 mnemonic string
     * @param passphrase  optional BIP39 passphrase (use "" for none)
     * @return            64-byte seed for BIP32 master key derivation
     */
    public static byte[] mnemonicToSeed(String mnemonic, String passphrase) {
        try {
            // Normalize: NFKD unicode normalization (simplified — ASCII mnemonics
            // from our wordlist don't need normalization)
            byte[] mnemonicBytes = mnemonic.trim()
                    .getBytes(StandardCharsets.UTF_8);
            byte[] saltBytes     = ("mnemonic" + passphrase)
                    .getBytes(StandardCharsets.UTF_8);

            // PBKDF2-HMAC-SHA512
            return pbkdf2HmacSha512(mnemonicBytes, saltBytes,
                    PBKDF2_ITERATIONS, SEED_LENGTH_BYTES);
        } catch (Exception e) {
            throw new RuntimeException("BIP39 seed derivation failed", e);
        }
    }

    /**
     * Derives seed with no passphrase (most common case).
     */
    public static byte[] mnemonicToSeed(String mnemonic) {
        return mnemonicToSeed(mnemonic, "");
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static int extractBits(byte[] data, int start, int length) {
        int result = 0;
        for (int i = 0; i < length; i++) {
            int byteIdx = (start + i) / 8;
            int bitIdx  = 7 - (start + i) % 8;
            if (byteIdx < data.length && (data[byteIdx] & (1 << bitIdx)) != 0)
                result |= (1 << (length - 1 - i));
        }
        return result;
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] pbkdf2HmacSha512(byte[] password, byte[] salt,
                                   int iterations, int keyLen)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(password, "HmacSHA512"));

        int hLen    = 64; // SHA-512 output bytes
        int blocks  = (keyLen + hLen - 1) / hLen;
        byte[] dk   = new byte[keyLen];

        for (int i = 1; i <= blocks; i++) {
            // U1 = PRF(password, salt || INT(i))
            mac.reset();
            mac.update(salt);
            mac.update(new byte[]{
                    (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i
            });
            byte[] u = mac.doFinal();
            byte[] t = Arrays.copyOf(u, hLen);

            // U2..Uc
            for (int c = 1; c < iterations; c++) {
                mac.reset();
                u = mac.doFinal(u);
                for (int j = 0; j < hLen; j++) t[j] ^= u[j];
            }

            int offset = (i - 1) * hLen;
            int len    = Math.min(hLen, keyLen - offset);
            System.arraycopy(t, 0, dk, offset, len);
        }
        return dk;
    }
}