package handshake.wallet;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cryptographic primitives for wallet seed phrase encryption.
 *
 * Encryption scheme (all standard Java, no third-party libraries):
 *   Key derivation: PBKDF2-HMAC-SHA256(password, randomSalt, 600000 iterations)
 *   Encryption:     AES-256-GCM(plaintext, derivedKey, randomNonce)
 *
 * Storage layout per wallet (all Base64-encoded in the database):
 *   salt       — 32 random bytes, unique per wallet
 *   nonce      — 12 random bytes, unique per encryption operation
 *   ciphertext — AES-GCM output (plaintext length + 16 byte auth tag)
 *
 * Security properties:
 *   - Password is never stored, not even hashed
 *   - Wrong password causes GCM authentication failure (unambiguous rejection)
 *   - 600,000 PBKDF2 iterations matches OWASP 2023 recommendation for SHA-256
 *   - Each wallet has a unique salt preventing cross-wallet attacks
 *   - GCM provides both confidentiality and integrity
 */
public class WalletCrypto {

    private static final int    PBKDF2_ITERATIONS = 600_000;
    private static final int    KEY_LENGTH_BITS   = 256;
    private static final int    SALT_LENGTH       = 32;
    private static final int    NONCE_LENGTH      = 12;
    private static final int    GCM_TAG_BITS      = 128;
    private static final String KDF_ALGORITHM     = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM  = "AES/GCM/NoPadding";

    // ── Encrypted seed container ──────────────────────────────────────────────

    public record EncryptedSeed(
            byte[] salt,
            byte[] nonce,
            byte[] ciphertext
    ) {
        /** Serializes to a Base64 string for database storage. */
        public String toStorageString() {
            Base64.Encoder enc = Base64.getEncoder();
            return enc.encodeToString(salt) + "."
                    + enc.encodeToString(nonce) + "."
                    + enc.encodeToString(ciphertext);
        }

        /** Deserializes from a storage string. */
        public static EncryptedSeed fromStorageString(String s) {
            String[] parts = s.split("\\.");
            if (parts.length != 3)
                throw new IllegalArgumentException("Invalid encrypted seed format");
            Base64.Decoder dec = Base64.getDecoder();
            return new EncryptedSeed(
                    dec.decode(parts[0]),
                    dec.decode(parts[1]),
                    dec.decode(parts[2]));
        }
    }

    // ── Exceptions ────────────────────────────────────────────────────────────

    public static class BadPasswordException extends Exception {
        public BadPasswordException(String msg) { super(msg); }
    }

    // ── Encryption ────────────────────────────────────────────────────────────

    /**
     * Encrypts a seed phrase with the user's password.
     *
     * @param seedPhrase  plaintext BIP39 mnemonic
     * @param password    user's wallet password (zeroed by caller after use)
     * @return            EncryptedSeed for database storage
     */
    public static EncryptedSeed encrypt(String seedPhrase, char[] password)
            throws GeneralSecurityException {
        SecureRandom rng = new SecureRandom();

        byte[] salt  = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        rng.nextBytes(salt);
        rng.nextBytes(nonce);

        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(GCM_TAG_BITS, nonce));

        byte[] ciphertext = cipher.doFinal(
                seedPhrase.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        return new EncryptedSeed(salt, nonce, ciphertext);
    }

    // ── Decryption ────────────────────────────────────────────────────────────

    /**
     * Decrypts an encrypted seed phrase.
     *
     * @param encrypted  the EncryptedSeed from the database
     * @param password   user's wallet password
     * @return           plaintext BIP39 mnemonic
     * @throws BadPasswordException if password is wrong or data corrupt
     */
    public static String decrypt(EncryptedSeed encrypted, char[] password)
            throws BadPasswordException, GeneralSecurityException {
        SecretKey key = deriveKey(password, encrypted.salt);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(GCM_TAG_BITS, encrypted.nonce));

        try {
            byte[] plaintext = cipher.doFinal(encrypted.ciphertext);
            return new String(plaintext,
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new BadPasswordException(
                    "Incorrect password or corrupt wallet data");
        }
    }

    /**
     * Verifies a password is correct without returning the seed.
     * Returns true if the password successfully decrypts the wallet.
     */
    public static boolean verifyPassword(EncryptedSeed encrypted, char[] password) {
        try {
            decrypt(encrypted, password);
            return true;
        } catch (BadPasswordException e) {
            return false;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // ── Key derivation ────────────────────────────────────────────────────────

    /**
     * Derives a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.
     * This is intentionally slow (600,000 iterations) to resist brute force.
     */
    private static SecretKey deriveKey(char[] password, byte[] salt)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(
                password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    // ── Secure memory helpers ─────────────────────────────────────────────────

    /**
     * Safely converts a String password to char array.
     * Prefer passing char[] directly when possible to avoid String interning.
     */
    public static char[] toCharArray(String password) {
        return password.toCharArray();
    }

    /**
     * Zeros a char array after use to prevent password lingering in memory.
     */
    public static void zeroChars(char[] chars) {
        if (chars != null) Arrays.fill(chars, '\0');
    }

    /**
     * Zeros a byte array after use.
     */
    public static void zeroBytes(byte[] bytes) {
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }
}