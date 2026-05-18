package handshake.node;

import handshake.node.crypto.Secp256k1;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;

/**
 * Manages our node's permanent brontide identity keypair.
 *
 * On first run, generates a random secp256k1 keypair and saves it to
 * ~/.easy_handshake/node.key (32-byte raw private key, hex encoded).
 *
 * On subsequent runs, loads the same key so our node identity is stable.
 * Other nodes can connect to us using our public key as the brontide
 * responder key.
 *
 * Our node's hostname (for ADDR messages) would be:
 *   base32(publicKey)@ourIP:44806
 */
public class NodeIdentity {

    private final byte[] privateKey;
    private final byte[] publicKey;

    public NodeIdentity(String dataDir) throws Exception {
        File keyFile = new File(dataDir, "node.key");

        if (keyFile.exists()) {
            // Load existing key
            String hex = new String(Files.readAllBytes(keyFile.toPath())).trim();
            this.privateKey = hexToBytes(hex);
            System.out.println("[Identity] Loaded node key from " + keyFile.getPath());
        } else {
            // Generate new keypair
            SecureRandom rng = new SecureRandom();
            byte[] priv = new byte[32];
            do {
                rng.nextBytes(priv);
            } while (!isValidPrivKey(priv));

            this.privateKey = priv;

            // Save to file
            File parent = keyFile.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs())
                System.err.println("[Identity] Warning: could not create directory: " + parent);
            Files.write(keyFile.toPath(), bytesToHex(priv).getBytes());
            System.out.println("[Identity] Generated new node key, saved to "
                    + keyFile.getPath());
        }

        this.publicKey = Secp256k1.compressedPublicKey(
                Secp256k1.pointMultiply(Secp256k1.G,
                        new BigInteger(1, privateKey)));
        System.out.println("[Identity] Node public key: " + bytesToHex(publicKey));
        System.out.println("[Identity] Brontide address: "
                + base32Encode(publicKey) + "@<yourIP>:44806");
    }

    public byte[] privateKey() { return privateKey; }

    @SuppressWarnings("unused") // used by PeerServer and future wallet (planned)
    public byte[] publicKey()  { return publicKey; }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static boolean isValidPrivKey(byte[] priv) {
        // Must be non-zero and less than secp256k1 order
        BigInteger n = new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        BigInteger k = new BigInteger(1, priv);
        return k.compareTo(BigInteger.ONE) >= 0 && k.compareTo(n) < 0;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i/2] = (byte)((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        return data;
    }

    @SuppressWarnings("DuplicatedCode") // same algorithm in HNSPeer — kept separate for independence
    private static String base32Encode(byte[] data) {
        final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0)
            sb.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        return sb.toString();
    }
}