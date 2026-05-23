package handshake.node;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Manages TLS for Easy Handshake using only standard Java APIs.
 *
 * On first run: invokes the JDK's keytool command to generate a
 * 10-year RSA-2048 self-signed certificate stored in node.keystore.
 *
 * No internal/sun.* APIs are used — only javax.net.ssl and java.security.
 *
 * The certificate is used for:
 *   - DoH (DNS over HTTPS) on port 8443
 *   - HTTPS dashboard on port 8443
 */
public class TLSManager {

    private static final String KEYSTORE_FILE     = "node.keystore";
    private static final String KEYSTORE_PASSWORD = "easy-handshake";
    private static final String KEY_ALIAS         = "node";
    private static final int    CERT_VALIDITY_DAYS = 3650; // 10 years

    private final Path   keystorePath;
    private SSLContext   sslContext;

    public TLSManager(String dataDir) {
        this.keystorePath = Path.of(dataDir, KEYSTORE_FILE);
    }

    public void init() throws Exception {
        if (!Files.exists(keystorePath)) {
            System.out.println("[TLS] No certificate found — generating self-signed certificate...");
            generateCertificateViaKeytool();
        } else {
            System.out.println("[TLS] Loading existing certificate from " + keystorePath);
        }
        loadSslContext();
        System.out.println("[TLS] SSL context ready.");
    }

    // ── Certificate generation via keytool ────────────────────────────────

    private void generateCertificateViaKeytool() throws Exception {
        // Find keytool — same directory as the running JVM
        String javaHome  = System.getProperty("java.home");
        String keytool   = javaHome + File.separator + "bin"
                + File.separator + "keytool";
        // On Windows
        if (System.getProperty("os.name").toLowerCase().contains("win"))
            keytool += ".exe";
        // Fallback to PATH
        if (!new File(keytool).exists()) keytool = "keytool";

        ProcessBuilder pb = new ProcessBuilder(
                keytool,
                "-genkeypair",
                "-alias",       KEY_ALIAS,
                "-keyalg",      "RSA",
                "-keysize",     "2048",
                "-sigalg",      "SHA256withRSA",
                "-validity",    String.valueOf(CERT_VALIDITY_DAYS),
                "-dname",       "CN=easy-handshake.local, O=Easy Handshake, C=US",
                "-keystore",    keystorePath.toString(),
                "-storepass",   KEYSTORE_PASSWORD,
                "-keypass",     KEYSTORE_PASSWORD,
                "-storetype",   "PKCS12",
                "-noprompt"
        );
        pb.redirectErrorStream(true);

        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes());
        int exitCode = p.waitFor();

        if (exitCode != 0) {
            throw new Exception("keytool failed (exit " + exitCode + "): " + output);
        }

        System.out.println("[TLS] Certificate generated: " + keystorePath);
        System.out.println("[TLS] Fingerprint: " + getFingerprint());
    }

    // ── SSL context ───────────────────────────────────────────────────────

    private void loadSslContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(keystorePath)) {
            ks.load(is, KEYSTORE_PASSWORD.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        // Log cert info
        java.security.cert.Certificate cert = ks.getCertificate(KEY_ALIAS);
        if (cert instanceof X509Certificate x509) {
            System.out.printf("[TLS] Subject:  %s%n",
                    x509.getSubjectX500Principal().getName());
            System.out.printf("[TLS] Expires:  %s%n", x509.getNotAfter());
            System.out.printf("[TLS] SHA-256:  %s%n", fingerprint(x509));
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    public SSLContext getSslContext() { return sslContext; }

    public String getCertFingerprint() {
        try { return getFingerprint(); }
        catch (Exception e) { return "unavailable"; }
    }

    private String getFingerprint() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(keystorePath)) {
            ks.load(is, KEYSTORE_PASSWORD.toCharArray());
        }
        java.security.cert.Certificate cert = ks.getCertificate(KEY_ALIAS);
        return cert instanceof X509Certificate x509
                ? fingerprint(x509) : "unknown";
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static String fingerprint(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", digest[i]));
        }
        return sb.toString();
    }
}