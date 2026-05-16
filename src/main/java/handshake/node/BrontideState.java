package handshake.node;

import handshake.node.crypto.CryptoUtils;
import handshake.node.crypto.Elligator;
import handshake.node.crypto.Secp256k1;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implements the initiator side of the brontide Noise XK handshake used by the
 * Handshake network. Brontide is a modified version of the Lightning Network
 * brontide protocol with:
 *   - Elligator Squared (SvdW) encoding of ephemeral public keys
 *   - Protocol name: Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared
 *   - No version byte in act messages
 *   - 4-byte encrypted length prefix for transport messages (vs 2-byte in LN)
 *
 * Act sizes:
 *   Act 1 (sent):     elligator(64) + tag(16)            =  80 bytes
 *   Act 2 (received): elligator(64) + tag(16)            =  80 bytes
 *   Act 3 (sent):     ct_pubkey(33) + tag1(16) + tag2(16) = 65 bytes
 *
 * Post-handshake transport framing matches BrontideStream.write():
 *   write() uses: encLen(2 BE) + lenTag(16) + encBody(N) + bodyTag(16) = 18+N+16
 *   _parse() reads: HEADER_SIZE(20) bytes then readUInt32LE — but this is
 *   used to RECEIVE from peers; write() is what we SEND as initiator.
 *   Header size for reading: 20 bytes (4-byte LE len + 16-byte tag)
 *   Header size for sending: 18 bytes (2-byte BE len + 16-byte tag)
 *
 * Session keys are derived via Noise Split() at the end of Act 3:
 *   [sendKey, recvKey] = HKDF(ck, zerolen)
 *   sendNonce and recvNonce both start at 0.
 */
public class BrontideState {

    // -------------------------------------------------------------------------
    // Protocol constants
    // -------------------------------------------------------------------------

    public static final String PROTOCOL_NAME =
            "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared";
    public static final String PROLOGUE = "hns";

    public static final int ACT_ONE_SIZE   = 80; // elligator(64) + tag(16)
    public static final int ACT_TWO_SIZE   = 80; // elligator(64) + tag(16)
    public static final int ACT_THREE_SIZE = 65; // ct_pubkey(33) + tag1(16) + tag2(16)

    // Transport framing sizes — BrontideStream.write() format:
    // encLen(4 LE) + lenTag(16) + encBody(N) + bodyTag(16)
    // Header (send/recv): 4 + 16 = 20 bytes
    public static final int SEND_HEADER_SIZE = 20;
    public static final int HEADER_SIZE      = 20;

    private static final SecureRandom RNG = new SecureRandom();

    // -------------------------------------------------------------------------
    // Handshake state fields (cleared after split)
    // -------------------------------------------------------------------------

    private byte[]       chain;
    private byte[]       digest;
    private byte[]       key;
    private int          nonce;
    private final byte[] iv = new byte[12];

    private final byte[]   localStaticPriv;
    private final byte[]   localStaticPub;
    private byte[]         localEphemeralPriv;
    private BigInteger[]   localEphemeralPubPoint;
    private final byte[]   remoteStaticPub;
    private BigInteger[]   remoteEphemeralPubPoint;

    // -------------------------------------------------------------------------
    // Session keys — set after split(), used for transport encryption
    // -------------------------------------------------------------------------

    private byte[] sendKey;
    private byte[] recvKey;
    private int    sendNonce;
    private int    recvNonce;
    private final byte[] sendIv = new byte[12];
    private final byte[] recvIv = new byte[12];
    private boolean      ready  = false; // true after split() is called

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * Constructor for the INITIATOR side (outbound connection).
     * We know the remote peer's static public key in advance.
     */
    public BrontideState(byte[] localStaticPriv, byte[] remoteStaticPub) {
        this.localStaticPriv = localStaticPriv;
        this.localStaticPub  = pubKeyFromPriv(localStaticPriv);
        this.remoteStaticPub = remoteStaticPub;
        this.isInitiator     = true;
    }

    /**
     * Constructor for the RESPONDER side (inbound connection).
     * We don't know the remote peer's static key yet — it arrives in Act Three.
     */
    public BrontideState(byte[] localStaticPriv) {
        this.localStaticPriv = localStaticPriv;
        this.localStaticPub  = pubKeyFromPriv(localStaticPriv);
        this.remoteStaticPub = null; // learned in recvActThree
        this.isInitiator     = false;
    }

    /** True if we are the initiator (outbound), false if responder (inbound). */
    private final boolean isInitiator;

    /** The remote peer's static public key — set in recvActThree for responder. */
    private byte[] remoteStaticPubDiscovered;

    // -------------------------------------------------------------------------
    // Initialisation
    // -------------------------------------------------------------------------

    public void init() {
        this.digest = CryptoUtils.sha256(PROTOCOL_NAME.getBytes());
        this.chain  = digest.clone();
        this.key    = new byte[32];
        this.nonce  = 0;
        updateIv();

        // Mix the prologue
        mixHash(PROLOGUE.getBytes());

        // Initiator mixes remote static pub; responder mixes local static pub
        if (isInitiator)
            mixHash(remoteStaticPub);
        else
            mixHash(localStaticPub);
    }

    // -------------------------------------------------------------------------
    // Act 1 — initiator sends 80 bytes
    // -------------------------------------------------------------------------

    public byte[] genActOne() {
        generateEphemeral();

        byte[] ephemeralPub = Secp256k1.compressedPublicKey(localEphemeralPubPoint);
        byte[] uniform      = Elligator.encode(localEphemeralPubPoint);

        mixHash(ephemeralPub);

        // es: ecdh(remoteStatic, localEphemeral)
        byte[] es = Secp256k1.ecdh(remoteStaticPub, localEphemeralPriv);
        mixKey(es);

        byte[] tag = encryptHash(new byte[0]);

        byte[] actOne = new byte[ACT_ONE_SIZE];
        System.arraycopy(uniform, 0, actOne, 0,  64);
        System.arraycopy(tag,     0, actOne, 64, 16);
        return actOne;
    }

    // -------------------------------------------------------------------------
    // Act 2 — initiator receives 80 bytes
    // -------------------------------------------------------------------------

    public boolean recvActTwo(byte[] actTwo) {
        byte[] uniform = Arrays.copyOfRange(actTwo, 0,  64);
        byte[] tag     = Arrays.copyOfRange(actTwo, 64, 80);

        BigInteger[] remoteEphPoint;
        try {
            remoteEphPoint = Elligator.decode(uniform);
        } catch (Exception e) {
            System.out.println("    Act 2 elligator decode failed: " + e.getMessage());
            return false;
        }
        this.remoteEphemeralPubPoint = remoteEphPoint;
        byte[] remoteEphPub = Secp256k1.compressedPublicKey(remoteEphPoint);

        mixHash(remoteEphPub);

        // ee: ecdh(remoteEphemeral, localEphemeral)
        byte[] ee = Secp256k1.ecdh(remoteEphPub, localEphemeralPriv);
        mixKey(ee);

        return decryptHash(new byte[0], tag);
    }

    // -------------------------------------------------------------------------
    // Act 3 — initiator sends 65 bytes, then calls split()
    // -------------------------------------------------------------------------

    public byte[] genActThree() {
        byte[] ourPub = localStaticPub.clone();
        byte[] tag1   = encryptHash(ourPub); // ourPub encrypted in-place, tag returned

        // se: ecdh(remoteEphemeral, localStatic)
        byte[] remoteEphPub = Secp256k1.compressedPublicKey(remoteEphemeralPubPoint);
        byte[] se           = Secp256k1.ecdh(remoteEphPub, localStaticPriv);
        mixKey(se);

        byte[] tag2 = encryptHash(new byte[0]);

        byte[] actThree = new byte[ACT_THREE_SIZE];
        System.arraycopy(ourPub, 0, actThree, 0,  33);
        System.arraycopy(tag1,   0, actThree, 33, 16);
        System.arraycopy(tag2,   0, actThree, 49, 16);

        // Derive session keys immediately after Act 3
        split();

        return actThree;
    }

    // -------------------------------------------------------------------------
    // Responder side — Act 1 receive, Act 2 send, Act 3 receive
    // -------------------------------------------------------------------------

    /**
     * RESPONDER: Receives Act One (80 bytes) from the initiator.
     * Extracts the initiator's ephemeral public key and verifies the tag.
     *
     * @param actOne 80-byte Act One from the initiator
     * @return true if the tag is valid
     */
    public boolean recvActOne(byte[] actOne) {
        if (actOne.length != ACT_ONE_SIZE) return false;

        byte[] uniform = Arrays.copyOfRange(actOne, 0,  64);
        byte[] tag     = Arrays.copyOfRange(actOne, 64, 80);

        // Decode elligator-encoded ephemeral public key
        BigInteger[] remoteEphPoint;
        try {
            remoteEphPoint = Elligator.decode(uniform);
        } catch (Exception e) {
            return false;
        }
        this.remoteEphemeralPubPoint = remoteEphPoint;
        byte[] remoteEphPub = Secp256k1.compressedPublicKey(remoteEphPoint);

        mixHash(remoteEphPub);

        // es: ecdh(remoteEphemeral, localStatic)  [responder's static is our local]
        byte[] es = Secp256k1.ecdh(remoteEphPub, localStaticPriv);
        mixKey(es);

        return decryptHash(new byte[0], tag);
    }

    /**
     * RESPONDER: Generates Act Two (80 bytes) to send to the initiator.
     * Creates our ephemeral keypair and performs ee ECDH.
     *
     * @return 80-byte Act Two
     */
    public byte[] genActTwo() {
        generateEphemeral();

        byte[] ephemeralPub = Secp256k1.compressedPublicKey(localEphemeralPubPoint);
        byte[] uniform      = Elligator.encode(localEphemeralPubPoint);

        mixHash(ephemeralPub);

        // ee: ecdh(remoteEphemeral, localEphemeral)
        byte[] remoteEphPub = Secp256k1.compressedPublicKey(remoteEphemeralPubPoint);
        byte[] ee           = Secp256k1.ecdh(remoteEphPub, localEphemeralPriv);
        mixKey(ee);

        byte[] tag    = encryptHash(new byte[0]);
        byte[] actTwo = new byte[ACT_TWO_SIZE];
        System.arraycopy(uniform, 0, actTwo, 0,  64);
        System.arraycopy(tag,     0, actTwo, 64, 16);
        return actTwo;
    }

    /**
     * RESPONDER: Receives Act Three (65 bytes) from the initiator.
     * Decrypts the initiator's static public key and verifies both tags.
     * Calls split() to derive session keys.
     *
     * @param actThree 65-byte Act Three from the initiator
     * @return true if both tags are valid
     */
    public boolean recvActThree(byte[] actThree) {
        if (actThree.length != ACT_THREE_SIZE) return false;

        byte[] cipherPub = Arrays.copyOfRange(actThree, 0,  33);
        byte[] tag1      = Arrays.copyOfRange(actThree, 33, 49);
        byte[] tag2      = Arrays.copyOfRange(actThree, 49, 65);

        // Decrypt the initiator's static public key
        if (!decryptHash(cipherPub, tag1)) return false;
        this.remoteStaticPubDiscovered = cipherPub; // now holds decrypted pub

        // se: ecdh(remoteStatic, localEphemeral)
        byte[] se = Secp256k1.ecdh(remoteStaticPubDiscovered, localEphemeralPriv);
        mixKey(se);

        if (!decryptHash(new byte[0], tag2)) return false;

        // Derive session keys
        split();
        return true;
    }

    /**
     * Returns the remote peer's static public key discovered during Act Three.
     * Only valid for the responder after a successful recvActThree().
     */
    public byte[] getRemoteStaticPub() {
        return isInitiator ? remoteStaticPub : remoteStaticPubDiscovered;
    }

    // -------------------------------------------------------------------------
    // Split — derives send/recv session keys via Noise Split()
    //
    // From BOLT #8 / Noise spec:
    //   [sendKey, recvKey] = HKDF(ck, zerolen)
    //   Both nonces start at 0.
    //   The handshake state (chain, digest, key) is cleared.
    // -------------------------------------------------------------------------

    private void split() {
        byte[][] keys = CryptoUtils.hkdfExpand(new byte[0], chain);
        this.sendKey   = keys[0];
        this.recvKey   = keys[1];
        this.sendNonce = 0;
        this.recvNonce = 0;
        // Salt is initialized to the chain value, matching hsd's
        // sendCipher.initSalt(h1, this.chain) / recvCipher.initSalt(h2, this.chain)
        this.sendSalt  = chain.clone();
        this.recvSalt  = chain.clone();
        updateNonceIv(sendIv, sendNonce);
        updateNonceIv(recvIv, recvNonce);
        this.ready = true;


        // Clear handshake state — no longer needed
        Arrays.fill(chain,  (byte) 0);
        Arrays.fill(key,    (byte) 0);
        Arrays.fill(digest, (byte) 0);
        this.chain  = null;
        this.key    = null;
        this.digest = null;
    }

    // -------------------------------------------------------------------------
    // Transport encryption — encryptMessage(plaintext) -> wire bytes
    //
    // Wire format (matching hsd brontide):
    //   encryptedLength(4) + lengthTag(16) + encryptedBody(N) + bodyTag(16)
    //
    // The length field contains the plaintext body length as a big-endian uint32,
    // encrypted separately with its own nonce to allow streaming decryption.
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Key rotation — matches hsd CipherState.rotateKey()
    //
    // Called when nonce reaches ROTATION_INTERVAL (1000).
    // Uses HKDF expand(old_key, salt, info=EMPTY) to derive new salt and key.
    // Nonce resets to 0 after rotation.
    // -------------------------------------------------------------------------

    private static final long ROTATION_INTERVAL = 1000;

    /** Salt for the send cipher, updated on each key rotation. */
    private byte[] sendSalt = new byte[32];

    /** Salt for the recv cipher, updated on each key rotation. */
    private byte[] recvSalt = new byte[32];

    private void rotateSendKey() {
        byte[][] expanded = CryptoUtils.hkdfExpand(sendKey, sendSalt);
        sendSalt = expanded[0];
        sendKey  = expanded[1];
        sendNonce = 0;
        updateNonceIv(sendIv, sendNonce);
    }

    private void rotateRecvKey() {
        byte[][] expanded = CryptoUtils.hkdfExpand(recvKey, recvSalt);
        recvSalt = expanded[0];
        recvKey  = expanded[1];
        recvNonce = 0;
        updateNonceIv(recvIv, recvNonce);
    }

    public byte[] encryptMessage(byte[] plaintext) {
        if (!ready) throw new IllegalStateException("Handshake not complete.");

        int bodyLen = plaintext.length;

        // BrontideStream.write() format: 4-byte LE length
        byte[] lenBytes = new byte[4];
        lenBytes[0] = (byte)  (bodyLen        & 0xFF);
        lenBytes[1] = (byte) ((bodyLen >>  8) & 0xFF);
        lenBytes[2] = (byte) ((bodyLen >> 16) & 0xFF);
        lenBytes[3] = (byte) ((bodyLen >> 24) & 0xFF);
        byte[] lenTag = CryptoUtils.chachaEncrypt(sendKey, sendIv, lenBytes, new byte[0]);
        sendNonce++;
        updateNonceIv(sendIv, sendNonce);
        if (sendNonce == ROTATION_INTERVAL) rotateSendKey();

        // Encrypt the body
        byte[] body    = plaintext.clone();
        byte[] bodyTag = CryptoUtils.chachaEncrypt(sendKey, sendIv, body, new byte[0]);
        sendNonce++;
        updateNonceIv(sendIv, sendNonce);
        if (sendNonce == ROTATION_INTERVAL) rotateSendKey();

        // Wire: encLen(4) + lenTag(16) + encBody(N) + bodyTag(16)
        byte[] packet = new byte[4 + 16 + bodyLen + 16];
        System.arraycopy(lenBytes, 0, packet, 0,          4);
        System.arraycopy(lenTag,   0, packet, 4,          16);
        System.arraycopy(body,     0, packet, 20,         bodyLen);
        System.arraycopy(bodyTag,  0, packet, 20 + bodyLen, 16);
        return packet;
    }

    // -------------------------------------------------------------------------
    // Transport decryption — decryptHeader(headerBytes) -> plaintext body length
    //
    // Call decryptHeader() first to learn the body size, read that many + 16
    // bytes from the stream, then call decryptBody().
    // -------------------------------------------------------------------------

    public int decryptHeader(byte[] headerBytes) {
        if (!ready) throw new IllegalStateException("Handshake not complete.");
        if (headerBytes.length != HEADER_SIZE)
            throw new IllegalArgumentException("Header must be " + HEADER_SIZE + " bytes.");

        // BrontideStream.write() / _parse() format: 4-byte LE len + 16-byte tag
        byte[] lenCt  = Arrays.copyOfRange(headerBytes, 0,  4);
        byte[] lenTag = Arrays.copyOfRange(headerBytes, 4, 20);

        boolean ok = CryptoUtils.chachaDecrypt(recvKey, recvIv, lenCt, lenTag, new byte[0]);
        if (!ok) throw new SecurityException("Header authentication failed.");
        recvNonce++;
        updateNonceIv(recvIv, recvNonce);
        if (recvNonce == ROTATION_INTERVAL) rotateRecvKey();

        return  (lenCt[0] & 0xFF)
                | ((lenCt[1] & 0xFF) <<  8)
                | ((lenCt[2] & 0xFF) << 16)
                | ((lenCt[3] & 0xFF) << 24);
    }

    public byte[] decryptBody(byte[] bodyBytes) {
        if (!ready) throw new IllegalStateException("Handshake not complete.");
        if (bodyBytes.length < 16)
            throw new IllegalArgumentException("Body must include 16-byte tag.");

        int bodyLen   = bodyBytes.length - 16;
        byte[] bodyCt = Arrays.copyOfRange(bodyBytes, 0,       bodyLen);
        byte[] bodyTag = Arrays.copyOfRange(bodyBytes, bodyLen, bodyBytes.length);

        boolean ok = CryptoUtils.chachaDecrypt(recvKey, recvIv, bodyCt, bodyTag, new byte[0]);
        if (!ok) throw new SecurityException("Body authentication failed.");
        recvNonce++;
        updateNonceIv(recvIv, recvNonce);
        if (recvNonce == ROTATION_INTERVAL) rotateRecvKey();

        return bodyCt; // decrypted in-place
    }

    // -------------------------------------------------------------------------
    // Convenience: returns true once split() has been called
    // -------------------------------------------------------------------------

    public boolean isReady() {
        return ready;
    }

    // -------------------------------------------------------------------------
    // Symmetric state (handshake phase)
    // -------------------------------------------------------------------------

    public void mixHash(byte[] data) {
        this.digest = CryptoUtils.sha256Concat(digest, data);
    }

    public void mixHash(byte[] data, byte[] tag) {
        this.digest = CryptoUtils.sha256Concat(digest, data, tag);
    }

    private void mixKey(byte[] input) {
        byte[][] expanded = CryptoUtils.hkdfExpand(input, chain);
        this.chain = expanded[0];
        this.key   = expanded[1];
        this.nonce = 0;
        updateIv();
    }

    private byte[] encryptHash(byte[] pt) {
        // hsd SymmetricState.encryptHash:
        //   tag = this.encrypt(pt, this.digest)  — encrypts pt IN-PLACE
        //   this.mixHash(pt, tag)                — pt is now CIPHERTEXT
        byte[] tag = CryptoUtils.chachaEncrypt(key, iv, pt, digest);
        mixHash(pt, tag); // pt is now ciphertext (modified in-place by chachaEncrypt)
        nonce++;
        updateIv();
        return tag;
    }

    private boolean decryptHash(byte[] ct, byte[] tag) {
        byte[] newDigest = CryptoUtils.sha256Concat(digest, ct, tag);
        boolean ok = CryptoUtils.chachaDecrypt(key, iv, ct, tag, digest);
        if (ok) this.digest = newDigest;
        nonce++;
        updateIv();
        return ok;
    }

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    private byte[] pubKeyFromPriv(byte[] priv) {
        BigInteger scalar = new BigInteger(1, priv).mod(Secp256k1.N);
        return Secp256k1.compressedPublicKey(Secp256k1.pointMultiply(Secp256k1.G, scalar));
    }

    private void generateEphemeral() {
        localEphemeralPriv = new byte[32];
        RNG.nextBytes(localEphemeralPriv);
        BigInteger scalar = new BigInteger(1, localEphemeralPriv).mod(Secp256k1.N);
        localEphemeralPriv     = Secp256k1.to32Bytes(scalar);
        localEphemeralPubPoint = Secp256k1.pointMultiply(Secp256k1.G, scalar);
    }

    // -------------------------------------------------------------------------
    // IV management
    // -------------------------------------------------------------------------

    // Handshake IV: nonce as little-endian uint32 at bytes 4-7 (matches hsd)
    private void updateIv() {
        Arrays.fill(iv, (byte) 0);
        iv[4] = (byte)  (nonce        & 0xFF);
        iv[5] = (byte) ((nonce >>  8) & 0xFF);
        iv[6] = (byte) ((nonce >> 16) & 0xFF);
        iv[7] = (byte) ((nonce >> 24) & 0xFF);
    }

    // Transport IV: nonce as little-endian uint32 at bytes 4-7
    // Matches CipherState.update(): this.iv.writeUInt32LE(this.nonce, 4)
    private void updateNonceIv(byte[] ivBuf, long n) {
        Arrays.fill(ivBuf, (byte) 0);
        ivBuf[4] = (byte)  (n        & 0xFF);
        ivBuf[5] = (byte) ((n >>  8) & 0xFF);
        ivBuf[6] = (byte) ((n >> 16) & 0xFF);
        ivBuf[7] = (byte) ((n >> 24) & 0xFF);
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}