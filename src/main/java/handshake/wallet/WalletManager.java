package handshake.wallet;

import handshake.node.EventBus;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages wallet sessions — creation, unlock, lock, and address derivation.
 *
 * Session model:
 *   - Wallet is locked by default at startup
 *   - User unlocks with password → master key held in memory only
 *   - Transactions can be signed without re-entering password while unlocked
 *   - Auto-locks after LOCK_TIMEOUT_MS of inactivity (default 15 minutes)
 *   - Explicit lock() zeros the master key from memory immediately
 *
 * Multiple wallets are supported. Each wallet is independently locked/unlocked.
 * The "active wallet" is the one currently in use for the UI.
 */
public class WalletManager {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final long   LOCK_TIMEOUT_MS   = 15 * 60 * 1000L; // 15 minutes
    private static final int    LOOKAHEAD          = 20; // derive this many addresses ahead
    private static final String WALLET_DB_PATH     = "wallet.mv.db";

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile WalletManager instance;

    public static WalletManager get() {
        if (instance == null) {
            synchronized (WalletManager.class) {
                if (instance == null) instance = new WalletManager();
            }
        }
        return instance;
    }

    // ── Active session ────────────────────────────────────────────────────────

    /** In-memory session for an unlocked wallet. */
    private static class WalletSession {
        final String   walletId;
        BIP32.HDKey    masterKey;  // zeroed on lock
        final AtomicLong lastActivity = new AtomicLong(System.currentTimeMillis());

        WalletSession(String walletId, BIP32.HDKey masterKey) {
            this.walletId  = walletId;
            this.masterKey = masterKey;
        }

        void touch() { lastActivity.set(System.currentTimeMillis()); }

        boolean isExpired() {
            return System.currentTimeMillis() - lastActivity.get() > LOCK_TIMEOUT_MS;
        }

        void zero() {
            if (masterKey != null) {
                masterKey.zeroPrivateKey();
                masterKey = null;
            }
        }
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final WalletDB                         db;
    private final ConcurrentHashMap<String, WalletSession> sessions
            = new ConcurrentHashMap<>();
    private volatile String                        activeWalletId;
    private final ScheduledExecutorService         autoLockScheduler;

    private WalletManager() {
        this.db = WalletDB.init(WALLET_DB_PATH);

        // Auto-lock scheduler — checks every 60 seconds
        this.autoLockScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "wallet-autolock");
            t.setDaemon(true);
            return t;
        });
        autoLockScheduler.scheduleAtFixedRate(
                this::checkAutoLock, 60, 60, TimeUnit.SECONDS);

        // Set active wallet to first wallet if one exists
        List<WalletDB.WalletRecord> wallets = db.getAllWallets();
        if (!wallets.isEmpty())
            activeWalletId = wallets.get(0).id;

        System.out.println("[Wallet] WalletManager started. Wallets: "
                + wallets.size() + ", RIPEMD-160: "
                + (HNSAddress.hasRipemd160() ? "available" : "UNAVAILABLE — using fallback"));
    }

    // ── Wallet creation ───────────────────────────────────────────────────────

    /**
     * Creates a new wallet from a freshly generated mnemonic.
     *
     * @param name      user-friendly wallet name
     * @param password  encryption password (will be zeroed after use)
     * @param use24Words  true for 24-word (256-bit entropy), false for 12-word
     * @return          CreateResult containing the wallet ID and mnemonic
     */
    public CreateResult createWallet(String name, char[] password,
                                     boolean use24Words)
            throws Exception {
        String mnemonic = use24Words
                ? BIP39.generateMnemonic24()
                : BIP39.generateMnemonic12();
        return createWalletFromMnemonic(name, mnemonic, password, "");
    }

    /**
     * Restores a wallet from an existing mnemonic.
     *
     * @param name        user-friendly wallet name
     * @param mnemonic    existing BIP39 mnemonic phrase
     * @param password    new encryption password for this wallet
     * @param passphrase  BIP39 passphrase (empty string if none)
     * @return            CreateResult with wallet ID
     */
    public CreateResult restoreWallet(String name, String mnemonic,
                                      char[] password, String passphrase)
            throws Exception {
        String normalized = mnemonic.trim().toLowerCase()
                .replaceAll("[^a-z\\s]", "")
                .replaceAll("\\s+", " ")
                .trim();
        if (!BIP39.isValid(normalized))
            throw new IllegalArgumentException("Invalid mnemonic phrase — "
                    + "please check all words are correct BIP39 English words");
        return createWalletFromMnemonic(name, normalized, password, passphrase);
    }

    private CreateResult createWalletFromMnemonic(String name, String mnemonic,
                                                  char[] password,
                                                  String passphrase)
            throws Exception {
        // Encrypt the seed phrase
        WalletCrypto.EncryptedSeed encrypted = WalletCrypto.encrypt(
                mnemonic, password);

        // Create wallet record
        WalletDB.WalletRecord wallet = new WalletDB.WalletRecord();
        wallet.id             = generateWalletId();
        wallet.name           = name;
        wallet.encryptedSeed  = encrypted.toStorageString();
        wallet.addressCount   = 0;
        wallet.changeCount    = 0;
        wallet.createdAt      = System.currentTimeMillis();
        wallet.lastUnlocked   = 0;
        wallet.hasBip39Passphrase = !passphrase.isEmpty();
        db.saveWallet(wallet);

        // Derive master key and initial addresses
        byte[] seed        = BIP39.mnemonicToSeed(mnemonic, passphrase);
        BIP32.HDKey master = BIP32.masterFromSeed(seed);
        WalletCrypto.zeroBytes(seed);

        deriveAddresses(wallet.id, master, 0, 0, LOOKAHEAD);

        // Unlock immediately after creation
        sessions.put(wallet.id, new WalletSession(wallet.id, master));
        activeWalletId = wallet.id;

        wallet.addressCount = LOOKAHEAD;
        db.saveWallet(wallet);

        EventBus.get().system("Wallet created: " + name
                + " (" + (wallet.hasBip39Passphrase ? "with" : "no") + " passphrase)");

        return new CreateResult(wallet.id, mnemonic);
    }

    // ── Lock / Unlock ─────────────────────────────────────────────────────────

    /**
     * Unlocks a wallet with the user's password.
     * The derived master key is held in memory until locked.
     *
     * @return true if password is correct, false otherwise
     */
    public boolean unlock(String walletId, char[] password) {
        return unlock(walletId, password, "");
    }

    public boolean unlock(String walletId, char[] password, String passphrase) {
        WalletDB.WalletRecord wallet = db.getWallet(walletId);
        if (wallet == null) return false;

        try {
            WalletCrypto.EncryptedSeed encrypted =
                    WalletCrypto.EncryptedSeed.fromStorageString(wallet.encryptedSeed);

            // Verify password and get mnemonic
            String mnemonic = WalletCrypto.decrypt(encrypted, password);

            // Derive master key
            byte[] seed        = BIP39.mnemonicToSeed(mnemonic, passphrase);
            BIP32.HDKey master = BIP32.masterFromSeed(seed);
            WalletCrypto.zeroBytes(seed);

            // Clear any existing session
            WalletSession old = sessions.remove(walletId);
            if (old != null) old.zero();

            // Create new session
            sessions.put(walletId, new WalletSession(walletId, master));
            activeWalletId = walletId;

            // Update last unlocked time
            wallet.lastUnlocked = System.currentTimeMillis();
            db.saveWallet(wallet);

            EventBus.get().system("Wallet unlocked: " + wallet.name);
            return true;

        } catch (WalletCrypto.BadPasswordException e) {
            EventBus.get().system("Wallet unlock failed: incorrect password");
            return false;
        } catch (Exception e) {
            EventBus.get().system("Wallet unlock error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Locks a wallet, zeroing the master key from memory.
     */
    public void lock(String walletId) {
        WalletSession session = sessions.remove(walletId);
        if (session != null) {
            session.zero();
            WalletDB.WalletRecord wallet = db.getWallet(walletId);
            if (wallet != null)
                EventBus.get().system("Wallet locked: " + wallet.name);
        }
    }

    /** Locks all wallets. */
    public void lockAll() {
        for (String id : sessions.keySet()) lock(id);
    }

    public boolean isUnlocked(String walletId) {
        WalletSession s = sessions.get(walletId);
        if (s == null) return false;
        if (s.isExpired()) {
            lock(walletId);
            return false;
        }
        return true;
    }

    public boolean isActiveWalletUnlocked() {
        return activeWalletId != null && isUnlocked(activeWalletId);
    }

    // ── Address management ────────────────────────────────────────────────────

    /**
     * Returns the next unused receiving address for the active wallet.
     * Derives more addresses if needed.
     */
    public String getNextReceiveAddress(String walletId) {
        requireUnlocked(walletId);
        WalletSession session = sessions.get(walletId);
        WalletDB.WalletRecord wallet = db.getWallet(walletId);
        if (wallet == null) throw new RuntimeException("Wallet not found");

        List<WalletDB.AddressRecord> addrs =
                db.getAddressesForWallet(walletId).stream()
                        .filter(a -> a.change == 0 && !a.used)
                        .sorted(Comparator.comparingInt(a -> a.index))
                        .toList();

        if (addrs.isEmpty()) {
            // Derive more addresses
            int from = wallet.addressCount;
            deriveAddresses(walletId, session.masterKey, 0, from, LOOKAHEAD);
            wallet.addressCount += LOOKAHEAD;
            db.saveWallet(wallet);
            addrs = db.getAddressesForWallet(walletId).stream()
                    .filter(a -> a.change == 0 && !a.used)
                    .sorted(Comparator.comparingInt(a -> a.index))
                    .toList();
        }

        session.touch();
        return addrs.get(0).address;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public WalletDB getWalletDB() { return db; }

    public List<WalletDB.WalletRecord> getAllWallets() {
        return db.getAllWallets();
    }

    public WalletDB.WalletRecord getActiveWallet() {
        return activeWalletId != null ? db.getWallet(activeWalletId) : null;
    }

    public void setActiveWallet(String walletId) {
        if (db.getWallet(walletId) != null)
            activeWalletId = walletId;
    }

    public List<WalletDB.AddressRecord> getAddresses(String walletId) {
        return db.getAddressesForWallet(walletId);
    }

    public long getBalance(String walletId) {
        return db.getBalanceForWallet(walletId);
    }

    public List<WalletDB.NameRecord> getNames(String walletId) {
        return db.getNamesForWallet(walletId);
    }

    public boolean hasWallets() {
        return db.hasWallets();
    }

    // ── Renewal warnings ──────────────────────────────────────────────────────

    /**
     * Checks all owned names for upcoming renewals and publishes warnings.
     * Called periodically by ChainFollower.
     * Names expire after 2 years (~105,120 blocks) without renewal.
     * Warning at 1 month (~4,380 blocks), 1 week (~1,008 blocks).
     */
    public void checkRenewalWarnings(int currentHeight) {
        for (WalletDB.WalletRecord wallet : db.getAllWallets()) {
            for (WalletDB.NameRecord name : db.getNamesForWallet(wallet.id)) {
                int blocks = name.blocksUntilExpiry(currentHeight);
                if (blocks <= 0) {
                    EventBus.get().renewal("⚠ Name EXPIRED: " + name.name
                            + " (wallet: " + wallet.name + ")");
                } else if (blocks <= 1_008) {
                    EventBus.get().renewal("⚠ Name expiring in ~"
                            + (blocks / 144) + " days: " + name.name
                            + " — renew soon!");
                } else if (blocks <= 4_380) {
                    EventBus.get().renewal("Name expiring in ~"
                            + (blocks / 4380) + " month(s): " + name.name);
                }
            }
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /** Derives and stores addresses for a wallet using a master key. */
    private void deriveAddresses(String walletId, BIP32.HDKey master,
                                 int account, int fromIndex, int count) {
        for (int change = 0; change <= 1; change++) {
            for (int i = fromIndex; i < fromIndex + count; i++) {
                BIP32.HDKey key = BIP32.deriveAddress(master, account, change, i);
                String address  = HNSAddress.fromPublicKey(key.publicKey);
                String path     = "m/44'/5353'/" + account + "'/" + change + "/" + i;
                WalletDB.AddressRecord rec = new WalletDB.AddressRecord();
                rec.walletId  = walletId;
                rec.path      = path;
                rec.address   = address;
                rec.publicKey = bytesToHex(key.publicKey);
                rec.account   = account;
                rec.change    = change;
                rec.index     = i;
                rec.used      = false;
                rec.balance   = 0;
                db.saveAddress(rec);
            }
        }
    }

    /** Package-visible: derives more addresses via session key (for WalletScanner). */
    void deriveMoreAddresses(String walletId, int account,
                             int change, int fromIndex, int count) {
        WalletSession session = sessions.get(walletId);
        if (session == null || session.masterKey == null) return;
        for (int i = fromIndex; i < fromIndex + count; i++) {
            BIP32.HDKey key = BIP32.deriveAddress(
                    session.masterKey, account, change, i);
            String address  = HNSAddress.fromPublicKey(key.publicKey);
            String path     = "m/44'/5353'/" + account + "'/" + change + "/" + i;
            WalletDB.AddressRecord rec = new WalletDB.AddressRecord();
            rec.walletId  = walletId;
            rec.path      = path;
            rec.address   = address;
            rec.publicKey = bytesToHex(key.publicKey);
            rec.account   = account;
            rec.change    = change;
            rec.index     = i;
            rec.used      = false;
            rec.balance   = 0;
            db.saveAddress(rec);
        }
        WalletDB.WalletRecord wallet = db.getWallet(walletId);
        if (wallet != null) {
            wallet.addressCount = Math.max(wallet.addressCount, fromIndex + count);
            db.saveWallet(wallet);
        }
    }

    private void checkAutoLock() {
        for (Map.Entry<String, WalletSession> e : sessions.entrySet()) {
            if (e.getValue().isExpired()) lock(e.getKey());
        }
    }

    private void requireUnlocked(String walletId) {
        if (!isUnlocked(walletId))
            throw new IllegalStateException(
                    "Wallet is locked — please unlock first");
    }

    private static String generateWalletId() {
        return "wallet_" + Long.toHexString(System.currentTimeMillis())
                + "_" + Long.toHexString(new java.util.Random().nextLong() & 0xFFFFFFFFL);
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // ── Result types ──────────────────────────────────────────────────────────

    public record CreateResult(String walletId, String mnemonic) {}

    // ── Shutdown ──────────────────────────────────────────────────────────────

    public void shutdown() {
        lockAll();
        autoLockScheduler.shutdown();
        db.close();
    }
}