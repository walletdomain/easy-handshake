package handshake.wallet;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.util.*;

/**
 * Persistent wallet database backed by MVStore (wallet.mv.db).
 *
 * Kept separate from chain.mv.db and config.mv.db so the wallet
 * survives chain resets and can be backed up independently.
 *
 * Maps:
 *   wallets    → walletId(String)     → serialized WalletRecord
 *   addresses  → "walletId:path"      → serialized AddressRecord
 *   addrIndex  → address(String)      → "walletId:path" (reverse lookup)
 *   utxos      → "txhash:index"       → serialized UtxoRecord
 *   names      → name(String)         → serialized NameRecord
 *   meta       → key(String)          → value(String)
 */
public class WalletDB implements AutoCloseable {

    // ── Records ───────────────────────────────────────────────────────────────

    public static class WalletRecord {
        public String  id;
        public String  name;           // user-friendly label e.g. "Main Wallet"
        public String  encryptedSeed;  // WalletCrypto.EncryptedSeed.toStorageString()
        public int     addressCount;   // number of addresses derived so far
        public int     changeCount;    // number of change addresses
        public long    createdAt;
        public long    lastUnlocked;
        public boolean hasBip39Passphrase; // true if user set a BIP39 passphrase

        public String toStorage() {
            return name + "|" + encryptedSeed + "|" + addressCount + "|"
                    + changeCount + "|" + createdAt + "|" + lastUnlocked + "|"
                    + hasBip39Passphrase;
        }

        public static WalletRecord fromStorage(String id, String s) {
            // encryptedSeed contains dots and pipes internally, so split carefully
            // Format: name|salt.nonce.cipher|addressCount|changeCount|createdAt|lastUnlocked|hasBip39
            int first = s.indexOf('|');
            // Find the last 5 pipes from the right
            int last5  = findNthFromEnd(s, '|', 5);
            WalletRecord r  = new WalletRecord();
            r.id            = id;
            r.name          = s.substring(0, first);
            r.encryptedSeed = s.substring(first + 1, last5);
            String[] tail   = s.substring(last5 + 1).split("\\|");
            r.addressCount  = Integer.parseInt(tail[0]);
            r.changeCount   = Integer.parseInt(tail[1]);
            r.createdAt     = Long.parseLong(tail[2]);
            r.lastUnlocked  = Long.parseLong(tail[3]);
            r.hasBip39Passphrase = Boolean.parseBoolean(tail[4]);
            return r;
        }

        private static int findNthFromEnd(String s, char c, int n) {
            int count = 0;
            for (int i = s.length() - 1; i >= 0; i--) {
                if (s.charAt(i) == c) {
                    count++;
                    if (count == n) return i;
                }
            }
            return -1;
        }
    }

    public static class AddressRecord {
        public String walletId;
        public String path;        // e.g. "m/44'/5353'/0'/0/0"
        public String address;     // "hs1q..."
        public String publicKey;   // hex-encoded compressed pubkey
        public int    account;
        public int    change;      // 0=receiving, 1=change
        public int    index;
        public boolean used;       // true once a tx has been seen for this address
        public long    balance;    // satoshis (updated during UTXO scan)

        public String toStorage() {
            return walletId + "|" + path + "|" + address + "|" + publicKey
                    + "|" + account + "|" + change + "|" + index
                    + "|" + used + "|" + balance;
        }

        public static AddressRecord fromStorage(String s) {
            String[] p = s.split("\\|", 9);
            AddressRecord r = new AddressRecord();
            r.walletId  = p[0];
            r.path      = p[1];
            r.address   = p[2];
            r.publicKey = p[3];
            r.account   = Integer.parseInt(p[4]);
            r.change    = Integer.parseInt(p[5]);
            r.index     = Integer.parseInt(p[6]);
            r.used      = Boolean.parseBoolean(p[7]);
            r.balance   = Long.parseLong(p[8]);
            return r;
        }

        public String toJson() {
            return String.format(
                    "{\"path\":\"%s\",\"address\":\"%s\","
                            + "\"account\":%d,\"change\":%d,\"index\":%d,"
                            + "\"used\":%b,\"balance\":%d}",
                    path, address, account, change, index, used, balance);
        }
    }

    public static class UtxoRecord {
        public String  txHash;
        public int     outputIndex;
        public String  address;
        public long    value;      // satoshis
        public int     height;
        public boolean spent;
        public boolean coinbase;

        public String key() { return txHash + ":" + outputIndex; }

        public String toStorage() {
            return txHash + "|" + outputIndex + "|" + address + "|"
                    + value + "|" + height + "|" + spent + "|" + coinbase;
        }

        public static UtxoRecord fromStorage(String s) {
            String[] p = s.split("\\|", 7);
            UtxoRecord r = new UtxoRecord();
            r.txHash      = p[0];
            r.outputIndex = Integer.parseInt(p[1]);
            r.address     = p[2];
            r.value       = Long.parseLong(p[3]);
            r.height      = Integer.parseInt(p[4]);
            r.spent       = Boolean.parseBoolean(p[5]);
            r.coinbase    = Boolean.parseBoolean(p[6]);
            return r;
        }

        public String toJson() {
            return String.format(
                    "{\"txHash\":\"%s\",\"index\":%d,\"address\":\"%s\","
                            + "\"value\":%d,\"height\":%d,\"spent\":%b}",
                    txHash, outputIndex, address, value, height, spent);
        }
    }

    public static class NameRecord {
        public String name;
        public String walletId;
        public String ownerAddress;
        public int    height;        // block height of last covenant update
        public int    expireHeight;  // block height when name expires
        public long   lastRenewed;   // epoch ms
        public String state;         // REGISTERED, TRANSFERRING, etc.
        // Fields needed for TRANSFER/FINALIZE transactions:
        public String nameHash;      // hex SHA3-256 of name (32 bytes)
        public String utxoTxHash;    // hex txid of current name UTXO
        public int    utxoIndex;     // output index of current name UTXO
        public int    claimHeight;   // original registration height (items[1])
        public int    renewalCount;  // number of renewals (items[5] in FINALIZE)

        public String toStorage() {
            return walletId + "|" + ownerAddress + "|" + height + "|"
                    + expireHeight + "|" + lastRenewed + "|" + state + "|"
                    + (nameHash != null ? nameHash : "") + "|"
                    + (utxoTxHash != null ? utxoTxHash : "") + "|"
                    + utxoIndex + "|" + claimHeight + "|" + renewalCount;
        }

        public static NameRecord fromStorage(String name, String s) {
            String[] p = s.split("\\|", 11);
            NameRecord r    = new NameRecord();
            r.name          = name;
            r.walletId      = p[0];
            r.ownerAddress  = p[1];
            r.height        = Integer.parseInt(p[2]);
            r.expireHeight  = Integer.parseInt(p[3]);
            r.lastRenewed   = Long.parseLong(p[4]);
            r.state         = p[5];
            r.nameHash      = p.length > 6  ? p[6]  : "";
            r.utxoTxHash    = p.length > 7  ? p[7]  : "";
            r.utxoIndex     = p.length > 8  ? Integer.parseInt(p[8])  : 0;
            r.claimHeight   = p.length > 9  ? Integer.parseInt(p[9])  : r.height;
            r.renewalCount  = p.length > 10 ? Integer.parseInt(p[10]) : 0;
            return r;
        }

        /** Returns blocks until expiry. Negative if already expired. */
        public int blocksUntilExpiry(int currentHeight) {
            return expireHeight - currentHeight;
        }

        public String toJson() {
            return String.format(
                    "{\"name\":\"%s\",\"address\":\"%s\","
                            + "\"expireHeight\":%d,\"state\":\"%s\"}",
                    name, ownerAddress, expireHeight, state);
        }
    }

    // ── Singleton / factory ───────────────────────────────────────────────────

    private static volatile WalletDB instance;

    public static WalletDB get() {
        if (instance == null)
            throw new IllegalStateException("WalletDB not initialized — call init() first");
        return instance;
    }

    public static WalletDB init(String path) {
        if (instance == null) {
            synchronized (WalletDB.class) {
                if (instance == null) instance = new WalletDB(path);
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final MVStore                  store;
    private final MVMap<String, String>    wallets;
    private final MVMap<String, String>    addresses;
    private final MVMap<String, String>    addrIndex;  // address → "walletId:path"
    private final MVMap<String, String>    utxos;
    private final MVMap<String, String>    names;
    private final MVMap<String, String>    meta;

    private WalletDB(String path) {
        this.store     = new MVStore.Builder()
                .fileName(path)
                .compress()
                .open();
        this.wallets   = store.openMap("wallets");
        this.addresses = store.openMap("addresses");
        this.addrIndex = store.openMap("addrIndex");
        this.utxos     = store.openMap("utxos");
        this.names     = store.openMap("names");
        this.meta      = store.openMap("meta");
    }

    // ── Wallet CRUD ───────────────────────────────────────────────────────────

    public void saveWallet(WalletRecord wallet) {
        wallets.put(wallet.id, wallet.toStorage());
        store.commit();
    }

    public WalletRecord getWallet(String id) {
        String s = wallets.get(id);
        return s != null ? WalletRecord.fromStorage(id, s) : null;
    }

    public List<WalletRecord> getAllWallets() {
        List<WalletRecord> list = new ArrayList<>();
        for (Map.Entry<String, String> e : wallets.entrySet())
            list.add(WalletRecord.fromStorage(e.getKey(), e.getValue()));
        list.sort(Comparator.comparingLong(w -> w.createdAt));
        return list;
    }

    public boolean hasWallets() { return !wallets.isEmpty(); }

    // ── Address CRUD ──────────────────────────────────────────────────────────

    public void saveAddress(AddressRecord addr) {
        String key = addr.walletId + ":" + addr.path;
        addresses.put(key, addr.toStorage());
        addrIndex.put(addr.address, key);
        store.commit();
    }

    public AddressRecord getAddress(String walletId, String path) {
        String s = addresses.get(walletId + ":" + path);
        return s != null ? AddressRecord.fromStorage(s) : null;
    }

    /** Returns the walletId and path for an address, or null if not ours. */
    public String[] lookupAddress(String address) {
        String key = addrIndex.get(address);
        if (key == null) return null;
        int sep = key.indexOf(':');
        return new String[]{ key.substring(0, sep), key.substring(sep + 1) };
    }

    public List<AddressRecord> getAddressesForWallet(String walletId) {
        List<AddressRecord> list = new ArrayList<>();
        String prefix = walletId + ":";
        for (Map.Entry<String, String> e : addresses.entrySet()) {
            if (e.getKey().startsWith(prefix))
                list.add(AddressRecord.fromStorage(e.getValue()));
        }
        list.sort(Comparator.comparingInt((AddressRecord a) -> a.change)
                .thenComparingInt(a -> a.index));
        return list;
    }

    /** Returns all known addresses for UTXO scanning. */
    public Set<String> getAllAddressStrings() {
        return Collections.unmodifiableSet(addrIndex.keySet());
    }

    // ── UTXO CRUD ─────────────────────────────────────────────────────────────

    public void saveUtxo(UtxoRecord utxo) {
        utxos.put(utxo.key(), utxo.toStorage());
    }

    public void commitUtxos() { store.commit(); }

    public UtxoRecord getUtxo(String txHash, int index) {
        String s = utxos.get(txHash + ":" + index);
        return s != null ? UtxoRecord.fromStorage(s) : null;
    }

    public List<UtxoRecord> getUtxosForAddress(String address) {
        List<UtxoRecord> list = new ArrayList<>();
        for (String s : utxos.values()) {
            UtxoRecord r = UtxoRecord.fromStorage(s);
            if (address.equals(r.address) && !r.spent) list.add(r);
        }
        return list;
    }

    /** Returns all UTXOs for an address including spent/locked ones (e.g. name UTXOs). */
    public List<UtxoRecord> getAllUtxosForAddress(String address) {
        List<UtxoRecord> list = new ArrayList<>();
        for (String s : utxos.values()) {
            UtxoRecord r = UtxoRecord.fromStorage(s);
            if (address.equals(r.address)) list.add(r);
        }
        return list;
    }

    public long getBalanceForWallet(String walletId) {
        Set<String> myAddresses = new HashSet<>();
        for (AddressRecord a : getAddressesForWallet(walletId))
            myAddresses.add(a.address);

        long total = 0;
        for (String s : utxos.values()) {
            UtxoRecord r = UtxoRecord.fromStorage(s);
            if (!r.spent && myAddresses.contains(r.address))
                total += r.value;
        }
        return total;
    }

    // ── Name CRUD ─────────────────────────────────────────────────────────────

    public void saveName(NameRecord name) {
        names.put(name.name, name.toStorage());
        store.commit();
    }

    public NameRecord getName(String name) {
        String s = names.get(name);
        return s != null ? NameRecord.fromStorage(name, s) : null;
    }

    public List<NameRecord> getNamesForWallet(String walletId) {
        return getNamesForWallet(walletId, 0);
    }

    public List<NameRecord> getNamesForWallet(String walletId, int currentHeight) {
        List<NameRecord> list = new ArrayList<>();
        for (Map.Entry<String, String> e : names.entrySet()) {
            NameRecord r = NameRecord.fromStorage(e.getKey(), e.getValue());
            if (!walletId.equals(r.walletId)) continue;
            if (r.state.equals("TRANSFERRING")) continue;
            // Filter expired names if we know the current height
            if (currentHeight > 0 && r.expireHeight < currentHeight) continue;
            list.add(r);
        }
        list.sort(Comparator.comparing(n -> n.name));
        return list;
    }

    // ── Meta ──────────────────────────────────────────────────────────────────

    public String getMeta(String key) { return meta.get(key); }
    public void   setMeta(String key, String value) {
        meta.put(key, value);
        store.commit();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void commit() { store.commit(); }

    @Override
    public void close() {
        if (!store.isClosed()) {
            store.commit();
            store.close();
        }
    }
}