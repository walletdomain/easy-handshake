package handshake.wallet;

import handshake.database.Database;
import handshake.node.EventBus;
import handshake.node.HNSBlock;
import handshake.node.HNSPeer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Scans the blockchain for UTXOs and name covenants belonging to wallet addresses.
 *
 * Strategy:
 *   1. Build a HashMap of all known wallet addresses for O(1) lookup
 *   2. Scan blocks sequentially from last scanned height
 *   3. For each output: check if addrHash matches a wallet address
 *   4. For each input: check if it spends one of our UTXOs
 *   5. Apply gap limit (20) — extend address lookahead when matches found
 *   6. Persist results to WalletDB
 */
public class WalletScanner {

    private static final int GAP_LIMIT            = 20;
    private static final int BLOCKS_PER_COMMIT    = 1000;
    private static final int HNS_EXPIRY_BLOCKS    = 105_120; // ~2 years

    // Covenant types
    private static final int COV_REGISTER = 6;
    private static final int COV_UPDATE   = 7;
    private static final int COV_RENEW    = 8;
    private static final int COV_TRANSFER = 9;
    private static final int COV_FINALIZE = 10;

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile WalletScanner instance;

    public static WalletScanner get() {
        if (instance == null) {
            synchronized (WalletScanner.class) {
                if (instance == null) instance = new WalletScanner();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private Database      chainDb;
    private WalletDB      walletDb;
    private WalletManager walletManager;
    private volatile boolean scanning = false;
    private final AtomicInteger scanProgress = new AtomicInteger(0);
    private final AtomicInteger scanTotal    = new AtomicInteger(0);
    private volatile long scanStart = 0;

    private WalletScanner() {}

    public void init(Database chainDb, WalletDB walletDb,
                     WalletManager walletManager) {
        this.chainDb       = chainDb;
        this.walletDb      = walletDb;
        this.walletManager = walletManager;
    }

    // ── Full scan ─────────────────────────────────────────────────────────────

    public void startScan() {
        if (scanning) return;
        if (walletDb == null || walletDb.getAllWallets().isEmpty()) return;
        Thread t = new Thread(this::runScan, "wallet-scanner");
        t.setDaemon(true);
        t.start();
    }

    private void runScan() {
        scanning  = true;
        scanStart = System.currentTimeMillis();
        try {
            int startHeight = getLastScannedHeight() + 1;
            int tipHeight   = chainDb.getBlockDataTip();
            scanTotal.set(tipHeight);

            System.out.printf("[WalletScanner] Scanning blocks %d–%d%n",
                    startHeight, tipHeight);
            EventBus.get().system("Wallet scan started — blocks "
                    + startHeight + " to " + tipHeight);

            Map<String, String> addrMap  = buildAddressMap();
            Map<String, String> utxoMap  = buildUtxoMap();
            int lastCommit = startHeight;

            for (int h = startHeight; h <= tipHeight; h++) {
                scanProgress.set(h);
                byte[] raw = chainDb.getRawBlock(h);
                if (raw == null) continue;
                processBlock(HNSBlock.parse(raw), h, addrMap, utxoMap);

                if (h - lastCommit >= BLOCKS_PER_COMMIT) {
                    walletDb.commitUtxos();
                    saveLastScannedHeight(h);
                    lastCommit = h;
                    int pct = (int)(100.0 * h / tipHeight);
                    long elapsed = (System.currentTimeMillis() - scanStart) / 1000;
                    long eta = elapsed > 0
                            ? (long)((tipHeight - h) / ((double)h / elapsed))
                            : -1;
                    System.out.printf("[WalletScanner] %d%% (%d/%d)%s%n",
                            pct, h, tipHeight,
                            eta > 0 ? " ETA " + fmtEta(eta) : "");
                    EventBus.get().system("Wallet scan " + pct + "% — block "
                            + String.format("%,d", h));
                }
            }

            walletDb.commitUtxos();
            saveLastScannedHeight(tipHeight);
            reportBalances();

            long elapsed = (System.currentTimeMillis() - scanStart) / 1000;
            System.out.printf("[WalletScanner] Scan complete in %s.%n",
                    fmtEta(elapsed));
            EventBus.get().system("Wallet scan complete in " + fmtEta(elapsed));

        } catch (Exception e) {
            System.out.println("[WalletScanner] Error: " + e.getMessage());
            e.printStackTrace();
            EventBus.get().system("Wallet scan error: " + e.getMessage());
        } finally {
            scanning = false;
        }
    }

    // ── Block processing ──────────────────────────────────────────────────────

    public void processBlock(HNSBlock block, int height,
                             Map<String, String> addrMap,
                             Map<String, String> utxoMap) {
        for (HNSBlock.Tx tx : block.txs) {
            // Compute txid: blake2b-256 of base tx (no witnesses)
            byte[] base   = Arrays.copyOf(tx.raw, tx.baseSize);
            String txHash = hex(HNSPeer.Blake2b.hash(base, 32));

            // Check inputs — mark spent UTXOs
            for (HNSBlock.Input input : tx.inputs) {
                if (input.isCoinbase()) continue;
                String key = hex(input.prevHash) + ":" + input.prevIndex;
                if (utxoMap.containsKey(key)) {
                    WalletDB.UtxoRecord u = walletDb.getUtxo(
                            hex(input.prevHash), (int)input.prevIndex);
                    if (u != null && !u.spent) {
                        u.spent = true;
                        walletDb.saveUtxo(u);
                        utxoMap.remove(key);
                    }
                }
            }

            // Check outputs — find payments to our addresses
            for (int i = 0; i < tx.outputs.size(); i++) {
                HNSBlock.Output out = tx.outputs.get(i);
                String addr = toAddress(out);
                if (addr == null) continue;

                String walletId = addrMap.get(addr);
                if (walletId == null) continue;

                // Record UTXO
                WalletDB.UtxoRecord u = new WalletDB.UtxoRecord();
                u.txHash      = txHash;
                u.outputIndex = i;
                u.address     = addr;
                u.value       = out.value;
                u.height      = height;
                u.spent       = false;
                u.coinbase    = tx.inputs.size() == 1
                        && tx.inputs.get(0).isCoinbase();
                walletDb.saveUtxo(u);
                utxoMap.put(txHash + ":" + i, walletId);

                // Mark address used and extend lookahead
                markUsed(walletId, addr, out.value);
                extendLookahead(walletId, addr, addrMap);

                // Check for name covenants
                processName(out, addr, walletId, height, txHash);
            }
        }
    }

    /** Called by ChainFollower for each new block after initial scan. */
    public void applyNewBlock(HNSBlock block, int height) {
        if (walletDb == null || walletDb.getAllWallets().isEmpty()) return;
        Map<String, String> addrMap = buildAddressMap();
        Map<String, String> utxoMap = buildUtxoMap();
        processBlock(block, height, addrMap, utxoMap);
        walletDb.commitUtxos();
        saveLastScannedHeight(height);
    }

    // ── Address / UTXO maps ───────────────────────────────────────────────────

    public Map<String, String> buildAddressMap() {
        Map<String, String> map = new HashMap<>();
        for (WalletDB.WalletRecord w : walletDb.getAllWallets())
            for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(w.id))
                map.put(a.address, w.id);
        return map;
    }

    private Map<String, String> buildUtxoMap() {
        Map<String, String> map = new HashMap<>();
        for (WalletDB.WalletRecord w : walletDb.getAllWallets())
            for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(w.id))
                for (WalletDB.UtxoRecord u : walletDb.getUtxosForAddress(a.address))
                    if (!u.spent) map.put(u.txHash + ":" + u.outputIndex, w.id);
        return map;
    }

    // ── Output → address ─────────────────────────────────────────────────────

    private String toAddress(HNSBlock.Output out) {
        if (out.addrHash == null || out.addrHash.length != 20) return null;
        if (out.addrVersion != 0) return null;
        return HNSAddress.encode("hs", 0, out.addrHash);
    }

    // ── Gap limit ─────────────────────────────────────────────────────────────

    private void extendLookahead(String walletId, String usedAddress,
                                 Map<String, String> addrMap) {
        WalletDB.AddressRecord used = null;
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId))
            if (a.address.equals(usedAddress)) { used = a; break; }
        if (used == null) return;

        int maxIdx = 0;
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId))
            if (a.change == used.change) maxIdx = Math.max(maxIdx, a.index);

        if (maxIdx - used.index < GAP_LIMIT && walletManager != null
                && walletManager.isUnlocked(walletId)) {
            int from  = maxIdx + 1;
            walletManager.deriveMoreAddresses(walletId, used.account,
                    used.change, from, GAP_LIMIT);
            for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId))
                if (a.index >= from) addrMap.put(a.address, walletId);
        }
    }

    private void markUsed(String walletId, String address, long value) {
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId)) {
            if (a.address.equals(address) && !a.used) {
                a.used    = true;
                a.balance += value;
                walletDb.saveAddress(a);
                break;
            }
        }
    }

    // ── Name covenant processing ──────────────────────────────────────────────

    private void processName(HNSBlock.Output out, String addr,
                             String walletId, int height, String txHash) {
        if (out.covenant == null) return;
        int type = out.covenant.type;
        if (type != COV_REGISTER && type != COV_UPDATE &&
                type != COV_RENEW    && type != COV_TRANSFER &&
                type != COV_FINALIZE) return;
        if (out.covenant.items == null || out.covenant.items.isEmpty()) return;

        String name = null;
        try {
            byte[] nameBytes = out.covenant.items.get(0);
            name = new String(nameBytes, java.nio.charset.StandardCharsets.UTF_8)
                    .replaceAll("[^a-z0-9\\-]", "");
        } catch (Exception ignored) {}
        if (name == null || name.isEmpty()) return;

        WalletDB.NameRecord rec = walletDb.getName(name);
        if (rec == null) rec = new WalletDB.NameRecord();
        rec.name         = name;
        rec.walletId     = walletId;
        rec.ownerAddress = addr;
        rec.height       = height;
        rec.expireHeight = height + HNS_EXPIRY_BLOCKS;
        rec.lastRenewed  = System.currentTimeMillis();
        rec.state        = switch (type) {
            case COV_REGISTER -> "REGISTERED";
            case COV_UPDATE   -> "UPDATED";
            case COV_RENEW    -> "RENEWED";
            case COV_TRANSFER -> "TRANSFER";
            case COV_FINALIZE -> "CLOSED";
            default           -> "UNKNOWN";
        };
        walletDb.saveName(rec);
        EventBus.get().name("Name found in wallet: ." + name + " → "
                + addr.substring(0, 12) + "...");
    }

    // ── Progress ──────────────────────────────────────────────────────────────

    public boolean isScanning()    { return scanning; }
    public int getScanProgress()   { return scanProgress.get(); }
    public int getScanTotal()      { return scanTotal.get(); }
    public long getScanStartTime() { return scanStart; }

    public int getScanPct() {
        int total = scanTotal.get();
        return total > 0 ? (int)(100.0 * scanProgress.get() / total) : 0;
    }

    public long getEtaSeconds() {
        if (!scanning || scanProgress.get() == 0 || scanStart == 0) return -1;
        double elapsed = (System.currentTimeMillis() - scanStart) / 1000.0;
        double rate    = scanProgress.get() / elapsed;
        int    remain  = scanTotal.get() - scanProgress.get();
        return rate > 0 ? (long)(remain / rate) : -1;
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private int getLastScannedHeight() {
        String v = walletDb.getMeta("scan.lastHeight");
        try { return v != null ? Integer.parseInt(v) : -1; }
        catch (Exception e) { return -1; }
    }

    private void saveLastScannedHeight(int h) {
        walletDb.setMeta("scan.lastHeight", String.valueOf(h));
    }

    private void reportBalances() {
        for (WalletDB.WalletRecord w : walletDb.getAllWallets()) {
            long bal   = walletDb.getBalanceForWallet(w.id);
            int  names = walletDb.getNamesForWallet(w.id).size();
            System.out.printf("[WalletScanner] '%s': %s HNS, %d name(s)%n",
                    w.name, fmtHns(bal), names);
            EventBus.get().system("Wallet '" + w.name + "': "
                    + fmtHns(bal) + " HNS, " + names + " name(s)");
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String hex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String fmtHns(long satoshis) {
        return String.format("%.6f", satoshis / 1_000_000.0);
    }

    private static String fmtEta(long s) {
        if (s >= 3600) return (s / 3600) + "h " + ((s % 3600) / 60) + "m";
        if (s >= 60)   return (s / 60) + "m " + (s % 60) + "s";
        return s + "s";
    }
}