package handshake.node.dns;

import handshake.database.Database;
import handshake.node.HNSBlock;
import org.h2.mvstore.MVMap;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Builds and maintains a name→DNS records index from Handshake covenant history.
 *
 * Uses MVStore maps from the chain database for persistence and memory efficiency.
 * The index survives node restarts without needing to rescan the blockchain.
 *
 * Covenant item structure (from handshake-types):
 *   OPEN     items: [nameHash(32), height(4), name(var)]
 *   REGISTER items: [nameHash(32), height(4), recordData(var)]
 *   UPDATE   items: [nameHash(32), height(4), recordData(var)]
 *   FINALIZE items: [nameHash(32), height(4), name(var), ...]
 *   REVOKE   items: [nameHash(32), height(4)]
 *
 * The name string is NOT in REGISTER/UPDATE — only in OPEN and FINALIZE.
 * We build a nameHash→name map from OPEN/FINALIZE covenants first,
 * then use it to resolve names for REGISTER/UPDATE records.
 */
public class NameIndex {

    private static final String META_BUILT_HEIGHT = "nameIndex_height";

    private final Database              db;
    private final MVMap<String, byte[]> index;      // name → resource bytes
    private final MVMap<String, String> hashToName; // hashHex → name

    private volatile boolean ready = false;

    public NameIndex(Database db) {
        this.db         = db;
        this.index      = db.getNameIndex();
        this.hashToName = db.getNameHashes();
    }

    // ── Progress tracking ─────────────────────────────────────────────────────

    private volatile int  buildTip      = 0;   // total blocks to scan
    private volatile int  buildProgress = 0;   // blocks scanned so far
    private volatile long buildStart    = 0;   // System.currentTimeMillis()

    /** Returns 0.0–1.0 build progress, or 1.0 if ready. */
    public double getBuildProgressFraction() {
        if (ready) return 1.0;
        if (buildTip == 0) return 0.0;
        return (double) buildProgress / buildTip;
    }

    public int  getBuildTip()      { return buildTip; }
    public int  getBuildProgress() { return buildProgress; }
    public long getBuildStart()    { return buildStart; }

    /** Estimated seconds remaining, or -1 if unknown. */
    public long getEtaSeconds() {
        if (ready || buildTip == 0 || buildProgress == 0 || buildStart == 0)
            return -1;
        double elapsed  = (System.currentTimeMillis() - buildStart) / 1000.0;
        double rate     = buildProgress / elapsed; // blocks per second
        int    remaining = buildTip - buildProgress;
        return rate > 0 ? (long)(remaining / rate) : -1;
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    public void build() {
        int tip = db.getBlockDataTip();

        // Check if index was already built
        byte[] builtHeightBytes = db.getMeta(META_BUILT_HEIGHT);
        if (builtHeightBytes != null && !index.isEmpty()) {
            int builtHeight = ((builtHeightBytes[0]&0xFF)<<24)
                    | ((builtHeightBytes[1]&0xFF)<<16)
                    | ((builtHeightBytes[2]&0xFF)<<8)
                    |  (builtHeightBytes[3]&0xFF);

            if (builtHeight >= tip) {
                // Fully current — just load
                ready = true;
                System.out.printf("[NameIndex] Loaded from disk. %,d names indexed "
                        + "(built at height %d).%n", index.size(), builtHeight);
                handshake.node.EventBus.get().name(
                        "Name index loaded — " + String.format("%,d", index.size())
                                + " names (built at block " + builtHeight + ")");
                return;
            }

            int gap = tip - builtHeight;
            if (gap <= 1000) {
                // Small gap — catch up by applying missing blocks directly
                System.out.printf("[NameIndex] Catching up %d blocks (%d → %d)...%n",
                        gap, builtHeight, tip);
                ready = true; // mark ready so applyBlock() works
                for (int h = builtHeight + 1; h <= tip; h++) {
                    byte[] raw = db.getRawBlock(h);
                    if (raw == null) continue;
                    HNSBlock block = HNSBlock.parse(raw);
                    for (HNSBlock.Tx tx : block.txs)
                        for (HNSBlock.Output output : tx.outputs)
                            processOutput(output);
                }
                // Save the new built height
                byte[] tipBytes = {(byte)(tip>>24),(byte)(tip>>16),(byte)(tip>>8),(byte)tip};
                db.putMeta(META_BUILT_HEIGHT, tipBytes);
                db.commitNameIndex();
                System.out.printf("[NameIndex] Caught up. %,d names indexed.%n", index.size());
                handshake.node.EventBus.get().name(
                        "Name index ready — " + String.format("%,d", index.size())
                                + " Handshake names indexed");
                return;
            }

            // Large gap — need full rescan
            System.out.printf("[NameIndex] Gap too large (%d blocks) — rebuilding...%n", gap);
        }

        System.out.println("[NameIndex] Building from " + (tip + 1) + " blocks...");
        buildTip   = tip;
        buildStart = System.currentTimeMillis();

        handshake.node.EventBus.get().name(
                "Name index build started — scanning " + String.format("%,d", tip + 1) + " blocks");

        for (int h = 0; h <= tip; h++) {
            buildProgress = h;
            byte[] raw = db.getRawBlock(h);
            if (raw == null) continue;

            HNSBlock block = HNSBlock.parse(raw);
            for (HNSBlock.Tx tx : block.txs)
                for (HNSBlock.Output output : tx.outputs)
                    processOutput(output);

            if (h > 0 && h % 10_000 == 0) {
                System.out.printf("[NameIndex] Scanned %,d / %,d blocks, "
                        + "%,d names indexed%n", h, tip, index.size());
                db.commitNameIndex();
                // Publish progress event every 10,000 blocks
                int pct = (int)(100.0 * h / tip);
                long eta = getEtaSeconds();
                String etaStr = eta > 0
                        ? " · ETA " + formatEta(eta)
                        : "";
                handshake.node.EventBus.get().name(
                        "Name index " + pct + "% — "
                                + String.format("%,d", index.size())
                                + " names indexed" + etaStr);
            }
        }

        buildProgress = tip;
        byte[] tipBytes = {(byte)(tip>>24),(byte)(tip>>16),(byte)(tip>>8),(byte)tip};
        db.putMeta(META_BUILT_HEIGHT, tipBytes);
        db.commitNameIndex();
        ready = true;

        long elapsed = System.currentTimeMillis() - buildStart;
        System.out.printf("[NameIndex] Build complete. %,d names indexed "
                + "in %.1fs%n", index.size(), elapsed / 1000.0);
        handshake.node.EventBus.get().name(
                "Name index ready — " + String.format("%,d", index.size())
                        + " Handshake names indexed");
    }

    private static String formatEta(long seconds) {
        if (seconds >= 3600)
            return (seconds / 3600) + "h " + ((seconds % 3600) / 60) + "m";
        if (seconds >= 60)
            return (seconds / 60) + "m " + (seconds % 60) + "s";
        return seconds + "s";
    }

    public void applyBlock(HNSBlock block) {
        if (!ready) return; // don't apply new blocks during initial build scan
        for (HNSBlock.Tx tx : block.txs)
            for (HNSBlock.Output output : tx.outputs)
                processOutput(output);
        int tip = db.getBlockDataTip();
        byte[] tipBytes = {(byte)(tip>>24),(byte)(tip>>16),(byte)(tip>>8),(byte)tip};
        db.putMeta(META_BUILT_HEIGHT, tipBytes);
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    public byte[] lookup(String name) {
        if (name == null || name.isEmpty()) return null;
        return index.get(name.toLowerCase());
    }

    public boolean contains(String name) {
        return name != null && index.containsKey(name.toLowerCase());
    }

    public boolean isReady()         { return ready; }
    public int     size()            { return index.size(); }
    public int     getIndexedCount() { return index.size(); }

    // ── Internal processing ───────────────────────────────────────────────────

    private void processOutput(HNSBlock.Output output) {
        if (output.covenant == null) return;
        List<byte[]> items = output.covenant.items;
        if (items.isEmpty()) return;

        switch (output.covenant.type) {

            case HNSBlock.Covenant.OPEN -> {
                if (items.size() < 3) return;
                String hashHex = bytesToHex(items.get(0));
                String name    = new String(items.get(2), StandardCharsets.UTF_8)
                        .toLowerCase().trim();
                if (!name.isEmpty()) hashToName.put(hashHex, name);
            }

            case HNSBlock.Covenant.FINALIZE -> {
                if (items.size() < 3) return;
                String hashHex = bytesToHex(items.get(0));
                String name    = new String(items.get(2), StandardCharsets.UTF_8)
                        .toLowerCase().trim();
                if (!name.isEmpty()) hashToName.put(hashHex, name);
            }

            case HNSBlock.Covenant.REGISTER,
                 HNSBlock.Covenant.UPDATE -> {
                if (items.size() < 3) return;
                String hashHex  = bytesToHex(items.get(0));
                byte[] resource = items.get(2);
                if (resource == null || resource.length == 0) return;
                String name = hashToName.get(hashHex);
                if (name == null) return;
                if (isValidName(name)) index.put(name, resource);
            }

            case HNSBlock.Covenant.REVOKE -> {
                if (items.isEmpty()) return;
                String name = hashToName.get(bytesToHex(items.get(0)));
                if (name != null) index.remove(name);
            }
        }
    }

    private static boolean isValidName(String name) {
        if (name == null || name.isEmpty() || name.length() > 63) return false;
        if (name.startsWith("-") || name.endsWith("-")) return false;
        for (char c : name.toCharArray()) {
            if (Character.isISOControl(c)) return false;
            if (c == '.' || c == '@' || c == ' ') return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}