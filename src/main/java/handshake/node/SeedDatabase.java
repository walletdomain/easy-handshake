package handshake.node;

import handshake.node.Seed;
import org.h2.mvstore.MVMap;

import java.util.*;

/**
 * Persistent seed node database backed by MVStore (config.mv.db).
 *
 * Seeds are stored as "ip:port" → "key|source|label" entries.
 * Falls back to the hardcoded BUILTIN seeds if the database is empty.
 *
 * Sources:
 *   BUILTIN — shipped with the node, cannot be deleted (only disabled)
 *   CUSTOM  — added by the user via settings page or CLI
 *
 * Usage:
 *   SeedDatabase.get().getActiveSeeds()   → List<Seed> for connections
 *   SeedDatabase.get().addSeed(...)       → add custom seed
 *   SeedDatabase.get().disableSeed(ip)    → disable a seed
 *   SeedDatabase.get().removeSeed(ip)     → remove a custom seed
 */
public class SeedDatabase {

    // ── Built-in seeds ────────────────────────────────────────────────────────

    /** The hardcoded bootstrap seeds shipped with the node. */
    public static final List<SeedEntry> BUILTIN_SEEDS = List.of(
            new SeedEntry("aksygghkgmciomeldjf5sc6rs2sgn2m34zfdz4xr7z5vguqvjis4e",
                    "129.153.177.220", 44806, "BUILTIN", "", true),
            new SeedEntry("apt4rf2dfyelbivg63u47wykvdjtsl4kxzfdylkaae5s5ydldlnwu",
                    "159.69.46.23",    44806, "BUILTIN", "", true),
            new SeedEntry("aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54",
                    "172.104.214.189", 44806, "BUILTIN", "", true),
            new SeedEntry("aiwykdz37okry3pb2lzdsgbxeg72uky2zckxmiapzstpqqmb2hnge",
                    "35.154.209.88",   44806, "BUILTIN", "", true),
            new SeedEntry("ai7dgiwueiiwber6uhoeqfjdujxph6ueqpnaml36sicakngmnm3am",
                    "194.50.5.26",     44806, "BUILTIN", "", true),
            new SeedEntry("aokj73pefmtrc7ikoxqiz4nrhgrxeqnnjpv4wxekteup33duneih2",
                    "194.50.5.27",     44806, "BUILTIN", "", true),
            new SeedEntry("ajd6wzdp34c32rymlljybvbosnx75aty4rwmtpkxshvfrqufq6vuk",
                    "194.50.5.28",     44806, "BUILTIN", "", true)
    );

    // ── SeedEntry record ──────────────────────────────────────────────────────

    public record SeedEntry(
            String  key,       // brontide public key (base32)
            String  ip,
            int     port,
            String  source,    // "BUILTIN" or "CUSTOM"
            String  label,     // optional human-readable label
            boolean enabled
    ) {
        /** Converts to a Seed for use in connection logic. */
        public Seed toSeed() { return new Seed(key, ip, port); }

        /** Serializes to storage string. */
        public String toStorage() {
            return key + "|" + port + "|" + source + "|"
                    + (label != null ? label.replace("|", "") : "") + "|"
                    + enabled;
        }

        /** Deserializes from storage string. */
        public static SeedEntry fromStorage(String ip, String s) {
            try {
                String[] p = s.split("\\|", 5);
                return new SeedEntry(
                        p[0],
                        ip,
                        Integer.parseInt(p[1]),
                        p[2],
                        p.length > 3 ? p[3] : "",
                        p.length > 4 ? Boolean.parseBoolean(p[4]) : true);
            } catch (Exception e) {
                return null;
            }
        }

        public String toJson() {
            return String.format(
                    "{\"key\":\"%s\",\"ip\":\"%s\",\"port\":%d,"
                            + "\"source\":\"%s\",\"label\":\"%s\",\"enabled\":%b}",
                    key, ip, port, source,
                    label != null ? label.replace("\"", "") : "",
                    enabled);
        }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile SeedDatabase instance;

    public static SeedDatabase get() {
        if (instance == null) {
            synchronized (SeedDatabase.class) {
                if (instance == null) instance = new SeedDatabase();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    /** ip → serialized SeedEntry */
    private MVMap<String, String> store;

    /** In-memory cache for fast access */
    private final LinkedHashMap<String, SeedEntry> cache = new LinkedHashMap<>();

    private SeedDatabase() {}

    /** Wires the database to persistent storage. Call after Config is loaded. */
    public void init(org.h2.mvstore.MVStore mvStore) {
        this.store = mvStore.openMap("seeds");

        // Load existing entries into cache
        for (Map.Entry<String, String> e : store.entrySet()) {
            SeedEntry entry = SeedEntry.fromStorage(e.getKey(), e.getValue());
            if (entry != null) cache.put(e.getKey(), entry);
        }

        // Seed the database with builtins if empty
        if (cache.isEmpty()) {
            for (SeedEntry s : BUILTIN_SEEDS) {
                cache.put(s.ip(), s);
                store.put(s.ip(), s.toStorage());
            }
            mvStore.commit();
            System.out.println("[SeedDB] Initialized with "
                    + BUILTIN_SEEDS.size() + " built-in seeds.");
        } else {
            // Ensure all builtins are present (add any new ones from updates)
            boolean added = false;
            for (SeedEntry builtin : BUILTIN_SEEDS) {
                if (!cache.containsKey(builtin.ip())) {
                    cache.put(builtin.ip(), builtin);
                    store.put(builtin.ip(), builtin.toStorage());
                    added = true;
                }
            }
            if (added) mvStore.commit();
            System.out.printf("[SeedDB] Loaded %d seeds (%d enabled).%n",
                    cache.size(), getActiveSeeds().size());
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /** Returns all enabled seeds as Seed objects for connection. */
    public List<Seed> getActiveSeeds() {
        return cache.values().stream()
                .filter(SeedEntry::enabled)
                .map(SeedEntry::toSeed)
                .toList();
    }

    /** Returns all seed entries (for the settings UI). */
    public List<SeedEntry> getAllEntries() {
        return new ArrayList<>(cache.values());
    }

    /** Returns all entries as a JSON array. */
    public String toJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (SeedEntry e : cache.values()) {
            if (!first) sb.append(",");
            sb.append(e.toJson());
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    // ── Mutations ─────────────────────────────────────────────────────────────

    /**
     * Adds a custom seed. Returns false if the IP already exists.
     */
    public boolean addSeed(String key, String ip, int port, String label) {
        if (cache.containsKey(ip)) return false;
        SeedEntry entry = new SeedEntry(key, ip, port, "CUSTOM", label, true);
        cache.put(ip, entry);
        if (store != null) store.put(ip, entry.toStorage());
        EventBus.get().peer("Seed added: " + ip + ":" + port
                + (label.isEmpty() ? "" : " (" + label + ")"));
        return true;
    }

    /**
     * Enables or disables a seed. Builtin seeds can be disabled but not deleted.
     */
    public boolean setEnabled(String ip, boolean enabled) {
        SeedEntry existing = cache.get(ip);
        if (existing == null) return false;
        SeedEntry updated = new SeedEntry(existing.key(), existing.ip(),
                existing.port(), existing.source(), existing.label(), enabled);
        cache.put(ip, updated);
        if (store != null) store.put(ip, updated.toStorage());
        EventBus.get().peer("Seed " + (enabled ? "enabled" : "disabled")
                + ": " + ip);
        return true;
    }

    /**
     * Removes a custom seed. Built-in seeds cannot be removed (only disabled).
     * Returns false if not found or is a builtin.
     */
    public boolean removeSeed(String ip) {
        SeedEntry existing = cache.get(ip);
        if (existing == null) return false;
        if ("BUILTIN".equals(existing.source())) return false;
        cache.remove(ip);
        if (store != null) store.remove(ip);
        EventBus.get().peer("Seed removed: " + ip);
        return true;
    }
}