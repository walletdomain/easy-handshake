package handshake.node.dns;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Runtime loader for the reserved TLD database.
 *
 * Loads reserved-tlds.mv.db from the JAR resources on first access,
 * copies it to a temp file (MVStore requires a real file path), and
 * opens it read-only for fast O(1) TLD lookups.
 *
 * Usage:
 *   ReservedTldList list = ReservedTldList.getInstance();
 *   ReservedTldList.Entry e = list.lookup("com");   // → flags=1, rank=0
 *   ReservedTldList.Entry e = list.lookup("google"); // → flags=0, rank=1
 *   ReservedTldList.Entry e = list.lookup("wallet"); // → null (Handshake name)
 *
 * NOTE: This database is informational only — it is NOT used for DNS
 * routing decisions. The resolver uses HNS-first logic: always check
 * the Handshake name index first, fall through to ICANN only if not found.
 */
public class ReservedTldList {

    private static final String RESOURCE_PATH = "/reserved-tlds.mv.db";

    /** Singleton instance — loaded once at startup. */
    private static volatile ReservedTldList instance;

    private final MVStore           store;
    private final MVMap<String, String> tlds;
    private final MVMap<String, String> nsMap;
    private final MVMap<String, String> glueMap;
    private final int               totalCount;
    private final int               rootCount;
    private final int               nonRootCount;

    // ── Entry record ─────────────────────────────────────────────────────────

    /**
     * A reserved TLD entry.
     *
     * @param name    the TLD name (lowercase)
     * @param flags   0 = non-root (Alexa/4yr lock), 1 = root (ICANN/permanent)
     * @param isRoot  true if this is a permanently reserved ICANN/root TLD
     */
    public record Entry(String name, int flags, boolean isRoot) {

        /** Returns true if this TLD should be forwarded to ICANN root hints. */
        public boolean forwardToIcann() { return isRoot; }

        /** Returns true if this is an Alexa Top 10K reserved name. */
        public boolean isAlexa() { return !isRoot; }

        @Override
        public String toString() {
            return "Entry{" + name + ", " + (isRoot ? "root/icann" : "alexa") + "}";
        }
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    private ReservedTldList() {
        try {
            // Extract the .mv.db resource to a temp file
            // MVStore requires a real filesystem path — can't open from stream
            InputStream is = ReservedTldList.class.getResourceAsStream(RESOURCE_PATH);
            if (is == null)
                throw new RuntimeException("Reserved TLD database not found in JAR: "
                        + RESOURCE_PATH + "\nRun IcannTldBuilder to generate it.");

            Path temp = Files.createTempFile("reserved-tlds-", ".mv.db");
            temp.toFile().deleteOnExit();
            Files.copy(is, temp, StandardCopyOption.REPLACE_EXISTING);
            is.close();

            // Open read-only
            this.store   = new MVStore.Builder()
                    .fileName(temp.toString())
                    .readOnly()
                    .open();

            this.tlds    = store.openMap("tlds");
            this.nsMap   = store.openMap("ns");
            this.glueMap = store.openMap("glue");

            MVMap<String, String> meta = store.openMap("meta");
            this.totalCount   = parseIntMeta(meta, "total_count");
            this.rootCount    = parseIntMeta(meta, "root_count");
            this.nonRootCount = parseIntMeta(meta, "non_root_count");

            System.out.println("[ReservedTldList] Loaded " + totalCount
                    + " reserved TLDs (" + rootCount + " root, "
                    + nonRootCount + " non-root)"
                    + ", NS records: " + nsMap.size()
                    + ", glue: " + glueMap.size());

        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load reserved TLD database", e);
        }
    }

    // ── Singleton access ──────────────────────────────────────────────────────

    public static ReservedTldList getInstance() {
        if (instance == null) {
            synchronized (ReservedTldList.class) {
                if (instance == null)
                    instance = new ReservedTldList();
            }
        }
        return instance;
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /**
     * Looks up a TLD in the reserved list.
     *
     * @param tld the TLD to look up (case-insensitive)
     * @return    Entry if reserved, null if not reserved (i.e. a Handshake name)
     */
    public Entry lookup(String tld) {
        if (tld == null || tld.isEmpty()) return null;
        String value = tlds.get(tld.toLowerCase());
        if (value == null) return null;
        return parseEntry(tld.toLowerCase(), value);
    }

    /**
     * Returns true if the TLD is reserved (ICANN, Alexa, or protocol-reserved).
     * Does NOT distinguish between types — use lookup() for that.
     */
    public boolean isReserved(String tld) {
        return tld != null && tlds.containsKey(tld.toLowerCase());
    }

    /**
     * Returns true if the TLD is a root/ICANN TLD that should be forwarded
     * to the ICANN root hints for resolution.
     */
    public boolean isIcann(String tld) {
        Entry e = lookup(tld);
        return e != null && e.isRoot();
    }

    /**
     * Returns NS hostnames for an ICANN TLD, or empty array if not found.
     * e.g. getNs("com") → ["a.gtld-servers.net.", "b.gtld-servers.net."]
     */
    public String[] getNs(String tld) {
        if (tld == null) return new String[0];
        String val = nsMap.get(tld.toLowerCase());
        return val != null ? val.split(",") : new String[0];
    }

    /**
     * Returns IPv4 addresses for a nameserver hostname, or empty array.
     * e.g. getGlueIps("a.gtld-servers.net.") → ["192.5.6.30", "192.26.92.30"]
     */
    public String[] getGlueIps(String hostname) {
        if (hostname == null) return new String[0];
        String val = glueMap.get(hostname.toLowerCase());
        return val != null ? val.split(",") : new String[0];
    }

    /** Returns true if NS records are available for this TLD. */
    public boolean hasNs(String tld) {
        return tld != null && nsMap.containsKey(tld.toLowerCase());
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public int getTotalCount()   { return totalCount; }
    public int getRootCount()    { return rootCount; }
    public int getNonRootCount() { return nonRootCount; }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void close() {
        if (store != null && !store.isClosed())
            store.close();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Entry parseEntry(String name, String value) {
        int flags = Integer.parseInt(value.trim());
        return new Entry(name, flags, flags == 1);
    }

    private static int parseIntMeta(MVMap<String, String> meta, String key) {
        String v = meta.get(key);
        return v != null ? Integer.parseInt(v) : 0;
    }
}