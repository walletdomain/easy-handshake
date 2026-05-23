package handshake.node;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persistent peer reliability scoring and blacklisting.
 *
 * Each peer (identified by IP) has a score based on:
 *   - Successful block deliveries   → score goes up
 *   - Connection failures/timeouts  → score goes down
 *   - Invalid blocks sent           → score drops sharply
 *   - Stale tip (far behind chain)  → score decreases slowly
 *
 * Score thresholds:
 *   >= 40  → healthy, use normally
 *   20-39  → degraded, use with lower priority
 *   10-19  → temporary backoff (exponential)
 *   < 10   → blacklisted (skip until backoff expires)
 *
 * Backoff schedule for low-scoring peers:
 *   1st blacklist: 5 minutes
 *   2nd:           30 minutes
 *   3rd:           2 hours
 *   4th+:          24 hours
 *
 * Scores persist to config.mv.db across restarts.
 * In-memory cache is kept for fast lookup during block sync.
 */
public class PeerScorecard {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final int SCORE_INITIAL          = 50;
    private static final int SCORE_MAX              = 100;
    private static final int SCORE_SUCCESS          = +3;
    private static final int SCORE_FAILURE          = -8;
    private static final int SCORE_INVALID_BLOCK    = -25;
    private static final int SCORE_STALE_TIP        = -2;
    private static final int SCORE_BACKOFF_THRESHOLD= 20;
    private static final int SCORE_BLACKLIST        = 10;

    private static final long[] BACKOFF_MS = {
            5  * 60_000L,   // 5 minutes
            30 * 60_000L,   // 30 minutes
            2  * 3600_000L, // 2 hours
            24 * 3600_000L  // 24 hours
    };

    // ── Peer record ───────────────────────────────────────────────────────────

    public static class PeerRecord {
        public final String ip;
        public int  score;
        public int  successCount;
        public int  failureCount;
        public int  invalidBlockCount;
        public int  staleTipCount;
        public int  backoffLevel;       // index into BACKOFF_MS
        public long lastFailureTime;
        public long lastSuccessTime;
        public long backoffUntil;       // epoch ms — skip peer until this time
        public String lastVersion;      // e.g. "/hsd:8.0.0/"
        public int  lastKnownHeight;

        public PeerRecord(String ip) {
            this.ip             = ip;
            this.score          = SCORE_INITIAL;
            this.lastSuccessTime= System.currentTimeMillis();
        }

        /** Returns true if this peer is currently in backoff. */
        public boolean isBackedOff() {
            return System.currentTimeMillis() < backoffUntil;
        }

        /** Returns true if this peer is effectively blacklisted (backoff level maxed). */
        public boolean isBlacklisted() {
            return score < SCORE_BLACKLIST && backoffLevel >= BACKOFF_MS.length - 1
                    && isBackedOff();
        }

        /** Returns a human-readable status string. */
        public String status() {
            if (isBlacklisted())  return "BLACKLISTED";
            if (isBackedOff())    return "BACKOFF";
            if (score >= 40)      return "HEALTHY";
            if (score >= 20)      return "DEGRADED";
            return "POOR";
        }

        /** Serializes to storage string. */
        public String toStorage() {
            return score + "," + successCount + "," + failureCount + ","
                    + invalidBlockCount + "," + staleTipCount + ","
                    + backoffLevel + "," + lastFailureTime + ","
                    + lastSuccessTime + "," + backoffUntil + ","
                    + lastKnownHeight + ","
                    + (lastVersion != null ? lastVersion.replace(",", "") : "");
        }

        /** Deserializes from storage string. */
        public static PeerRecord fromStorage(String ip, String s) {
            PeerRecord r = new PeerRecord(ip);
            try {
                String[] p = s.split(",", 11);
                r.score             = Integer.parseInt(p[0]);
                r.successCount      = Integer.parseInt(p[1]);
                r.failureCount      = Integer.parseInt(p[2]);
                r.invalidBlockCount = Integer.parseInt(p[3]);
                r.staleTipCount     = Integer.parseInt(p[4]);
                r.backoffLevel      = Integer.parseInt(p[5]);
                r.lastFailureTime   = Long.parseLong(p[6]);
                r.lastSuccessTime   = Long.parseLong(p[7]);
                r.backoffUntil      = Long.parseLong(p[8]);
                r.lastKnownHeight   = Integer.parseInt(p[9]);
                if (p.length > 10)  r.lastVersion = p[10];
            } catch (Exception ignored) {}
            return r;
        }

        @Override public String toString() {
            return String.format("%s score=%d [%s] ok=%d fail=%d inv=%d",
                    ip, score, status(), successCount, failureCount,
                    invalidBlockCount);
        }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile PeerScorecard instance;

    public static PeerScorecard get() {
        if (instance == null) {
            synchronized (PeerScorecard.class) {
                if (instance == null) instance = new PeerScorecard();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, PeerRecord> cache = new ConcurrentHashMap<>();
    private MVMap<String, String> store; // ip → serialized PeerRecord

    private PeerScorecard() {}

    /** Wires the scorecard to persistent storage. Call after Config is loaded. */
    public void init(MVStore mvStore) {
        this.store = mvStore.openMap("peerScores");
        // Load all existing records into cache
        for (Map.Entry<String, String> e : store.entrySet()) {
            PeerRecord r = PeerRecord.fromStorage(e.getKey(), e.getValue());
            cache.put(e.getKey(), r);
        }
        System.out.printf("[PeerScore] Loaded %d peer records from disk.%n",
                cache.size());
    }

    // ── Scoring ───────────────────────────────────────────────────────────────

    /** Records a successful connection/block delivery. */
    public void recordSuccess(String ip, String version, int peerHeight) {
        PeerRecord r = getOrCreate(ip);
        r.score = Math.min(SCORE_MAX, r.score + SCORE_SUCCESS);
        r.successCount++;
        r.lastSuccessTime = System.currentTimeMillis();
        r.lastVersion     = version;
        r.lastKnownHeight = peerHeight;
        // Reset backoff on consistent success
        if (r.successCount % 3 == 0 && r.backoffLevel > 0) {
            r.backoffLevel--;
        }
        persist(r);
    }

    /** Records a connection failure or timeout. */
    public void recordFailure(String ip, String reason) {
        PeerRecord r = getOrCreate(ip);
        r.score           = Math.max(0, r.score + SCORE_FAILURE);
        r.failureCount++;
        r.lastFailureTime = System.currentTimeMillis();

        if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(r);
        }
        persist(r);

        if (r.score < SCORE_BLACKLIST) {
            System.out.printf("[PeerScore] ⚠ %s blacklisted (score=%d, "
                            + "backoff=%s): %s%n",
                    ip, r.score, formatDuration(r.backoffUntil
                            - System.currentTimeMillis()), reason);
            EventBus.get().peer("Peer " + ip + " blacklisted — score " + r.score
                    + " (" + reason + ")");
        }

        persist(r);
    }

    /** Records that a peer sent an invalid block. */
    public void recordInvalidBlock(String ip) {
        PeerRecord r = getOrCreate(ip);
        r.score             = Math.max(0, r.score + SCORE_INVALID_BLOCK);
        r.invalidBlockCount++;
        r.lastFailureTime   = System.currentTimeMillis();
        applyBackoff(r);
        persist(r);

        System.out.printf("[PeerScore] ⛔ %s penalized for invalid block "
                + "(score=%d)%n", ip, r.score);
        EventBus.get().peer("Peer " + ip + " sent invalid block — score "
                + r.score);
    }

    /** Records that a peer's tip is far behind ours (stale peer). */
    public void recordStaleTip(String ip, int peerHeight, int ourHeight) {
        PeerRecord r = getOrCreate(ip);
        r.score        = Math.max(0, r.score + SCORE_STALE_TIP);
        r.staleTipCount++;
        r.lastKnownHeight = peerHeight;
        persist(r);
    }

    // ── Querying ──────────────────────────────────────────────────────────────

    /**
     * Returns true if this peer should be skipped (backed off or blacklisted).
     */
    public boolean shouldSkip(String ip) {
        PeerRecord r = cache.get(ip);
        if (r == null) return false; // unknown peer — give it a chance
        return r.isBackedOff();
    }

    /**
     * Returns true if peer is healthy enough to use.
     */
    public boolean isHealthy(String ip) {
        PeerRecord r = cache.get(ip);
        if (r == null) return true;
        return !r.isBackedOff() && r.score >= SCORE_BACKOFF_THRESHOLD;
    }

    /**
     * Sorts a list of peer IPs by score, best first.
     * Backed-off peers are moved to the end.
     */
    public List<String> sortByScore(List<String> ips) {
        List<String> sorted = new ArrayList<>(ips);
        sorted.sort((a, b) -> {
            PeerRecord ra = cache.getOrDefault(a, new PeerRecord(a));
            PeerRecord rb = cache.getOrDefault(b, new PeerRecord(b));
            // Backed-off peers go last
            boolean backA = ra.isBackedOff();
            boolean backB = rb.isBackedOff();
            if (backA != backB) return backA ? 1 : -1;
            // Higher score first
            return Integer.compare(rb.score, ra.score);
        });
        return sorted;
    }

    /** Returns all peer records sorted by score descending. */
    public List<PeerRecord> getAllRecords() {
        List<PeerRecord> list = new ArrayList<>(cache.values());
        list.sort((a, b) -> Integer.compare(b.score, a.score));
        return list;
    }

    /** Returns the record for a specific peer, or null if unknown. */
    public PeerRecord getRecord(String ip) {
        return cache.get(ip);
    }

    /** Returns a JSON array of all peer scores for the /api/peers endpoint. */
    public String toJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (PeerRecord r : getAllRecords()) {
            if (!first) sb.append(",");
            sb.append(String.format(
                    "{\"ip\":\"%s\",\"score\":%d,\"status\":\"%s\","
                            + "\"ok\":%d,\"fail\":%d,\"inv\":%d,\"height\":%d,"
                            + "\"version\":\"%s\",\"backoff\":%b}",
                    r.ip, r.score, r.status(),
                    r.successCount, r.failureCount, r.invalidBlockCount,
                    r.lastKnownHeight,
                    r.lastVersion != null ? r.lastVersion : "",
                    r.isBackedOff()));
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Resets a single peer's backoff — lets us retry immediately.
     * Does not change the score, just clears the backoff timer.
     */
    public void resetBackoff(String ip) {
        PeerRecord r = getOrCreate(ip);
        r.backoffUntil = 0;
        r.backoffLevel = 0;
        r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD); // give it a chance
        persist(r);
        System.out.printf("[PeerScore] Reset backoff for %s%n", ip);
    }

    /** Resets backoffs for ALL backed-off peers so we retry them. */
    public void resetAllBackoffs() {
        for (PeerRecord r : getAllRecords()) {
            if (r.isBackedOff() || r.isBlacklisted()) {
                r.backoffUntil = 0;
                r.backoffLevel = 0;
                r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD);
                persist(r);
            }
        }
        System.out.println("[PeerScore] All peer backoffs reset");
    }

    /**
     * Applies time-based score decay/recovery.
     * Called periodically — peers slowly recover score over time
     * so transient failures don't permanently exclude good peers.
     * +1 per 10 minutes for peers with score < 50.
     */
    public void applyDecay() {
        long now = System.currentTimeMillis();
        for (PeerRecord r : getAllRecords()) {
            if (r.score < SCORE_INITIAL && r.lastFailureTime > 0) {
                long minutesSinceFailure = (now - r.lastFailureTime) / 60_000;
                int recovery = (int)(minutesSinceFailure / 10); // +1 per 10 min
                if (recovery > 0) {
                    r.score = Math.min(SCORE_INITIAL, r.score + recovery);
                    // If score recovered above blacklist threshold, clear backoff
                    if (r.score >= SCORE_BACKOFF_THRESHOLD && r.isBackedOff()
                            && r.backoffLevel > 0) {
                        r.backoffLevel = Math.max(0, r.backoffLevel - 1);
                    }
                    persist(r);
                }
            }
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private PeerRecord getOrCreate(String ip) {
        return cache.computeIfAbsent(ip, PeerRecord::new);
    }

    private void applyBackoff(PeerRecord r) {
        int level = Math.min(r.backoffLevel, BACKOFF_MS.length - 1);
        r.backoffUntil = System.currentTimeMillis() + BACKOFF_MS[level];
        r.backoffLevel = Math.min(r.backoffLevel + 1, BACKOFF_MS.length - 1);
    }

    private void persist(PeerRecord r) {
        if (store != null)
            store.put(r.ip, r.toStorage());
    }

    private static String formatDuration(long ms) {
        if (ms <= 0) return "expired";
        long s = ms / 1000;
        if (s < 60)   return s + "s";
        if (s < 3600) return (s / 60) + "m";
        return (s / 3600) + "h";
    }
}