package handshake.node;

import handshake.database.Database;
import org.h2.mvstore.MVMap;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Singleton event bus for node-wide event publishing.
 *
 * Events are:
 *   1. Stored in an in-memory ring buffer (last 500 events) — served instantly on page load
 *   2. Persisted to MVStore (last 10,000 events) — survives restarts, queryable
 *   3. Streamed live to all connected SSE clients (browser live panel)
 *
 * Event categories:
 *   BLOCK   — new block found, validated, invalid
 *   DNS     — queries resolved, NXDOMAIN, upstream failures
 *   PEER    — connections, disconnections, errors
 *   NAME    — covenant processed, index updated
 *   SYSTEM  — startup, shutdown, config changes
 *   RENEWAL — TLD renewal warnings (future)
 *
 * Usage:
 *   EventBus.get().publish(EventBus.Category.BLOCK, "New block at height 330065");
 */
public class EventBus {

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int RING_BUFFER_SIZE  = 500;
    public static final int PERSIST_MAX       = 10_000;

    // ── Event categories ──────────────────────────────────────────────────────

    public enum Category {
        BLOCK, DNS, PEER, NAME, SYSTEM, RENEWAL;

        public String cssClass() {
            return switch (this) {
                case BLOCK   -> "event-block";
                case DNS     -> "event-dns";
                case PEER    -> "event-peer";
                case NAME    -> "event-name";
                case SYSTEM  -> "event-system";
                case RENEWAL -> "event-renewal";
            };
        }

        public String icon() {
            return switch (this) {
                case BLOCK   -> "⛏";
                case DNS     -> "🌐";
                case PEER    -> "🔗";
                case NAME    -> "📛";
                case SYSTEM  -> "⚙";
                case RENEWAL -> "⏰";
            };
        }
    }

    // ── Event record ──────────────────────────────────────────────────────────

    public record Event(
            long      id,
            long      timestamp,
            Category  category,
            String    message
    ) {
        /** Serializes to SSE data line format. */
        public String toSseLine() {
            return "data: " + toJson() + "\n\n";
        }

        /** Serializes to JSON. */
        public String toJson() {
            return String.format(
                    "{\"id\":%d,\"ts\":%d,\"cat\":\"%s\",\"icon\":\"%s\",\"msg\":\"%s\",\"css\":\"%s\"}",
                    id, timestamp, category.name(), category.icon(),
                    message.replace("\"", "\\\"").replace("\n", " "),
                    category.cssClass());
        }

        /** Serializes to compact string for MVStore storage. */
        public String toStorageString() {
            return timestamp + "|" + category.name() + "|" + message;
        }

        /** Deserializes from MVStore storage string. */
        public static Event fromStorageString(long id, String s) {
            int first  = s.indexOf('|');
            int second = s.indexOf('|', first + 1);
            long ts    = Long.parseLong(s.substring(0, first));
            Category cat = Category.valueOf(s.substring(first + 1, second));
            String msg = s.substring(second + 1);
            return new Event(id, ts, cat, msg);
        }
    }

    // ── SSE client ────────────────────────────────────────────────────────────

    public static class SseClient {
        private final PrintWriter writer;
        private volatile boolean  active = true;

        public SseClient(PrintWriter writer) {
            this.writer = writer;
        }

        public void send(String data) {
            if (!active) return;
            try {
                writer.print(data);
                writer.flush();
                if (writer.checkError()) active = false;
            } catch (Exception e) {
                active = false;
            }
        }

        public boolean isActive() { return active && !writer.checkError(); }
        public void close()       { active = false; }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile EventBus instance;

    public static EventBus get() {
        if (instance == null) {
            synchronized (EventBus.class) {
                if (instance == null) instance = new EventBus();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final Event[]                   ringBuffer = new Event[RING_BUFFER_SIZE];
    private volatile int                    head       = 0; // next write position
    private volatile int                    size       = 0; // current fill level
    private final AtomicLong                idCounter  = new AtomicLong(0);
    private final CopyOnWriteArrayList<SseClient> clients = new CopyOnWriteArrayList<>();

    private MVMap<Long, String> persistMap; // set when database is available
    private volatile long       persistHead = 0; // next ID to evict from persist

    private EventBus() {
        // Publish a startup event
        publishInternal(Category.SYSTEM, "easy-handshake node started");
    }

    // ── Initialization ────────────────────────────────────────────────────────

    /**
     * Wires the EventBus to the database for persistent logging.
     * Call once during node startup after the database is open.
     */
    public void init(Database db) {
        this.persistMap = db.getEventLog();

        // Load the last event ID from the persist map
        if (!persistMap.isEmpty()) {
            long lastId = persistMap.lastKey();
            idCounter.set(lastId + 1);

            // Load last RING_BUFFER_SIZE events into ring buffer for page load
            List<Long> keys = new ArrayList<>();
            long from = Math.max(0, lastId - RING_BUFFER_SIZE + 1);
            for (long k = from; k <= lastId; k++) {
                if (persistMap.containsKey(k)) keys.add(k);
            }
            for (Long key : keys) {
                String val = persistMap.get(key);
                if (val != null) addToRing(Event.fromStorageString(key, val));
            }
            System.out.println("[EventBus] Loaded " + keys.size()
                    + " events from persistent log (last id=" + lastId + ")");
        }
    }

    // ── Publishing ────────────────────────────────────────────────────────────

    /** Publishes an event to the ring buffer, persist map, and all SSE clients. */
    public void publish(Category category, String message) {
        publishInternal(category, message);
    }

    /** Convenience methods for each category. */
    public void block(String msg)   { publish(Category.BLOCK,   msg); }
    public void dns(String msg)     { publish(Category.DNS,     msg); }
    public void peer(String msg)    { publish(Category.PEER,    msg); }
    public void name(String msg)    { publish(Category.NAME,    msg); }
    public void system(String msg)  { publish(Category.SYSTEM,  msg); }
    public void renewal(String msg) { publish(Category.RENEWAL, msg); }

    private synchronized void publishInternal(Category category, String message) {
        long id = idCounter.getAndIncrement();
        Event event = new Event(id, System.currentTimeMillis(), category, message);

        // 1. Add to ring buffer
        addToRing(event);

        // 2. Persist to MVStore
        if (persistMap != null) {
            persistMap.put(id, event.toStorageString());
            // Evict old entries if over limit
            while (persistMap.size() > PERSIST_MAX && persistHead < id) {
                persistMap.remove(persistHead++);
            }
        }

        // 3. Stream to all connected SSE clients
        String sseLine = event.toSseLine();
        clients.removeIf(c -> !c.isActive());
        for (SseClient client : clients) {
            client.send(sseLine);
        }
    }

    private void addToRing(Event event) {
        ringBuffer[head] = event;
        head = (head + 1) % RING_BUFFER_SIZE;
        if (size < RING_BUFFER_SIZE) size++;
    }

    // ── SSE client management ─────────────────────────────────────────────────

    /** Registers a new SSE client and sends the current ring buffer as backfill. */
    public void addClient(SseClient client) {
        // Send ring buffer backfill (oldest first)
        List<Event> backfill = getRecentEvents(RING_BUFFER_SIZE);
        for (Event e : backfill) {
            client.send(e.toSseLine());
        }
        clients.add(client);
    }

    public void removeClient(SseClient client) {
        client.close();
        clients.remove(client);
    }

    public int getClientCount() { return clients.size(); }

    // ── Query ─────────────────────────────────────────────────────────────────

    /**
     * Returns the most recent N events from the ring buffer, oldest first.
     */
    public synchronized List<Event> getRecentEvents(int count) {
        int n = Math.min(count, size);
        List<Event> result = new ArrayList<>(n);
        int start = (head - size + RING_BUFFER_SIZE) % RING_BUFFER_SIZE;
        for (int i = 0; i < n; i++) {
            Event e = ringBuffer[(start + i) % RING_BUFFER_SIZE];
            if (e != null) result.add(e);
        }
        return result;
    }

    /**
     * Returns events from persistent log for a given category, most recent first.
     * Used by the /api/events/history endpoint.
     */
    public List<Event> getHistory(Category filter, int limit) {
        if (persistMap == null) return getRecentEvents(limit);
        List<Event> result = new ArrayList<>();
        // Iterate in reverse (most recent first)
        Long key = persistMap.lastKey();
        while (key != null && result.size() < limit) {
            String val = persistMap.get(key);
            if (val != null) {
                Event e = Event.fromStorageString(key, val);
                if (filter == null || e.category() == filter) {
                    result.add(e);
                }
            }
            key = persistMap.lowerKey(key);
        }
        return result;
    }
}