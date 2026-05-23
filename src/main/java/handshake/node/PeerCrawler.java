package handshake.node;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Crawls the Handshake P2P network to discover peers.
 *
 * Strategy:
 *   1. At startup, connect to our known seeds via brontide
 *   2. Send GETADDR to each seed
 *   3. Parse ADDR responses to get new peer IPs
 *   4. For each new IP, attempt both brontide (port 44806) and cleartext (port 12038)
 *   5. Register discovered peers in PeerDiscovery
 *   6. Re-crawl periodically (every 30 minutes)
 *
 * This expands our peer pool from ~3 seeds to dozens of peers,
 * significantly improving transaction propagation.
 */
public class PeerCrawler {

    private static final int    CRAWL_THREADS       = 20;
    private static final int    CONNECT_TIMEOUT_MS  = 4_000;
    private static final long   CRAWL_INTERVAL_MS   = 30 * 60_000L; // 30 min
    private static final int    MAX_PEERS_PER_SEED  = 1000;

    private static volatile PeerCrawler instance;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "peer-crawler");
                t.setDaemon(true);
                return t;
            });

    public static PeerCrawler get() {
        if (instance == null) {
            synchronized (PeerCrawler.class) {
                if (instance == null) instance = new PeerCrawler();
            }
        }
        return instance;
    }

    /** Starts the crawler — runs immediately then every 30 minutes. */
    public void start() {
        if (running.getAndSet(true)) return;
        System.out.println("[PeerCrawler] Starting peer discovery crawler...");
        scheduler.scheduleAtFixedRate(this::crawl, 0, CRAWL_INTERVAL_MS,
                TimeUnit.MILLISECONDS);
    }

    /** Runs a single crawl cycle. */
    void crawl() {
        try {
            System.out.println("[PeerCrawler] Crawling for peers...");
            Set<String> newIps = new ConcurrentHashSet<>();

            // Step 1: Ask all known seeds for their peer lists
            List<Seed> seeds = PeerDiscovery.get().getAllPeers();
            System.out.printf("[PeerCrawler] Querying %d seeds for peers%n", seeds.size());

            ExecutorService exec = Executors.newFixedThreadPool(
                    Math.min(seeds.size(), CRAWL_THREADS));
            List<Future<List<String>>> futures = new ArrayList<>();

            for (Seed seed : seeds) {
                futures.add(exec.submit(() -> getAddrFromSeed(seed)));
            }
            exec.shutdown();
            exec.awaitTermination(CONNECT_TIMEOUT_MS * 3L, TimeUnit.MILLISECONDS);

            for (Future<List<String>> f : futures) {
                try {
                    List<String> ips = f.get();
                    if (ips != null) newIps.addAll(ips);
                } catch (Exception ignored) {}
            }

            System.out.printf("[PeerCrawler] Discovered %d candidate IPs%n", newIps.size());

            // Step 2: Try connecting to each new IP
            int added = 0;
            ExecutorService probeExec = Executors.newFixedThreadPool(
                    Math.min(newIps.size() + 1, CRAWL_THREADS));
            List<Future<String>> probeFutures = new ArrayList<>();

            for (String ip : newIps) {
                probeFutures.add(probeExec.submit(() -> probeIp(ip)));
            }
            probeExec.shutdown();
            probeExec.awaitTermination(CONNECT_TIMEOUT_MS * 2L, TimeUnit.MILLISECONDS);

            for (Future<String> f : probeFutures) {
                try {
                    String result = f.get();
                    if (result != null) added++;
                } catch (Exception ignored) {}
            }

            System.out.printf("[PeerCrawler] Added %d new peers (total known: %d)%n",
                    added, PeerDiscovery.get().getAllPeers().size());

        } catch (Exception e) {
            System.out.printf("[PeerCrawler] Crawl error: %s%n", e.getMessage());
        }
    }

    /**
     * Connects to a seed, sends GETADDR, parses the ADDR response.
     * Tries brontide first, falls back to cleartext.
     * Returns list of IP addresses discovered.
     */
    private List<String> getAddrFromSeed(Seed seed) {
        // Try brontide first if we have a key
        if (seed.key() != null && !seed.key().isEmpty()) {
            List<String> ips = getAddrViaBrontide(seed);
            if (ips != null) return ips;
        }
        // Fall back to cleartext
        return getAddrViaCleartext(seed.ipAddress());
    }

    private List<String> getAddrViaBrontide(Seed seed) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(seed.ipAddress(), seed.port()),
                    CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);

            byte[] remoteStaticPub = HNSPeerManager.base32Decode(seed.key());
            if (remoteStaticPub.length != 33) { socket.close(); return null; }

            byte[] localStaticPriv = new byte[32];
            new java.util.Random().nextBytes(localStaticPriv);

            BrontideState state = new BrontideState(localStaticPriv, remoteStaticPub);
            state.init();

            var in  = socket.getInputStream();
            var out = socket.getOutputStream();

            byte[] actOne = state.genActOne();
            out.write(actOne); out.flush();
            byte[] actTwo = in.readNBytes(BrontideState.ACT_TWO_SIZE);
            if (actTwo.length != BrontideState.ACT_TWO_SIZE || !state.recvActTwo(actTwo)) {
                socket.close(); return null;
            }
            byte[] actThree = state.genActThree();
            out.write(actThree); out.flush();

            Peer peer = new Peer(seed, 0, socket, state);
            HNSPeer hnsPeer = new HNSPeer(peer, state);
            hnsPeer.handshake();

            // Send GETADDR
            hnsPeer.send(HNSMessage.TYPE_GETADDR, new byte[0]);

            // Wait for ADDR response
            socket.setSoTimeout(8_000);
            List<String> ips = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                HNSMessage.Message msg = hnsPeer.readMessage();
                if (msg.type == HNSMessage.TYPE_ADDR) {
                    List<String[]> peers = HNSMessage.parseAddr(msg.payload);
                    for (String[] p : peers) ips.add(p[0]);
                    if (!ips.isEmpty()) break;
                }
            }
            socket.close();
            return ips;
        } catch (Exception e) {
            return null;
        }
    }

    private List<String> getAddrViaCleartext(String ip) {
        try {
            Socket socket = new Socket();
            socket.connect(
                    new InetSocketAddress(ip, HNSCleartextPeer.CLEARTEXT_PORT),
                    CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);

            Seed seed = new Seed("", ip, HNSCleartextPeer.CLEARTEXT_PORT);
            HNSCleartextPeer peer = new HNSCleartextPeer(seed, socket);
            peer.handshake();

            // Send GETADDR
            peer.send(HNSMessage.TYPE_GETADDR, new byte[0]);

            // Wait for ADDR
            socket.setSoTimeout(8_000);
            List<String> ips = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                HNSCleartextPeer.Message msg = peer.readMessage();
                if (msg.type == HNSMessage.TYPE_ADDR) {
                    List<String[]> peers = HNSMessage.parseAddr(msg.payload);
                    for (String[] p : peers) ips.add(p[0]);
                    if (!ips.isEmpty()) break;
                }
            }
            peer.close();
            return ips;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Probes an IP on port 12038. Completes full VERSION handshake to capture
     * agent string and block height. Registers peer in PeerDiscovery if reachable.
     */
    private String probeIp(String ip) {
        if (PeerScorecard.get().shouldSkip(ip)) return null;

        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, HNSCleartextPeer.CLEARTEXT_PORT),
                    CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);

            Seed seed = new Seed("", ip, HNSCleartextPeer.CLEARTEXT_PORT);
            HNSCleartextPeer peer = new HNSCleartextPeer(seed, socket);

            // Send our VERSION
            peer.sendVersion(0);

            // Read until we get VERSION from them
            String agent = "";
            int height = 0;
            for (int i = 0; i < 5; i++) {
                HNSCleartextPeer.Message msg = peer.readMessage();
                if (msg.type == HNSMessage.TYPE_VERSION) {
                    HNSMessage.VersionInfo vi = HNSMessage.parseVersion(msg.payload);
                    if (vi != null) {
                        agent  = vi.agent != null ? vi.agent : "";
                        height = vi.height;
                    }
                    peer.sendVerack();
                    break;
                }
            }
            peer.close();

            PeerDiscovery.get().addCleartextPeer(ip);
            HNSPeerManager.addCleartextCapable(ip); // cache for fast broadcast
            // Preserve existing version if we didn't get one
            PeerScorecard.PeerRecord existing = PeerScorecard.get().getRecord(ip);
            if (agent.isEmpty() && existing != null
                    && existing.lastVersion != null && !existing.lastVersion.isEmpty())
                agent = existing.lastVersion;
            PeerScorecard.get().recordSuccess(ip, agent, height);
            return ip;
        } catch (Exception e) {
            // Not reachable on cleartext port — don't penalize
        }
        return null;
    }

    public void stop() {
        running.set(false);
        scheduler.shutdownNow();
    }

    /** Simple concurrent hash set. */
    private static class ConcurrentHashSet<T> extends java.util.AbstractSet<T> {
        private final ConcurrentHashMap<T, Boolean> map = new ConcurrentHashMap<>();
        public boolean add(T e)      { return map.put(e, Boolean.TRUE) == null; }
        public boolean contains(Object o) { return map.containsKey(o); }
        public java.util.Iterator<T> iterator() { return map.keySet().iterator(); }
        public int size()            { return map.size(); }
    }
}