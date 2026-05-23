package handshake.node.dns;

import handshake.node.EventBus;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Recursive DNS resolver on port 5350.
 *
 * Resolves DNS queries for any name using HNS-first logic:
 *
 *   1. Extract the TLD from the query name
 *   2. Check the Handshake name index — HNS always wins
 *      → Found: forward to our own authoritative server (port 5349)
 *        which returns NS records, then follow the referral chain
 *      → Not found: forward to ICANN root hints for normal resolution
 *
 * This means Handshake TLDs are always resolved from the blockchain,
 * even if a conflicting ICANN TLD is created in the future.
 *
 * Matches HSD's recursive resolver behavior on port 5350.
 * Configure this as your system DNS server or browser DoH endpoint.
 */
public class RecursiveResolver {

    public static final int  DEFAULT_PORT     = 5350;
    private static final int MAX_UDP_SIZE     = 4096;
    private static final int THREAD_POOL_SIZE = 16;
    private static final int UPSTREAM_TIMEOUT = 1500; // ms

    private final NameIndex           nameIndex;
    private final AuthoritativeServer authServer;
    private final int                 port;
    private final ExecutorService executor;
    private DatagramSocket        socket;
    private volatile boolean      running;
    private Thread                listenThread;

    public RecursiveResolver(NameIndex nameIndex, AuthoritativeServer authServer, int port) {
        this.nameIndex  = nameIndex;
        this.authServer = authServer;
        this.port       = port;
        this.executor   = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
    }

    public RecursiveResolver(NameIndex nameIndex, AuthoritativeServer authServer) {
        this(nameIndex, authServer, DEFAULT_PORT);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() throws Exception {
        socket = new DatagramSocket(port);
        running      = true;
        listenThread = new Thread(this::listenLoop, "dns-recursive-" + port);
        listenThread.setDaemon(true);
        listenThread.start();
        System.out.println("[RecursiveNS] Recursive resolver listening on port " + port);
        System.out.println("[RecursiveNS] HNS-first: Handshake names always take priority");
        // Auto-detect upstream DNS eagerly so it shows in startup log
        getUpstreamDns();
    }

    public void stop() {
        running = false;
        if (socket != null && !socket.isClosed()) socket.close();
        executor.shutdown();
        System.out.println("[RecursiveNS] Stopped.");
    }

    // ── Listen loop ───────────────────────────────────────────────────────────

    private void listenLoop() {
        byte[] buf = new byte[MAX_UDP_SIZE];
        while (running) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                System.out.println("[RecursiveNS] Packet received: "
                        + packet.getLength() + " bytes from "
                        + packet.getAddress().getHostAddress()
                        + ":" + packet.getPort());

                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), 0, data, 0, data.length);
                InetAddress addr = packet.getAddress();
                int         prt  = packet.getPort();

                executor.submit(() -> handleQuery(data, data.length, addr, prt));

            } catch (Exception e) {
                if (running)
                    System.out.println("[RecursiveNS] Receive error: "
                            + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    // ── Query handler ─────────────────────────────────────────────────────────

    private void handleQuery(byte[] data, int len,
                             InetAddress clientAddr, int clientPort) {
        try {
            DnsMessage.Message query = DnsMessage.parse(data, len);
            if (!query.header.isQuery()) return;
            if (query.questions.isEmpty()) return;

            byte[] response = resolve(query, data);
            DatagramPacket reply = new DatagramPacket(
                    response, response.length, clientAddr, clientPort);
            socket.send(reply);

        } catch (Exception e) {
            System.out.println("[RecursiveNS] Handler error: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ── Resolution logic ──────────────────────────────────────────────────────

    /**
     * Resolves a DNS query using HNS-first logic.
     *
     * @param query    the parsed DNS query
     * @param rawQuery the original raw bytes (forwarded upstream if needed)
     * @return         the DNS response bytes to send back to the client
     */
    /**
     * Resolves a raw DNS wire-format query and returns a raw DNS wire-format response.
     * Used by the DoH endpoint in NodeHttpServer.
     */
    public byte[] resolveRaw(byte[] rawQuery) {
        try {
            if (rawQuery == null || rawQuery.length < 12) {
                System.out.printf("[DoH] Query too short: %d bytes%n",
                        rawQuery == null ? 0 : rawQuery.length);
                return DnsMessage.buildMinimalServfail();
            }
            DnsMessage.Message query = DnsMessage.parse(rawQuery, rawQuery.length);
            if (query == null) {
                System.out.println("[DoH] Failed to parse query");
                return DnsMessage.buildMinimalServfail();
            }
            if (query.questions.isEmpty()) {
                System.out.println("[DoH] Query has no questions");
                return DnsMessage.buildMinimalServfail();
            }
            System.out.printf("[DoH] Resolving: %s type=%s%n",
                    query.queryName(), DnsMessage.typeName(query.queryType()));
            byte[] response = resolve(query, rawQuery);
            System.out.printf("[DoH] Response: %d bytes%n",
                    response != null ? response.length : 0);
            return response != null ? response : DnsMessage.buildMinimalServfail();
        } catch (Exception e) {
            System.out.printf("[DoH] Error: %s%n", e.getMessage());
            return DnsMessage.buildMinimalServfail();
        }
    }

    private byte[] resolve(DnsMessage.Message query, byte[] rawQuery) {
        String tld   = query.queryTld();
        String qname = query.queryName();
        String qtype = DnsMessage.typeName(query.queryType());

        if (tld == null || tld.isEmpty())
            return DnsMessage.buildServfail(query);

        ReservedTldList reserved = ReservedTldList.getInstance();

        // ── HNS-first: check Handshake name index ─────────────────────────────
        if (nameIndex.contains(tld)) {
            byte[] response = forwardToAuthoritativeServer(rawQuery, query);
            int rcode = DnsMessage.rcode(response);

            // If this is an A/AAAA/TYPE65 query and we got an NS referral,
            // follow the referral to get the actual address record
            int qtype_int = query.queryType();
            boolean isAddrQuery = qtype_int == DnsMessage.TYPE_A
                    || qtype_int == DnsMessage.TYPE_AAAA
                    || qtype_int == 65; // HTTPS/SVCB

            if (rcode == 0 && isAddrQuery && DnsMessage.answerCount(response) == 0) {
                // Extract glue IPs from additional section and follow referral
                byte[] followed = followHnsReferral(rawQuery, response);
                if (followed != null && followed.length > 12) {
                    response = followed;
                }
            }

            EventBus.get().dns("HNS " + DnsMessage.typeName(qtype_int) + " " + qname
                    + (DnsMessage.answerCount(response) > 0 ? " → resolved"
                    : rcode == 0 ? " → referral" : " → NXDOMAIN"));
            return response;
        }

        // ── Check if this is a known ICANN/reserved TLD ───────────────────────
        if (reserved.isReserved(tld)) {
            byte[] response = forwardToIcann(rawQuery, query);
            int answers = DnsMessage.answerCount(response);
            EventBus.get().dns("ICANN " + qtype + " " + qname
                    + " → " + (answers > 0 ? answers + " records" : "NXDOMAIN"));
            return response;
        }

        // ── Unknown TLD ───────────────────────────────────────────────────────
        if (!nameIndex.isReady()) {
            System.out.printf("[RecursiveNS] Name index still building — "
                    + "NXDOMAIN for '%s' (may exist on Handshake)%n", tld);
            return DnsMessage.buildNxdomain(query);
        }

        // Index complete — not on Handshake or ICANN
        EventBus.get().dns("NXDOMAIN " + qtype + " " + qname);
        return DnsMessage.buildNxdomain(query);
    }

    /**
     * Follows an HNS NS referral by extracting glue IPs from the additional
     * section and querying the nameserver directly for the original record.
     */
    private byte[] followHnsReferral(byte[] rawQuery, byte[] referral) {
        try {
            DnsMessage.Message ref = DnsMessage.parse(referral, referral.length);

            // Collect glue IPs from additional section
            java.util.List<String> glueIps = new java.util.ArrayList<>();
            for (DnsMessage.ResourceRecord rr : ref.additional) {
                if (rr.type() == DnsMessage.TYPE_A && rr.rdata().length == 4) {
                    byte[] ip = rr.rdata();
                    glueIps.add((ip[0]&0xFF)+"."+(ip[1]&0xFF)+"."
                            + (ip[2]&0xFF)+"."+(ip[3]&0xFF));
                }
            }

            if (glueIps.isEmpty()) return null;

            // Query each glue nameserver for the original record
            for (String ip : glueIps) {
                try {
                    System.out.printf("[RecursiveNS] Following HNS referral → %s%n", ip);
                    byte[] resp = forwardUdp(rawQuery,
                            java.net.InetAddress.getByName(ip), 53);
                    if (resp != null && resp.length > 12
                            && DnsMessage.answerCount(resp) > 0) {
                        System.out.printf("[RecursiveNS] HNS referral → %d bytes%n",
                                resp.length);
                        return resp;
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            System.out.printf("[RecursiveNS] followHnsReferral error: %s%n",
                    e.getMessage());
        }
        return null;
    }

    /**
     * Forwards the query to our own authoritative server on port 5349.
     * Used for Handshake TLDs found in the name index.
     */
    private byte[] forwardToAuthoritativeServer(byte[] rawQuery,
                                                DnsMessage.Message query) {
        // Direct method call — no UDP round-trip needed since we're in the same JVM
        return authServer.resolveDirectly(rawQuery, rawQuery.length);
    }

    // ── Upstream DNS configuration ────────────────────────────────────────────

    /**
     * Upstream DNS server for ICANN queries.
     * Auto-detected from system on startup, or overridden via setUpstreamDns().
     */
    private static volatile String upstreamDns = null;

    public static void setUpstreamDns(String dns) {
        upstreamDns = dns;
        System.out.println("[RecursiveNS] Upstream DNS set to: " + dns);
    }

    private static String getUpstreamDns() {
        if (upstreamDns != null) return upstreamDns;

        // Method 1: sun.net.dns.ResolverConfiguration (JDK 8-17)
        try {
            Class<?> rc = Class.forName("sun.net.dns.ResolverConfiguration");
            Object config = rc.getMethod("open").invoke(null);
            @SuppressWarnings("unchecked")
            java.util.List<String> ns =
                    (java.util.List<String>) rc.getMethod("nameservers").invoke(config);
            for (String s : ns) {
                if (!s.equals("127.0.0.1") && !s.equals("::1")) {
                    upstreamDns = s;
                    System.out.println("[RecursiveNS] Auto-detected upstream DNS: " + s);
                    return s;
                }
            }
        } catch (Exception ignored) {}

        // Method 2: netsh on Windows (JDK 18+)
        try {
            Process p = Runtime.getRuntime().exec("netsh interface ip show dns");
            String output = new String(p.getInputStream().readAllBytes());
            for (String line : output.split("\n")) {
                line = line.trim();
                if (line.contains(":")) {
                    String val = line.substring(line.lastIndexOf(':') + 1).trim();
                    if (val.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")
                            && !val.equals("127.0.0.1")) {
                        upstreamDns = val;
                        System.out.println("[RecursiveNS] Auto-detected upstream DNS: " + val);
                        return val;
                    }
                }
            }
        } catch (Exception ignored) {}

        System.out.println("[RecursiveNS] Could not auto-detect upstream DNS");
        return null;
    }

    // ── Full recursive ICANN resolution ───────────────────────────────────────

    private static final int MAX_REFERRAL_DEPTH = 5;

    /**
     * Fully recursive ICANN resolution.
     * Follows NS referral chains until an authoritative answer is found.
     */
    private byte[] forwardToIcann(byte[] rawQuery, DnsMessage.Message query) {
        String tld = query.queryTld();
        ReservedTldList reserved = ReservedTldList.getInstance();

        // Step 1: Try TLD nameservers from database directly (UDP)
        if (tld != null && reserved.hasNs(tld)) {
            for (String nsHost : reserved.getNs(tld)) {
                for (String ip : reserved.getGlueIps(nsHost)) {
                    try {
                        byte[] resp = forwardUdp(rawQuery,
                                InetAddress.getByName(ip), 53);
                        byte[] resolved = followReferrals(rawQuery, resp, 1);
                        // Only use this result if it has actual answers (>50 bytes)
                        if (resolved != null && resolved.length > 50)
                            return resolved;
                    } catch (Exception ignored) {}
                }
            }
        }

        // Step 2: Try configured upstream DNS, then well-known fallbacks
        String[] candidates = buildUpstreamCandidates();
        for (String upstream : candidates) {
            try {
                byte[] response = forwardUdp(rawQuery,
                        InetAddress.getByName(upstream), 53);
                if (response != null && response.length > 12) {
                    System.out.printf("[RecursiveNS] Upstream %s → %d bytes%n",
                            upstream, response.length);
                    // Update cached upstream to the one that worked
                    if (!upstream.equals(upstreamDns)) {
                        System.out.printf("[RecursiveNS] Switching upstream to %s%n",
                                upstream);
                        upstreamDns = upstream;
                    }
                    return response;
                }
            } catch (Exception ignored) {}
        }

        System.out.println("[RecursiveNS] All upstream DNS failed — SERVFAIL");
        return DnsMessage.buildServfail(query);
    }

    /** Builds ordered list of upstream DNS candidates to try. */
    private static String[] buildUpstreamCandidates() {
        java.util.List<String> list = new java.util.ArrayList<>();
        // Auto-detected system DNS first
        if (upstreamDns != null && !upstreamDns.isBlank())
            list.add(upstreamDns);
        // Well-known reliable fallbacks
        list.add("1.1.1.1");   // Cloudflare
        list.add("8.8.8.8");   // Google
        list.add("9.9.9.9");   // Quad9
        return list.toArray(new String[0]);
    }

    /**
     * Follows NS referral chains in a DNS response.
     * Returns the final answer, or the last referral if max depth reached.
     */
    private byte[] followReferrals(byte[] rawQuery, byte[] responseBytes,
                                   int depth) {
        if (depth > MAX_REFERRAL_DEPTH) return responseBytes;

        try {
            DnsMessage.Message response = DnsMessage.parse(responseBytes,
                    responseBytes.length);

            // Has answers or is authoritative — this is the final response
            if (!response.answers.isEmpty()) return responseBytes;
            if ((response.header.flags() & DnsMessage.FLAG_AA) != 0)
                return responseBytes;
            if (response.authority.isEmpty()) return responseBytes;

            // Extract glue IPs from additional section for NS referral
            java.util.List<String> referralIps = new java.util.ArrayList<>();
            for (DnsMessage.ResourceRecord auth : response.authority) {
                if (auth.type() != DnsMessage.TYPE_NS) continue;
                // Use full message buffer to resolve compression pointers in NS rdata
                String nsName = DnsMessage.decodeNameFromMessage(
                                responseBytes, auth.rdataOffset())
                        .toLowerCase().replaceAll("\\.$", "");
                for (DnsMessage.ResourceRecord add : response.additional) {
                    if (add.type() == DnsMessage.TYPE_A) {
                        String addName = add.name().toLowerCase()
                                .replaceAll("\\.$", "");
                        if (addName.equals(nsName)) {
                            byte[] ip = add.rdata();
                            if (ip.length == 4)
                                referralIps.add((ip[0]&0xFF) + "." + (ip[1]&0xFF)
                                        + "." + (ip[2]&0xFF) + "." + (ip[3]&0xFF));
                        }
                    }
                }
            }

            if (referralIps.isEmpty()) return responseBytes;

            System.out.printf("[RecursiveNS] Following referral to %s (depth %d)%n",
                    referralIps.get(0), depth);

            for (String ip : referralIps) {
                try {
                    byte[] next = forwardUdp(rawQuery,
                            InetAddress.getByName(ip), 53);
                    byte[] result = followReferrals(rawQuery, next, depth + 1);
                    if (result != null) return result;
                } catch (Exception ignored) {}
            }

            return responseBytes; // return referral if we couldn't follow

        } catch (Exception e) {
            return responseBytes;
        }
    }

    /**
     * Forwards a raw DNS query via UDP and returns the response.
     *
     * @param query   raw DNS query bytes
     * @param server  upstream server address
     * @param port    upstream server port
     * @return        raw response bytes
     * @throws Exception if the upstream query fails or times out
     */
    private byte[] forwardUdp(byte[] query,
                              InetAddress server, int port) throws Exception {
        try (DatagramSocket upstream = new DatagramSocket()) {
            upstream.setSoTimeout(UPSTREAM_TIMEOUT);

            DatagramPacket send = new DatagramPacket(query, query.length,
                    server, port);
            upstream.send(send);

            byte[] buf    = new byte[4096];
            DatagramPacket recv = new DatagramPacket(buf, buf.length);
            upstream.receive(recv);

            byte[] response = new byte[recv.getLength()];
            System.arraycopy(buf, 0, response, 0, response.length);
            return response;
        }
    }
}