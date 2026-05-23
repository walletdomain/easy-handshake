package handshake.node.dns;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Authoritative nameserver for the Handshake root zone (port 5349).
 *
 * Answers DNS queries about Handshake TLDs only.
 * Does NOT handle ICANN TLDs — those belong to the recursive resolver.
 *
 * For each incoming query:
 *   1. Parse the DNS question
 *   2. Extract the TLD from the queried name
 *   3. Look up the TLD in the Handshake name index
 *   4. If found: return NS records (and any glue A/AAAA records)
 *   5. If not found: return NXDOMAIN
 *
 * This matches HSD's authoritative server behavior on port 5349.
 * Other resolvers point at this server to resolve Handshake TLDs.
 *
 * Thread safety: one thread per UDP packet, up to THREAD_POOL_SIZE concurrent.
 * The NameIndex uses a ConcurrentHashMap so concurrent lookups are safe.
 */
public class AuthoritativeServer {

    public static final int  DEFAULT_PORT    = 5349;
    private static final int MAX_UDP_SIZE    = 4096;
    private static final int THREAD_POOL_SIZE = 8;
    private static final int DEFAULT_TTL     = 3600; // 1 hour

    private final NameIndex       nameIndex;
    private final int             port;
    private final ExecutorService executor;
    private DatagramSocket        socket;
    private volatile boolean      running;
    private Thread                listenThread;

    public AuthoritativeServer(NameIndex nameIndex, int port) {
        this.nameIndex = nameIndex;
        this.port      = port;
        this.executor  = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
    }

    public AuthoritativeServer(NameIndex nameIndex) {
        this(nameIndex, DEFAULT_PORT);
    }

    /**
     * Resolves a query directly without UDP — called by RecursiveResolver
     * to avoid an internal UDP round-trip on the loopback interface.
     *
     * @param queryBytes raw DNS query bytes
     * @param len        number of valid bytes
     * @return           raw DNS response bytes
     */
    public byte[] resolveDirectly(byte[] queryBytes, int len) {
        try {
            DnsMessage.Message query = DnsMessage.parse(queryBytes, len);
            if (!query.header.isQuery() || query.questions.isEmpty())
                return DnsMessage.buildServfail(query);
            return buildResponse(query);
        } catch (Exception e) {
            System.out.println("[AuthNS] Direct resolve error: " + e.getMessage());
            // Build a minimal SERVFAIL — we may not have a parsed query
            byte[] servfail = new byte[12];
            servfail[0] = queryBytes[0]; // copy ID
            servfail[1] = queryBytes[1];
            servfail[2] = (byte) 0x80;  // QR=1
            servfail[3] = (byte) 0x02;  // RCODE=SERVFAIL
            return servfail;
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() throws Exception {
        socket = new DatagramSocket(port);
        running      = true;
        listenThread = new Thread(this::listenLoop, "dns-auth-" + port);
        listenThread.setDaemon(true);
        listenThread.start();
        System.out.println("[AuthNS] Handshake authoritative nameserver listening on port "
                + port);
    }

    public void stop() {
        running = false;
        if (socket != null && !socket.isClosed()) socket.close();
        executor.shutdown();
        System.out.println("[AuthNS] Stopped.");
    }

    // ── Listen loop ───────────────────────────────────────────────────────────

    private void listenLoop() {
        byte[] buf = new byte[MAX_UDP_SIZE];
        while (running) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                // Copy data for handler thread — buf will be reused
                byte[] data   = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), 0, data, 0, data.length);
                InetAddress addr = packet.getAddress();
                int         prt  = packet.getPort();

                executor.submit(() -> handleQuery(data, data.length, addr, prt));

            } catch (Exception e) {
                if (running)
                    System.out.println("[AuthNS] Receive error: " + e.getMessage());
            }
        }
    }

    // ── Query handler ─────────────────────────────────────────────────────────

    private void handleQuery(byte[] data, int len,
                             InetAddress clientAddr, int clientPort) {
        try {
            DnsMessage.Message query = DnsMessage.parse(data, len);

            if (!query.header.isQuery()) return; // ignore responses
            if (query.questions.isEmpty()) return;

            byte[] response = buildResponse(query);
            DatagramPacket reply = new DatagramPacket(
                    response, response.length, clientAddr, clientPort);
            socket.send(reply);

        } catch (Exception e) {
            System.out.println("[AuthNS] Handler error: " + e.getMessage());
        }
    }

    // ── Response builder ──────────────────────────────────────────────────────

    private byte[] buildResponse(DnsMessage.Message query) {
        String tld = query.queryTld();
        if (tld == null || tld.isEmpty())
            return DnsMessage.buildNxdomain(query);

        byte[] resource = nameIndex.lookup(tld);
        if (resource == null)
            return DnsMessage.buildNxdomain(query);

        return buildNsResponse(query, tld, resource);
    }

    /**
     * Builds an NS referral response from Handshake resource record bytes.
     *
     * Handshake resource records use a compact encoding where each record
     * is prefixed with a type byte followed by type-specific data.
     * We decode NS records and return them as a DNS NS referral response.
     *
     * If no NS records are found in the resource data, we return NXDOMAIN
     * (the name exists but has no nameserver delegation configured yet).
     */
    private byte[] buildNsResponse(DnsMessage.Message query,
                                   String tld, byte[] resource) {
        List<String> nsNames = parseNsRecords(resource);
        if (nsNames.isEmpty())
            return buildEmptyResponse(query);

        // Parse glue records (NS name → IP)
        java.util.Map<String, String> glue4 = parseGlue4Records(resource);
        java.util.Map<String, String> glue6 = parseGlue6Records(resource);

        return DnsMessage.buildNsReferralWithGlue(
                query, tld, nsNames, glue4, glue6, DEFAULT_TTL);
    }

    /** Parses GLUE4 records: ns name → IPv4 address string. */
    private static java.util.Map<String, String> parseGlue4Records(byte[] resource) {
        java.util.Map<String, String> glue = new java.util.LinkedHashMap<>();
        if (resource == null || resource.length == 0) return glue;
        int i = (resource.length > 1 && resource[0] == 0x00) ? 1 : 0;
        while (i < resource.length) {
            int type = resource[i++] & 0xFF;
            switch (type) {
                case 0: { // DS
                    if (i + 5 > resource.length) return glue;
                    i += 5 + (resource[i + 4] & 0xFF);
                    break;
                }
                case 1: { // NS — skip
                    int[] r = readWireName(resource, i);
                    if (r == null) return glue;
                    i = r[0];
                    break;
                }
                case 2: { // GLUE4
                    int[] r = readWireName(resource, i);
                    if (r == null || r[0] + 4 > resource.length) return glue;
                    String name = wireBytesToName(resource, i);
                    if (!name.endsWith(".")) name += ".";
                    byte[] ip = new byte[]{resource[r[0]], resource[r[0]+1],
                            resource[r[0]+2], resource[r[0]+3]};
                    glue.put(name, (ip[0]&0xFF)+"."+( ip[1]&0xFF)+"."+(ip[2]&0xFF)+"."+(ip[3]&0xFF));
                    i = r[0] + 4;
                    break;
                }
                case 3: { // GLUE6 — skip
                    int[] r = readWireName(resource, i);
                    if (r == null || r[0] + 16 > resource.length) return glue;
                    i = r[0] + 16;
                    break;
                }
                case 4: i += 4;  break; // SYNTH4
                case 5: i += 16; break; // SYNTH6
                case 6: { // TXT
                    if (i >= resource.length) return glue;
                    int count = resource[i++] & 0xFF;
                    for (int t = 0; t < count && i < resource.length; t++) {
                        int len = resource[i++] & 0xFF;
                        i += len;
                    }
                    break;
                }
                default: return glue;
            }
        }
        return glue;
    }

    /** Parses GLUE6 records: ns name → IPv6 address string. */
    private static java.util.Map<String, String> parseGlue6Records(byte[] resource) {
        java.util.Map<String, String> glue = new java.util.LinkedHashMap<>();
        if (resource == null || resource.length == 0) return glue;
        int i = (resource.length > 1 && resource[0] == 0x00) ? 1 : 0;
        while (i < resource.length) {
            int type = resource[i++] & 0xFF;
            switch (type) {
                case 0: { if (i + 5 > resource.length) return glue; i += 5 + (resource[i+4]&0xFF); break; }
                case 1: { int[] r = readWireName(resource, i); if (r==null) return glue; i=r[0]; break; }
                case 2: { int[] r = readWireName(resource, i); if (r==null||r[0]+4>resource.length) return glue; i=r[0]+4; break; }
                case 3: { // GLUE6
                    int[] r = readWireName(resource, i);
                    if (r == null || r[0] + 16 > resource.length) return glue;
                    String name = wireBytesToName(resource, i);
                    if (!name.endsWith(".")) name += ".";
                    byte[] ip = java.util.Arrays.copyOfRange(resource, r[0], r[0]+16);
                    try {
                        glue.put(name, java.net.Inet6Address.getByAddress(ip).getHostAddress());
                    } catch (Exception ignored) {}
                    i = r[0] + 16;
                    break;
                }
                case 4: i += 4; break;
                case 5: i += 16; break;
                case 6: { if (i>=resource.length) return glue; int c=resource[i++]&0xFF; for(int t=0;t<c&&i<resource.length;t++){int l=resource[i++]&0xFF;i+=l;} break; }
                default: return glue;
            }
        }
        return glue;
    }

    /**
     * Parses NS record hostnames from Handshake resource record bytes.
     *
     * Handshake uses a compact resource record format defined in
     * hsd/lib/dns/resource.js. The format is:
     *
     *   For each record:
     *     type  (1 byte)  — record type (2=NS, 1=A, 28=AAAA, 16=TXT, etc.)
     *     data  (variable) — type-specific encoding
     *
     *   NS record data:
     *     name_len (1 byte) — length of nameserver hostname
     *     name     (N bytes) — nameserver hostname as ASCII string
     *
     * We extract only NS records for the referral response.
     */
    private static List<String> parseNsRecords(byte[] resource) {
        List<String> nsNames = new ArrayList<>();
        if (resource == null || resource.length == 0) return nsNames;

        int i = 0;

        // Version byte is optional — skip 0x00 if present at start
        if (resource.length > 1 && resource[0] == 0x00) {
            int nextType = resource[1] & 0xFF;
            if (nextType >= 1 && nextType <= 6) {
                i = 1;
            }
        }

        while (i < resource.length) {
            int type = resource[i++] & 0xFF;

            switch (type) {
                case 0: { // DS: keyTag(2) + algo(1) + digestType(1) + digestLen(1) + digest(N)
                    if (i + 5 > resource.length) return nsNames;
                    int digestLen = resource[i + 4] & 0xFF;
                    i += 5 + digestLen;
                    break;
                }
                case 1: { // NS — DNS wire format name (length-prefixed labels)
                    int[] result = readWireName(resource, i);
                    if (result == null) return nsNames;
                    String name = wireBytesToName(resource, i);
                    if (!name.isEmpty())
                        nsNames.add(name.endsWith(".") ? name : name + ".");
                    i = result[0]; // advance past name
                    break;
                }
                case 2: { // GLUE4 — DNS wire name + 4 bytes IPv4
                    int[] result = readWireName(resource, i);
                    if (result == null || result[0] + 4 > resource.length)
                        return nsNames;
                    String name = wireBytesToName(resource, i);
                    if (!name.isEmpty())
                        nsNames.add(name.endsWith(".") ? name : name + ".");
                    i = result[0] + 4; // skip past name + IPv4
                    break;
                }
                case 3: { // GLUE6 — DNS wire name + 16 bytes IPv6
                    int[] result = readWireName(resource, i);
                    if (result == null || result[0] + 16 > resource.length)
                        return nsNames;
                    String name = wireBytesToName(resource, i);
                    if (!name.isEmpty())
                        nsNames.add(name.endsWith(".") ? name : name + ".");
                    i = result[0] + 16;
                    break;
                }
                case 4: { // SYNTH4 — 4 bytes IPv4, synthesize NS name
                    if (i + 4 > resource.length) return nsNames;
                    byte[] ip = new byte[4];
                    System.arraycopy(resource, i, ip, 0, 4);
                    nsNames.add(synthesizeNs4(ip));
                    i += 4;
                    break;
                }
                case 5: { // SYNTH6 — 16 bytes IPv6
                    if (i + 16 > resource.length) return nsNames;
                    i += 16;
                    break;
                }
                case 6: { // TXT
                    if (i >= resource.length) return nsNames;
                    int count = resource[i++] & 0xFF;
                    for (int t = 0; t < count && i < resource.length; t++) {
                        int txtLen = resource[i++] & 0xFF;
                        i += txtLen;
                    }
                    break;
                }
                default:
                    System.out.printf("[AuthNS] Unknown type 0x%02x — stopping%n", type);
                    return nsNames;
            }
        }
        return nsNames;
    }

    /**
     * Reads a DNS wire-format name starting at offset within data.
     * Returns {endOffset} after consuming the name bytes.
     * Compression pointers (0xC0 0xXX) are supported via the full buffer.
     */
    private static int[] readWireName(byte[] data, int offset) {
        int i = offset;
        while (i < data.length) {
            int len = data[i++] & 0xFF;
            if (len == 0) return new int[]{i};
            if ((len & 0xC0) == 0xC0) { i++; return new int[]{i}; }
            i += len;
        }
        return null;
    }

    /**
     * Converts DNS wire-format name bytes at offset to a dotted string.
     * Follows compression pointers using the full resource buffer.
     */
    private static String wireBytesToName(byte[] data, int offset) {
        StringBuilder sb  = new StringBuilder();
        int           i   = offset;
        int           jumps = 0;

        while (i < data.length) {
            int len = data[i++] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) {
                // Compression pointer — follow it
                if (i >= data.length) break;
                int ptr = ((len & 0x3F) << 8) | (data[i++] & 0xFF);
                if (++jumps > 10 || ptr >= data.length) break;
                i = ptr; // jump to pointer target and continue reading
                continue;
            }
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(data, i, len, StandardCharsets.UTF_8));
            i += len;
        }
        return sb.toString().toLowerCase();
    }

    private static String synthesizeNs4(byte[] ip) {
        return String.format("_%d.%d.%d.%d._synth.",
                ip[0]&0xFF, ip[1]&0xFF, ip[2]&0xFF, ip[3]&0xFF);
    }

    private static byte[] buildEmptyResponse(DnsMessage.Message query) {
        // NOERROR with AA bit set, no records
        var b = new handshake.node.dns.DnsMessage.Message();
        b.header = new DnsMessage.Header(
                query.header.id(),
                DnsMessage.FLAG_QR | DnsMessage.FLAG_AA,
                query.questions.size(), 0, 0, 0);
        b.questions.addAll(query.questions);
        // Manually build the minimal response
        java.nio.ByteBuffer buf =
                java.nio.ByteBuffer.allocate(512)
                        .order(java.nio.ByteOrder.BIG_ENDIAN);
        buf.putShort((short) query.header.id());
        buf.putShort((short)(DnsMessage.FLAG_QR | DnsMessage.FLAG_AA));
        buf.putShort((short) query.questions.size()); // qdcount
        buf.putShort((short) 0); // ancount
        buf.putShort((short) 0); // nscount
        buf.putShort((short) 0); // arcount
        for (DnsMessage.Question q : query.questions) {
            buf.put(DnsMessage.encodeName(q.name()));
            buf.putShort((short) q.type());
            buf.putShort((short) q.qclass());
        }
        buf.flip();
        byte[] result = new byte[buf.limit()];
        buf.get(result);
        return result;
    }
}