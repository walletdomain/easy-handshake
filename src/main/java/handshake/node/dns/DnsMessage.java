package handshake.node.dns;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * DNS message wire format parser and builder (RFC 1035).
 *
 * DNS message layout:
 *   Header   (12 bytes)
 *   Question (variable)  — what is being asked
 *   Answer   (variable)  — direct answers
 *   Authority (variable) — NS referrals
 *   Additional (variable)— A/AAAA for NS records (glue)
 *
 * We implement the subset needed for a Handshake root nameserver:
 *   - Parse incoming A, AAAA, NS, TXT, SOA queries
 *   - Build NS referral responses (authoritative nameserver answers)
 *   - Build A/AAAA direct answers
 *   - Build NXDOMAIN responses
 *   - Build SERVFAIL responses
 *   - DNS name compression (pointer following) for parsing
 *   - DNS name compression for building (simple, no shared pointers)
 */
public class DnsMessage {

    // ── Record types ──────────────────────────────────────────────────────────

    public static final int TYPE_A     = 1;
    public static final int TYPE_NS    = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA   = 6;
    public static final int TYPE_MX    = 15;
    public static final int TYPE_TXT   = 16;
    public static final int TYPE_AAAA  = 28;
    public static final int TYPE_SRV   = 33;
    public static final int TYPE_DS    = 43;
    public static final int TYPE_ANY   = 255;

    // ── Classes ───────────────────────────────────────────────────────────────

    public static final int CLASS_IN  = 1;

    // ── Response codes ────────────────────────────────────────────────────────

    public static final int RCODE_OK       = 0;
    public static final int RCODE_FORMAT   = 1;
    public static final int RCODE_SERVFAIL = 2;
    public static final int RCODE_NXDOMAIN = 3;
    public static final int RCODE_NOTIMPL  = 4;
    public static final int RCODE_REFUSED  = 5;

    // ── Opcodes ───────────────────────────────────────────────────────────────

    public static final int OPCODE_QUERY  = 0;
    public static final int OPCODE_IQUERY = 1;
    public static final int OPCODE_STATUS = 2;

    // ── Header flags ─────────────────────────────────────────────────────────

    public static final int FLAG_QR = 0x8000; // Query(0) / Response(1)
    public static final int FLAG_AA = 0x0400; // Authoritative Answer
    public static final int FLAG_TC = 0x0200; // Truncated
    public static final int FLAG_RD = 0x0100; // Recursion Desired
    public static final int FLAG_RA = 0x0080; // Recursion Available

    // =========================================================================
    // Data classes
    // =========================================================================

    /** DNS message header (12 bytes). */
    public record Header(
            int id,
            int flags,
            int qdCount,
            int anCount,
            int nsCount,
            int arCount
    ) {
        public boolean isQuery()       { return (flags & FLAG_QR) == 0; }
        public boolean isResponse()    { return (flags & FLAG_QR) != 0; }
        public int     opcode()        { return (flags >> 11) & 0xF; }
        public int     rcode()         { return flags & 0xF; }
        public boolean isRecursionDesired() { return (flags & FLAG_RD) != 0; }
    }

    /** DNS question entry. */
    public record Question(String name, int type, int qclass) {
        @Override public String toString() {
            return name + " " + typeName(type) + " " + className(qclass);
        }
    }

    /** DNS resource record. */
    public record ResourceRecord(
            String name,
            int    type,
            int    rrClass,
            long   ttl,
            byte[] rdata,
            int    rdataOffset  // offset of rdata within the full message buffer
    ) {
        @Override public String toString() {
            return name + " " + ttl + " " + typeName(type)
                    + " [" + rdata.length + " bytes]";
        }
    }

    /** Parsed DNS message. */
    public static class Message {
        public Header               header;
        public List<Question>       questions   = new ArrayList<>();
        public List<ResourceRecord> answers     = new ArrayList<>();
        public List<ResourceRecord> authority   = new ArrayList<>();
        public List<ResourceRecord> additional  = new ArrayList<>();
        public byte[]               rawBytes;   // full message bytes for compression pointer resolution

        /** Returns the first question's name, or null. */
        public String queryName() {
            return questions.isEmpty() ? null : questions.getFirst().name();
        }

        /** Returns the TLD of the first question (last label before root). */
        public String queryTld() {
            String name = queryName();
            if (name == null || name.isEmpty() || name.equals(".")) return null;
            String stripped = name.endsWith(".") ? name.substring(0, name.length()-1) : name;
            int dot = stripped.lastIndexOf('.');
            return dot < 0 ? stripped : stripped.substring(dot + 1);
        }

        /** Returns the first question's type, or 0. */
        public int queryType() {
            return questions.isEmpty() ? 0 : questions.getFirst().type();
        }
    }

    // =========================================================================
    // Parser
    // =========================================================================

    /**
     * Parses a DNS message from raw UDP bytes.
     *
     * @param data  the raw DNS message bytes
     * @param len   number of valid bytes in data
     * @return      parsed Message
     * @throws IllegalArgumentException if the message is malformed
     */
    public static Message parse(byte[] data, int len) {
        if (len < 12) throw new IllegalArgumentException("DNS message too short: " + len);

        ByteBuffer buf = ByteBuffer.wrap(data, 0, len).order(ByteOrder.BIG_ENDIAN);
        Message msg = new Message();
        msg.rawBytes = data;

        // Header
        int id      = buf.getShort() & 0xFFFF;
        int flags   = buf.getShort() & 0xFFFF;
        int qdCount = buf.getShort() & 0xFFFF;
        int anCount = buf.getShort() & 0xFFFF;
        int nsCount = buf.getShort() & 0xFFFF;
        int arCount = buf.getShort() & 0xFFFF;
        msg.header  = new Header(id, flags, qdCount, anCount, nsCount, arCount);

        // Questions
        int[] pos = {buf.position()};
        for (int i = 0; i < qdCount; i++) {
            String name   = readName(data, pos, len);
            int    qtype  = readUInt16(data, pos);
            int    qclass = readUInt16(data, pos);
            msg.questions.add(new Question(name, qtype, qclass));
        }

        // Resource records
        for (int i = 0; i < anCount; i++)
            msg.answers.add(readRR(data, pos, len));
        for (int i = 0; i < nsCount; i++)
            msg.authority.add(readRR(data, pos, len));
        for (int i = 0; i < arCount; i++)
            msg.additional.add(readRR(data, pos, len));

        return msg;
    }

    // =========================================================================
    // Builder — Response construction
    // =========================================================================

    /**
     * Builds a NXDOMAIN response for a query.
     * Used when a name does not exist in either Handshake or ICANN.
     */
    public static byte[] buildNxdomain(Message query) {
        return buildErrorResponse(query, RCODE_NXDOMAIN, true);
    }

    /**
     * Builds a SERVFAIL response.
     * Used when an upstream query fails or an internal error occurs.
     */
    public static byte[] buildServfail(Message query) {
        return buildErrorResponse(query, RCODE_SERVFAIL, false);
    }

    /**
     * Builds an NS referral response.
     * Used by the authoritative server to return NS records for a Handshake TLD.
     *
     * @param query    the original query
     * @param tld      the TLD being delegated (e.g. "wallet")
     * @param nsNames  list of nameserver hostnames (e.g. ["ns1.example.com."])
     * @param ttl      TTL for the NS records
     */
    public static byte[] buildNsReferral(Message query, String tld,
                                         List<String> nsNames, long ttl) {
        Builder b = new Builder(query.header.id(),
                FLAG_QR | FLAG_AA,   // authoritative response
                RCODE_OK);

        // Copy question
        for (Question q : query.questions) b.addQuestion(q);

        // Add NS records in authority section
        String apex = tld.endsWith(".") ? tld : tld + ".";
        for (String ns : nsNames) {
            String nsName = ns.endsWith(".") ? ns : ns + ".";
            b.addAuthority(apex, TYPE_NS, CLASS_IN, ttl, encodeName(nsName));
        }

        return b.build();
    }

    /**
     * Builds an A record response.
     *
     * @param query   the original query
     * @param name    the queried name
     * @param ipv4    IPv4 address string (e.g. "192.0.2.1")
     * @param ttl     TTL in seconds
     */
    public static byte[] buildAResponse(Message query, String name,
                                        String ipv4, long ttl) {
        Builder b = new Builder(query.header.id(), FLAG_QR | FLAG_AA, RCODE_OK);
        for (Question q : query.questions) b.addQuestion(q);
        b.addAnswer(name, TYPE_A, CLASS_IN, ttl, encodeIPv4(ipv4));
        return b.build();
    }

    /**
     * Builds an AAAA record response.
     */
    public static byte[] buildAaaaResponse(Message query, String name,
                                           String ipv6, long ttl) {
        Builder b = new Builder(query.header.id(), FLAG_QR | FLAG_AA, RCODE_OK);
        for (Question q : query.questions) b.addQuestion(q);
        b.addAnswer(name, TYPE_AAAA, CLASS_IN, ttl, encodeIPv6(ipv6));
        return b.build();
    }

    /**
     * Builds a TXT record response.
     */
    public static byte[] buildTxtResponse(Message query, String name,
                                          List<String> texts, long ttl) {
        Builder b = new Builder(query.header.id(), FLAG_QR | FLAG_AA, RCODE_OK);
        for (Question q : query.questions) b.addQuestion(q);
        for (String text : texts)
            b.addAnswer(name, TYPE_TXT, CLASS_IN, ttl, encodeTxt(text));
        return b.build();
    }

    /**
     * Builds a generic error response (NXDOMAIN, SERVFAIL, etc.).
     */
    private static byte[] buildErrorResponse(Message query, int rcode,
                                             boolean authoritative) {
        int flags = FLAG_QR | rcode;
        if (authoritative) flags |= FLAG_AA;
        Builder b = new Builder(query.header.id(), flags, rcode);
        for (Question q : query.questions) b.addQuestion(q);
        return b.build();
    }

    // =========================================================================
    // Internal builder
    // =========================================================================

    private static class Builder {
        private final int id;
        private final int flags;
        private final int rcode;
        private final List<Question>       questions  = new ArrayList<>();
        private final List<ResourceRecord> answers    = new ArrayList<>();
        private final List<ResourceRecord> authority  = new ArrayList<>();
        private final List<ResourceRecord> additional = new ArrayList<>();

        Builder(int id, int flags, int rcode) {
            this.id    = id;
            this.flags = (flags & ~0xF) | (rcode & 0xF);
            this.rcode = rcode;
        }

        void addQuestion(Question q)  { questions.add(q); }
        void addAnswer(String name, int type, int cls, long ttl, byte[] rdata) {
            answers.add(new ResourceRecord(name, type, cls, ttl, rdata, 0));
        }
        void addAuthority(String name, int type, int cls, long ttl, byte[] rdata) {
            authority.add(new ResourceRecord(name, type, cls, ttl, rdata, 0));
        }
        @SuppressWarnings("unused")
        void addAdditional(String name, int type, int cls, long ttl, byte[] rdata) {
            additional.add(new ResourceRecord(name, type, cls, ttl, rdata, 0));
        }

        byte[] build() {
            ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);

            // Header
            buf.putShort((short) id);
            buf.putShort((short) flags);
            buf.putShort((short) questions.size());
            buf.putShort((short) answers.size());
            buf.putShort((short) authority.size());
            buf.putShort((short) additional.size());

            // Questions
            for (Question q : questions) {
                writeNameBytes(buf, q.name());
                buf.putShort((short) q.type());
                buf.putShort((short) q.qclass());
            }

            // RR sections
            for (ResourceRecord rr : answers)    writeRR(buf, rr);
            for (ResourceRecord rr : authority)   writeRR(buf, rr);
            for (ResourceRecord rr : additional)  writeRR(buf, rr);

            buf.flip();
            byte[] result = new byte[buf.limit()];
            buf.get(result);
            return result;
        }

        private void writeRR(ByteBuffer buf, ResourceRecord rr) {
            writeNameBytes(buf, rr.name());
            buf.putShort((short) rr.type());
            buf.putShort((short) rr.rrClass());
            buf.putInt((int) rr.ttl());
            buf.putShort((short) rr.rdata().length);
            buf.put(rr.rdata());
        }

        private void writeNameBytes(ByteBuffer buf, String name) {
            buf.put(encodeName(name));
        }
    }

    // =========================================================================
    // Wire format helpers
    // =========================================================================

    /** Reads a DNS name (with pointer compression support) from data[pos]. */
    private static String readName(byte[] data, int[] pos, int len) {
        StringBuilder sb   = new StringBuilder();
        int           p    = pos[0];
        boolean       jumped = false;
        int           jumps  = 0;

        while (p < len) {
            int labelLen = data[p] & 0xFF;

            if (labelLen == 0) {
                if (!jumped) pos[0] = p + 1;
                break;
            }

            if ((labelLen & 0xC0) == 0xC0) {
                // Pointer compression
                if (p + 1 >= len) break;
                int ptr = ((labelLen & 0x3F) << 8) | (data[p+1] & 0xFF);
                if (!jumped) pos[0] = p + 2;
                jumped = true;
                p = ptr;
                if (++jumps > 10) break; // loop guard
                continue;
            }

            p++;
            if (p + labelLen > len) break;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(data, p, labelLen));
            p += labelLen;
        }

        if (sb.length() > 0 && sb.charAt(sb.length()-1) != '.')
            sb.append('.');

        return sb.toString().toLowerCase();
    }

    /** Encodes a DNS name to wire format (no compression). */
    static byte[] encodeName(String name) {
        if (name == null || name.equals(".")) return new byte[]{0};

        if (name.endsWith(".")) name = name.substring(0, name.length()-1);
        String[] labels = name.split("\\.");
        ByteBuffer buf  = ByteBuffer.allocate(name.length() + 2);

        for (String label : labels) {
            if (label.isEmpty()) continue;
            byte[] b = label.getBytes();
            buf.put((byte) b.length);
            buf.put(b);
        }
        buf.put((byte) 0); // root label

        buf.flip();
        byte[] result = new byte[buf.limit()];
        buf.get(result);
        return result;
    }

    private static int readUInt16(byte[] data, int[] pos) {
        int v = ((data[pos[0]] & 0xFF) << 8) | (data[pos[0]+1] & 0xFF);
        pos[0] += 2;
        return v;
    }

    private static ResourceRecord readRR(byte[] data, int[] pos, int len) {
        String name   = readName(data, pos, len);
        int    type   = readUInt16(data, pos);
        int    cls    = readUInt16(data, pos);
        long   ttl    = ((data[pos[0]] & 0xFFL) << 24)
                | ((data[pos[0]+1] & 0xFFL) << 16)
                | ((data[pos[0]+2] & 0xFFL) << 8)
                |  (data[pos[0]+3] & 0xFFL);
        pos[0] += 4;
        int    rdlen  = readUInt16(data, pos);
        int    rdataOffset = pos[0]; // offset of rdata in full message
        byte[] rdata  = new byte[rdlen];
        System.arraycopy(data, pos[0], rdata, 0, rdlen);
        pos[0] += rdlen;
        return new ResourceRecord(name, type, cls, ttl, rdata, rdataOffset);
    }

    /** Encodes a dotted IPv4 address to 4-byte wire format. */
    static byte[] encodeIPv4(String ipv4) {
        String[] parts = ipv4.split("\\.");
        return new byte[]{
                (byte) Integer.parseInt(parts[0]),
                (byte) Integer.parseInt(parts[1]),
                (byte) Integer.parseInt(parts[2]),
                (byte) Integer.parseInt(parts[3])
        };
    }

    /** Encodes a colon-separated IPv6 address to 16-byte wire format. */
    static byte[] encodeIPv6(String ipv6) {
        // Expand :: shorthand then parse
        if (ipv6.contains("::")) {
            String[] halves = ipv6.split("::", -1);
            String   left   = halves[0];
            String   right  = halves.length > 1 ? halves[1] : "";
            int leftCount   = left.isEmpty()  ? 0 : left.split(":").length;
            int rightCount  = right.isEmpty() ? 0 : right.split(":").length;
            int fill        = 8 - leftCount - rightCount;
            StringBuilder sb = new StringBuilder(left);
            for (int i = 0; i < fill; i++) sb.append(":0");
            if (!right.isEmpty()) sb.append(':').append(right);
            ipv6 = sb.toString().replaceFirst("^:", "");
        }
        String[] groups = ipv6.split(":");
        byte[]   result = new byte[16];
        for (int i = 0; i < 8; i++) {
            int val = Integer.parseInt(groups[i], 16);
            result[i*2]   = (byte)(val >> 8);
            result[i*2+1] = (byte)(val & 0xFF);
        }
        return result;
    }

    /** Encodes a string as a TXT record rdata (length-prefixed). */
    static byte[] encodeTxt(String text) {
        byte[] b = text.getBytes();
        byte[] result = new byte[b.length + 1];
        result[0] = (byte) b.length;
        System.arraycopy(b, 0, result, 1, b.length);
        return result;
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Decodes a DNS name from NS/CNAME rdata, given the full message buffer.
     * NS rdata is an encoded domain name that may use compression pointers
     * referencing earlier parts of the message — requires the full buffer.
     *
     * @param fullMessage the complete DNS message bytes
     * @param rdataOffset the offset within fullMessage where the rdata starts
     */
    public static String decodeNameFromMessage(byte[] fullMessage, int rdataOffset) {
        int[] pos = {rdataOffset};
        return readName(fullMessage, pos, fullMessage.length);
    }

    /**
     * Decodes a DNS name from standalone rdata bytes (no compression support).
     * Only use when the rdata is self-contained with no compression pointers.
     */
    public static String decodeNameFromRdata(byte[] rdata) {
        if (rdata == null || rdata.length == 0) return "";
        int[] pos = {0};
        return readName(rdata, pos, rdata.length);
    }

    /** Returns the string name for a DNS record type. */
    public static String typeName(int type) {
        return switch (type) {
            case TYPE_A     -> "A";
            case TYPE_NS    -> "NS";
            case TYPE_CNAME -> "CNAME";
            case TYPE_SOA   -> "SOA";
            case TYPE_MX    -> "MX";
            case TYPE_TXT   -> "TXT";
            case TYPE_AAAA  -> "AAAA";
            case TYPE_SRV   -> "SRV";
            case TYPE_DS    -> "DS";
            case TYPE_ANY   -> "ANY";
            default         -> "TYPE" + type;
        };
    }

    /** Returns the string name for a DNS class. */
    public static String className(int cls) {
        return cls == CLASS_IN ? "IN" : "CLASS" + cls;
    }
}