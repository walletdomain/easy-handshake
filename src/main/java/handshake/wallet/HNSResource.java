package handshake.wallet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Encodes Handshake DNS resource records into the 512-byte blob
 * used in UPDATE covenant transactions.
 *
 * Wire format (from hsd lib/dns/resource.js and lib/dns/common.js):
 *
 *   version(1) = 0x00
 *   [type(1) + record_data]*
 *
 * Type codes (hsTypes from common.js):
 *   DS=0, NS=1, GLUE4=2, GLUE6=3, SYNTH4=4, SYNTH6=5, TXT=6
 *
 * Record data formats:
 *   DS:     keyTag(2 BE) + algorithm(1) + digestType(1) + len(1) + digest
 *   NS:     name (DNS wire format, uncompressed)
 *   GLUE4:  name + ipv4(4)
 *   GLUE6:  name + ipv6(16)
 *   SYNTH4: ipv4(4)
 *   SYNTH6: ipv6(16)
 *   TXT:    count(1) + [len(1) + str]*
 *
 * DNS name wire format: sequence of labels, each prefixed by length byte,
 * terminated by 0x00. e.g. "ns1.example.com." → 03ns101example03com00
 */
public class HNSResource {

    public static final int HS_DS     = 0;
    public static final int HS_NS     = 1;
    public static final int HS_GLUE4  = 2;
    public static final int HS_GLUE6  = 3;
    public static final int HS_SYNTH4 = 4;
    public static final int HS_SYNTH6 = 5;
    public static final int HS_TXT    = 6;

    public static final int MAX_RESOURCE_SIZE = 512;

    // ── Record types ──────────────────────────────────────────────────────────

    public interface Record {
        int type();
        void write(ByteArrayOutputStream bos) throws IOException;
        String toJson();
    }

    public static class NSRecord implements Record {
        public final String ns; // FQDN with trailing dot e.g. "ns1.example.com."
        public NSRecord(String ns) { this.ns = ns; }
        public int type() { return HS_NS; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            writeDnsName(bos, ns);
        }
        public String toJson() {
            return "{\"type\":\"NS\",\"ns\":" + jsonStr(ns) + "}";
        }
    }

    public static class GLUE4Record implements Record {
        public final String ns;
        public final String address; // IPv4
        public GLUE4Record(String ns, String address) {
            this.ns = ns; this.address = address;
        }
        public int type() { return HS_GLUE4; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            writeDnsName(bos, ns);
            bos.write(parseIPv4(address));
        }
        public String toJson() {
            return "{\"type\":\"GLUE4\",\"ns\":" + jsonStr(ns)
                    + ",\"address\":" + jsonStr(address) + "}";
        }
    }

    public static class GLUE6Record implements Record {
        public final String ns;
        public final String address; // IPv6
        public GLUE6Record(String ns, String address) {
            this.ns = ns; this.address = address;
        }
        public int type() { return HS_GLUE6; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            writeDnsName(bos, ns);
            bos.write(parseIPv6(address));
        }
        public String toJson() {
            return "{\"type\":\"GLUE6\",\"ns\":" + jsonStr(ns)
                    + ",\"address\":" + jsonStr(address) + "}";
        }
    }

    public static class SYNTH4Record implements Record {
        public final String address; // IPv4
        public SYNTH4Record(String address) { this.address = address; }
        public int type() { return HS_SYNTH4; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            bos.write(parseIPv4(address));
        }
        public String toJson() {
            return "{\"type\":\"SYNTH4\",\"address\":" + jsonStr(address) + "}";
        }
    }

    public static class SYNTH6Record implements Record {
        public final String address; // IPv6
        public SYNTH6Record(String address) { this.address = address; }
        public int type() { return HS_SYNTH6; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            bos.write(parseIPv6(address));
        }
        public String toJson() {
            return "{\"type\":\"SYNTH6\",\"address\":" + jsonStr(address) + "}";
        }
    }

    public static class DSRecord implements Record {
        public final int    keyTag;
        public final int    algorithm;
        public final int    digestType;
        public final byte[] digest;
        public DSRecord(int keyTag, int algorithm, int digestType, byte[] digest) {
            this.keyTag = keyTag; this.algorithm = algorithm;
            this.digestType = digestType; this.digest = digest;
        }
        public int type() { return HS_DS; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            bos.write((keyTag >> 8) & 0xFF);
            bos.write(keyTag & 0xFF);
            bos.write(algorithm & 0xFF);
            bos.write(digestType & 0xFF);
            bos.write(digest.length & 0xFF);
            bos.write(digest);
        }
        public String toJson() {
            return "{\"type\":\"DS\",\"keyTag\":" + keyTag
                    + ",\"algorithm\":" + algorithm
                    + ",\"digestType\":" + digestType
                    + ",\"digest\":" + jsonStr(toHex(digest)) + "}";
        }
    }

    public static class TXTRecord implements Record {
        public final List<String> txt;
        public TXTRecord(List<String> txt) { this.txt = txt; }
        public TXTRecord(String... entries) {
            this.txt = new ArrayList<>();
            for (String s : entries) this.txt.add(s);
        }
        public int type() { return HS_TXT; }
        public void write(ByteArrayOutputStream bos) throws IOException {
            bos.write(txt.size() & 0xFF);
            for (String s : txt) {
                byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                bos.write(b.length & 0xFF);
                bos.write(b);
            }
        }
        public String toJson() {
            StringBuilder sb = new StringBuilder("{\"type\":\"TXT\",\"txt\":[");
            for (int i = 0; i < txt.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(jsonStr(txt.get(i)));
            }
            return sb.append("]}").toString();
        }
    }

    // ── Resource encoder ──────────────────────────────────────────────────────

    /**
     * Encodes a list of records into the Handshake resource blob.
     * Returns bytes to be used as UPDATE covenant items[2].
     */
    public static byte[] encode(List<Record> records) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0x00); // version
        for (Record r : records) {
            bos.write(r.type());
            r.write(bos);
        }
        byte[] result = bos.toByteArray();
        if (result.length > MAX_RESOURCE_SIZE)
            throw new IllegalArgumentException(
                    "Resource too large: " + result.length + " > " + MAX_RESOURCE_SIZE);
        return result;
    }

    /**
     * Decodes a resource blob back into records.
     */
    public static List<Record> decode(byte[] data) {
        List<Record> records = new ArrayList<>();
        if (data == null || data.length == 0) return records;
        int pos = 0;
        if (data[pos++] != 0x00) return records; // unknown version
        while (pos < data.length) {
            int type = data[pos++] & 0xFF;
            try {
                switch (type) {
                    case HS_NS: {
                        int[] end = {pos};
                        String ns = readDnsName(data, end);
                        pos = end[0];
                        records.add(new NSRecord(ns));
                        break;
                    }
                    case HS_GLUE4: {
                        int[] end = {pos};
                        String ns = readDnsName(data, end);
                        pos = end[0];
                        String addr = readIPv4(data, pos); pos += 4;
                        records.add(new GLUE4Record(ns, addr));
                        break;
                    }
                    case HS_GLUE6: {
                        int[] end = {pos};
                        String ns = readDnsName(data, end);
                        pos = end[0];
                        String addr = readIPv6(data, pos); pos += 16;
                        records.add(new GLUE6Record(ns, addr));
                        break;
                    }
                    case HS_SYNTH4: {
                        String addr = readIPv4(data, pos); pos += 4;
                        records.add(new SYNTH4Record(addr));
                        break;
                    }
                    case HS_SYNTH6: {
                        String addr = readIPv6(data, pos); pos += 16;
                        records.add(new SYNTH6Record(addr));
                        break;
                    }
                    case HS_DS: {
                        int keyTag = ((data[pos] & 0xFF) << 8) | (data[pos+1] & 0xFF);
                        int alg = data[pos+2] & 0xFF;
                        int dt  = data[pos+3] & 0xFF;
                        int len = data[pos+4] & 0xFF;
                        pos += 5;
                        byte[] digest = java.util.Arrays.copyOfRange(data, pos, pos + len);
                        pos += len;
                        records.add(new DSRecord(keyTag, alg, dt, digest));
                        break;
                    }
                    case HS_TXT: {
                        int count = data[pos++] & 0xFF;
                        List<String> txts = new ArrayList<>();
                        for (int i = 0; i < count; i++) {
                            int slen = data[pos++] & 0xFF;
                            txts.add(new String(data, pos, slen,
                                    java.nio.charset.StandardCharsets.UTF_8));
                            pos += slen;
                        }
                        records.add(new TXTRecord(txts));
                        break;
                    }
                    default:
                        return records; // unknown type, stop
                }
            } catch (Exception e) {
                break; // malformed, stop
            }
        }
        return records;
    }

    /** Encodes records as a JSON array string. */
    public static String toJson(List<Record> records) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(records.get(i).toJson());
        }
        return sb.append("]").toString();
    }

    // ── DNS name encoding ─────────────────────────────────────────────────────

    /**
     * Writes a DNS name in wire format (uncompressed).
     * "ns1.example.com." → 03 6e73 31 07 65 78 61 6d 70 6c 65 03 636f6d 00
     */
    static void writeDnsName(ByteArrayOutputStream bos, String name) throws IOException {
        if (name == null || name.isEmpty() || name.equals(".")) {
            bos.write(0); // root
            return;
        }
        // Remove trailing dot if present
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        String[] labels = name.split("\\.");
        for (String label : labels) {
            byte[] lb = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (lb.length > 63) throw new IllegalArgumentException(
                    "DNS label too long: " + label);
            bos.write(lb.length);
            bos.write(lb);
        }
        bos.write(0); // root terminator
    }

    static String readDnsName(byte[] data, int[] pos) {
        StringBuilder sb = new StringBuilder();
        while (pos[0] < data.length) {
            int len = data[pos[0]++] & 0xFF;
            if (len == 0) break;
            if (len >= 0xC0) { // pointer — skip
                pos[0]++; break;
            }
            if (sb.length() > 0) sb.append(".");
            sb.append(new String(data, pos[0], len,
                    java.nio.charset.StandardCharsets.UTF_8));
            pos[0] += len;
        }
        sb.append(".");
        return sb.toString();
    }

    // ── IP address helpers ────────────────────────────────────────────────────

    static byte[] parseIPv4(String addr) {
        try {
            return Inet4Address.getByName(addr).getAddress();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid IPv4: " + addr);
        }
    }

    static byte[] parseIPv6(String addr) {
        try {
            return Inet6Address.getByName(addr).getAddress();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid IPv6: " + addr);
        }
    }

    static String readIPv4(byte[] data, int pos) throws Exception {
        return InetAddress.getByAddress(
                java.util.Arrays.copyOfRange(data, pos, pos + 4)).getHostAddress();
    }

    static String readIPv6(byte[] data, int pos) throws Exception {
        return InetAddress.getByAddress(
                java.util.Arrays.copyOfRange(data, pos, pos + 16)).getHostAddress();
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
        return b;
    }

    static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private HNSResource() {}
}