package handshake.node.api;

/**
 * Shared JSON building utilities for all API classes.
 * No external library needed — simple string concatenation
 * is sufficient for our structured API responses.
 */
public class JsonBuilder {

    private JsonBuilder() {} // static utility class

    /** Builds a JSON object from alternating key/value string pairs. */
    public static String json(String... kv) {
        if (kv.length % 2 != 0)
            throw new IllegalArgumentException("kv must be pairs");
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append('"').append(kv[i]).append("\":").append(kv[i+1]);
        }
        return sb.append('}').toString();
    }

    /** Wraps a string in JSON quotes, escaping special characters. */
    public static String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n") + "\"";
    }

    /** Returns a raw JSON fragment (number, boolean, array, nested object). */
    public static String raw(String s) { return s; }

    /** Converts a value to its JSON string representation. */
    public static String str(Object v) {
        if (v instanceof Double d) return String.format("%.8f", d);
        return v.toString();
    }

    /** Returns a JSON error object. */
    public static String error(String msg, int code) {
        return json("error", raw(json("message", q(msg), "code", str(code))));
    }

    /** Builds a full JSON-RPC success response. */
    public static String rpcResponse(String result, Object id) {
        return "{\"id\":" + jsonId(id)
                + ",\"result\":" + result + ",\"error\":null}";
    }

    /** Builds a full JSON-RPC error response. */
    public static String rpcError(String msg, int code, Object id) {
        return "{\"id\":" + jsonId(id) + ",\"result\":null,\"error\":"
                + json("message", q(msg), "code", str(code)) + "}";
    }

    private static String jsonId(Object id) {
        if (id == null)           return "null";
        if (id instanceof Number) return id.toString();
        return q(id.toString());
    }

    // ── Byte / hex helpers ────────────────────────────────────────────────────

    public static String toHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) return null;
        try {
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < b.length; i++)
                b[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
            return b;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static int toInt(Object v) {
        if (v instanceof Number n) return n.intValue();
        try { return Integer.parseInt(v.toString()); }
        catch (NumberFormatException e) {
            throw new RpcException("Expected integer, got: " + v, -8);
        }
    }

    // ── RPC exception ─────────────────────────────────────────────────────────

    public static class RpcException extends RuntimeException {
        public final int code;
        public RpcException(String msg, int code) {
            super(msg);
            this.code = code;
        }
    }
}