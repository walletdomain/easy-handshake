package handshake.node;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal JSON-RPC request parser.
 *
 * Parses {"method":"...","params":[...],"id":...} without any
 * external JSON library. Handles strings, numbers, booleans, and null
 * in the params array. Nested objects in params are not supported
 * (not needed for any Handshake RPC calls we implement).
 */
public class RpcRequest {

    public final String       method;
    public final List<Object> params;
    public final Object       id;

    private RpcRequest(String method, List<Object> params, Object id) {
        this.method = method;
        this.params = params;
        this.id     = id;
    }

    /**
     * Parses a JSON-RPC request body.
     * @throws IllegalArgumentException if the JSON is malformed or missing method
     */
    public static RpcRequest parse(String body) {
        if (body == null || body.isBlank())
            throw new IllegalArgumentException("Empty request body");

        String method = extractMethod(body);
        if (method == null)
            throw new IllegalArgumentException("Missing 'method' field");

        List<Object> params = extractParams(body);
        Object id           = extractId(body);

        return new RpcRequest(method, params, id);
    }

    // -------------------------------------------------------------------------
    // Extractors
    // -------------------------------------------------------------------------

    private static String extractMethod(String json) {
        String search = "\"method\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int start = skipWhitespace(json, colon + 1);
        if (start >= json.length() || json.charAt(start) != '"') return null;
        return (String) readString(json, start).value;
    }

    private static List<Object> extractParams(String json) {
        String search = "\"params\"";
        int idx = json.indexOf(search);
        if (idx < 0) return new ArrayList<>();
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return new ArrayList<>();
        int start = skipWhitespace(json, colon + 1);
        if (start >= json.length() || json.charAt(start) != '[')
            return new ArrayList<>();
        return readArray(json, start);
    }

    private static Object extractId(String json) {
        String search = "\"id\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int start = skipWhitespace(json, colon + 1);
        if (start >= json.length()) return null;
        return readValue(json, start).value;
    }

    // -------------------------------------------------------------------------
    // Value readers
    // -------------------------------------------------------------------------

    private record Token(Object value, int end) {}

    private static List<Object> readArray(String json, int start) {
        List<Object> list = new ArrayList<>();
        int i = start + 1; // skip '['
        while (i < json.length()) {
            i = skipWhitespace(json, i);
            if (i >= json.length()) break;
            char c = json.charAt(i);
            if (c == ']') break;
            if (c == ',') { i++; continue; }
            Token tok = readValue(json, i);
            list.add(tok.value);
            i = tok.end;
        }
        return list;
    }

    private static Token readValue(String json, int i) {
        i = skipWhitespace(json, i);
        if (i >= json.length()) return new Token(null, i);
        char c = json.charAt(i);

        if (c == '"')  return readString(json, i);
        if (c == '[')  return new Token(readArray(json, i), findArrayEnd(json, i));
        if (c == 't')  return new Token(Boolean.TRUE,  i + 4);
        if (c == 'f')  return new Token(Boolean.FALSE, i + 5);
        if (c == 'n')  return new Token(null,           i + 4);

        // Number
        int end = i;
        while (end < json.length()) {
            char ch = json.charAt(end);
            if (ch == ',' || ch == ']' || ch == '}' || ch == ' '
                    || ch == '\n' || ch == '\r' || ch == '\t') break;
            end++;
        }
        String num = json.substring(i, end).trim();
        try {
            if (num.contains(".")) return new Token(Double.parseDouble(num), end);
            return new Token(Long.parseLong(num), end);
        } catch (NumberFormatException e) {
            return new Token(num, end);
        }
    }

    private static Token readString(String json, int start) {
        StringBuilder sb = new StringBuilder();
        int i = start + 1; // skip opening quote
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(i + 1);
                switch (next) {
                    case '"'  -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case 'n'  -> sb.append('\n');
                    case 'r'  -> sb.append('\r');
                    case 't'  -> sb.append('\t');
                    default   -> sb.append(next);
                }
                i += 2;
            } else if (c == '"') {
                return new Token(sb.toString(), i + 1);
            } else {
                sb.append(c);
                i++;
            }
        }
        return new Token(sb.toString(), i);
    }

    private static int findArrayEnd(String json, int start) {
        int depth = 0, i = start;
        while (i < json.length()) {
            char c = json.charAt(i);
            if      (c == '[') depth++;
            else if (c == ']') { depth--; if (depth == 0) return i + 1; }
            else if (c == '"') i = readString(json, i).end - 1;
            i++;
        }
        return i;
    }

    private static int skipWhitespace(String json, int i) {
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        return i;
    }
}