package handshake.node;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import handshake.database.Database;
import handshake.node.api.ApiRouter;
import handshake.node.api.JsonBuilder;
import handshake.node.api.RpcRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP server for the Easy Handshake node.
 *
 * Serves static web assets from src/main/resources/web/ (bundled in the JAR)
 * and a JSON REST API for node status and block data.
 *
 * Built on com.sun.net.httpserver.HttpServer — JDK built-in, zero dependencies.
 *
 * Static assets (loaded from JAR resources):
 *   /            → /web/index.html
 *   /style.css   → /web/style.css
 *   /app.js      → /web/app.js
 *
 * JSON API:
 *   GET /api/status       — node status (height, sync, uptime, db size)
 *   GET /api/block/{h}    — block info at height h
 *
 * Planned:
 *   GET  /api/name/{tld}  — Handshake name record lookup (DNS resolver)
 *   POST /dns-query       — DNS over HTTPS (DoH, RFC 8484)
 *   GET  /config          — node configuration UI
 *   GET  /wallet          — wallet UI
 */
public class NodeHttpServer {

    public static final int DEFAULT_PORT = 8888;

    /** MIME types for static files. */
    private static final Map<String, String> MIME_TYPES = Map.of(
            ".html", "text/html; charset=utf-8",
            ".css",  "text/css; charset=utf-8",
            ".js",   "application/javascript; charset=utf-8",
            ".json", "application/json",
            ".svg",  "image/svg+xml",
            ".ico",  "image/x-icon"
    );

    private final Database   db;
    private final int        port;
    private final Instant    startTime;
    private final String     version;
    private final ApiRouter  api;
    private handshake.node.dns.NameIndex nameIndex; // optional — set after DNS starts
    private final Config config;
    private HttpServer       server;

    public void setNameIndex(handshake.node.dns.NameIndex nameIndex) {
        this.nameIndex = nameIndex;
    }

    public NodeHttpServer(Database db, int port, String version) {
        this.db        = db;
        this.port      = port;
        this.version   = version;
        this.startTime = Instant.now();
        this.api       = new ApiRouter(db, version, startTime);
        this.config    = Config.load();
    }

    public NodeHttpServer(Database db) {
        this(db, DEFAULT_PORT, "1.0.0");
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start() throws IOException {
        String bind = config.httpBind();
        server = HttpServer.create(new InetSocketAddress(bind, port), 0);
        System.out.println("[HTTP] Binding to " + bind + ":" + port);

        // JSON-RPC dispatcher (POST /)
        server.createContext("/", exchange -> {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                new RpcHandler().handle(exchange);
            } else {
                new StaticHandler().handle(exchange);
            }
        });

        // REST API routes
        server.createContext("/api/status",          new StatusHandler());
        server.createContext("/api/block/",          new BlockHandler());
        server.createContext("/api/events",          new SseHandler());
        server.createContext("/api/nameindex",       new NameIndexStatusHandler());
        server.createContext("/api/config",          new ConfigHandler());
        server.createContext("/api/peers",           new PeersHandler());
        server.createContext("/block/",              new RestBlockHandler());
        server.createContext("/header/",             new RestHeaderHandler());
        server.createContext("/tx/",                 new RestTxHandler());
        server.createContext("/coin/",               new RestCoinHandler());

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        System.out.println("[HTTP] Dashboard: http://localhost:" + port);
        System.out.println("[HTTP] API:       http://localhost:" + port + "/api/status");
        System.out.println("[HTTP] RPC:       http://localhost:" + port + " (POST)");
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
            System.out.println("[HTTP] Server stopped.");
        }
    }

    // -------------------------------------------------------------------------
    // GET /api/status
    // -------------------------------------------------------------------------

    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }

            int    headerTip  = db.getTipHeight();
            int    blockTip   = db.getBlockDataTip();
            long   dbBytes    = db.getStoreSize();
            long   uptimeSecs = Duration.between(startTime, Instant.now()).getSeconds();
            boolean synced    = blockTip >= headerTip - 2;

            String json = String.format("""
                    {
                      "version": "%s",
                      "height": %d,
                      "blockTip": %d,
                      "synced": %b,
                      "uptimeSeconds": %d,
                      "dbSizeBytes": %d,
                      "dbSizeGB": %.2f
                    }""",
                    version, headerTip, blockTip, synced,
                    uptimeSecs, dbBytes, dbBytes / 1_073_741_824.0);

            sendText(exchange, 200, "application/json", json);
        }
    }

    // -------------------------------------------------------------------------
    // GET /api/block/{height}
    // -------------------------------------------------------------------------

    private class BlockHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }

            String[] parts = exchange.getRequestURI().getPath().split("/");
            if (parts.length < 4) {
                sendText(exchange, 400, "application/json",
                        "{\"error\": \"Usage: /api/block/{height}\"}");
                return;
            }

            int height;
            try {
                height = Integer.parseInt(parts[3]);
            } catch (NumberFormatException e) {
                sendText(exchange, 400, "application/json",
                        "{\"error\": \"Invalid height — must be an integer\"}");
                return;
            }

            byte[] rawBlock = db.getRawBlock(height);
            if (rawBlock == null) {
                sendText(exchange, 404, "application/json",
                        "{\"error\": \"Block not found at height " + height + "\"}");
                return;
            }

            byte[] hash      = db.getHashAtHeight(height);
            byte[] headerRaw = db.getHeaderAtHeight(height);

            HNSPeer.BlockHeader header = headerRaw != null
                    ? HNSPeer.BlockHeader.parse(headerRaw, 0) : null;
            HNSBlock block = HNSBlock.parse(rawBlock);

            String json = String.format("""
                    {
                      "height": %d,
                      "hash": "%s",
                      "time": %d,
                      "bits": "%s",
                      "txCount": %d,
                      "sizeBytes": %d
                    }""",
                    height,
                    hash != null ? toHex(hash) : "unknown",
                    header != null ? header.time : 0,
                    header != null ? "0x" + Integer.toHexString(header.bits) : "unknown",
                    block.txs.size(),
                    rawBlock.length);

            sendText(exchange, 200, "application/json", json);
        }
    }

    // -------------------------------------------------------------------------
    // Static file handler — serves from JAR resources under /web/
    // -------------------------------------------------------------------------

    private static class StaticHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }

            String path = exchange.getRequestURI().getPath();

            // Map URL paths to resource paths
            String resource = switch (path) {
                case "/", "/index.html" -> "/web/index.html";
                case "/style.css"       -> "/web/style.css";
                case "/app.js"          -> "/web/app.js";
                case "/favicon.ico"     -> "/web/favicon.ico";
                case "/favicon.svg"     -> "/web/favicon.svg";
                case "/hns-logo.svg"    -> "/web/hns-logo.svg";
                default                 -> null;
            };

            if (resource == null) {
                sendText(exchange, 404, "text/plain", "404 Not Found: " + path);
                return;
            }

            byte[] bytes = loadResource(resource);
            if (bytes == null) {
                sendText(exchange, 500, "text/plain",
                        "Resource not found in JAR: " + resource);
                return;
            }

            String ext  = resource.substring(resource.lastIndexOf('.'));
            String mime = MIME_TYPES.getOrDefault(ext, "application/octet-stream");
            sendBytes(exchange, 200, mime, bytes);
        }

        private byte[] loadResource(String path) {
            try (InputStream is = NodeHttpServer.class.getResourceAsStream(path)) {
                return is != null ? is.readAllBytes() : null;
            } catch (IOException e) {
                return null;
            }
        }
    }

    // -------------------------------------------------------------------------
    // HTTP helpers
    // -------------------------------------------------------------------------

    private static boolean isNotGet(HttpExchange exchange) {
        return !"GET".equalsIgnoreCase(exchange.getRequestMethod());
    }

    private static void methodNotAllowed(HttpExchange exchange) throws IOException {
        sendText(exchange, 405, "text/plain", "Method Not Allowed");
    }

    private static void sendText(HttpExchange exchange, int code,
                                 String contentType, String body)
            throws IOException {
        sendBytes(exchange, code, contentType,
                body.getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBytes(HttpExchange exchange, int code,
                                  String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache");
        exchange.sendResponseHeaders(code, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    // -------------------------------------------------------------------------
    // POST / — JSON-RPC dispatcher
    // -------------------------------------------------------------------------

    private class RpcHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String body = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8);
                RpcRequest req = RpcRequest.parse(body);
                String response = api.rpc(req.method, req.params, req.id);
                sendText(exchange, 200, "application/json", response);
            } catch (Exception e) {
                String err = "{\"id\":null,\"result\":null,\"error\":"
                        + "{\"message\":" + JsonBuilder.q(e.getMessage())
                        + ",\"code\":-32700}}";
                sendText(exchange, 400, "application/json", err);
            }
        }
    }

    // -------------------------------------------------------------------------
    // GET /block/:hashOrHeight
    // -------------------------------------------------------------------------

    private class RestBlockHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }
            String[] parts = exchange.getRequestURI().getPath().split("/");
            if (parts.length < 3) {
                sendText(exchange, 400, "application/json",
                        JsonBuilder.error("Usage: /block/:hashOrHeight", -8));
                return;
            }
            String query = exchange.getRequestURI().getQuery();
            boolean details = query == null || !query.contains("verbose=0");
            sendText(exchange, 200, "application/json",
                    api.getBlock(parts[2], details));
        }
    }

    // -------------------------------------------------------------------------
    // GET /header/:hashOrHeight
    // -------------------------------------------------------------------------

    private class RestHeaderHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }
            String[] parts = exchange.getRequestURI().getPath().split("/");
            if (parts.length < 3) {
                sendText(exchange, 400, "application/json",
                        JsonBuilder.error("Usage: /header/:hashOrHeight", -8));
                return;
            }
            sendText(exchange, 200, "application/json",
                    api.getHeader(parts[2]));
        }
    }

    // -------------------------------------------------------------------------
    // GET /tx/:txhash
    // -------------------------------------------------------------------------

    private class RestTxHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }
            String[] parts = exchange.getRequestURI().getPath().split("/");
            if (parts.length < 3) {
                sendText(exchange, 400, "application/json",
                        JsonBuilder.error("Usage: /tx/:txhash", -8));
                return;
            }
            sendText(exchange, 200, "application/json",
                    api.getTx(parts[2]));
        }
    }

    // -------------------------------------------------------------------------
    // GET /coin/:txhash/:index
    // -------------------------------------------------------------------------

    private class RestCoinHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (isNotGet(exchange)) { methodNotAllowed(exchange); return; }
            String[] parts = exchange.getRequestURI().getPath().split("/");
            if (parts.length < 4) {
                sendText(exchange, 400, "application/json",
                        JsonBuilder.error("Usage: /coin/:txhash/:index", -8));
                return;
            }
            try {
                int index = Integer.parseInt(parts[3]);
                sendText(exchange, 200, "application/json",
                        api.getCoin(parts[2], index));
            } catch (NumberFormatException e) {
                sendText(exchange, 400, "application/json",
                        JsonBuilder.error("Invalid index", -8));
            }
        }
    }

    // ── GET /api/events — Server-Sent Events live stream ─────────────────────

    private class SseHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            String path = exchange.getRequestURI().getPath();

            // GET /api/events/history?cat=BLOCK&limit=100
            if (path.endsWith("/history")) {
                handleHistory(exchange);
                return;
            }

            // GET /api/events — live SSE stream
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control",  "no-cache");
            exchange.getResponseHeaders().set("Connection",     "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, 0); // chunked

            java.io.PrintWriter writer = new java.io.PrintWriter(
                    exchange.getResponseBody(), true);

            // Send a heartbeat comment to establish the connection
            writer.print(": connected\n\n");
            writer.flush();

            EventBus.SseClient client = new EventBus.SseClient(writer);
            EventBus.get().addClient(client);

            // Keep connection open until client disconnects
            try {
                while (client.isActive()) {
                    Thread.sleep(15_000);
                    // Send SSE heartbeat comment to keep connection alive
                    writer.print(": heartbeat\n\n");
                    writer.flush();
                    if (writer.checkError()) break;
                }
            } catch (InterruptedException ignored) {
            } finally {
                EventBus.get().removeClient(client);
                exchange.close();
            }
        }

        private void handleHistory(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            String query = exchange.getRequestURI().getQuery();
            EventBus.Category filter = null;
            int limit = 200;

            if (query != null) {
                for (String param : query.split("&")) {
                    String[] kv = param.split("=", 2);
                    if (kv.length == 2) {
                        if (kv[0].equals("cat")) {
                            try { filter = EventBus.Category.valueOf(kv[1]); }
                            catch (Exception ignored) {}
                        } else if (kv[0].equals("limit")) {
                            try { limit = Math.min(1000, Integer.parseInt(kv[1])); }
                            catch (Exception ignored) {}
                        }
                    }
                }
            }

            var events = EventBus.get().getHistory(filter, limit);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < events.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(events.get(i).toJson());
            }
            sb.append("]");

            byte[] body = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        }
    }

    // ── GET /api/peers — peer scores and status ───────────────────────────────

    private class PeersHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            byte[] body = PeerScorecard.get().toJson()
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        }
    }

    // ── GET /api/config — read config / POST to update ───────────────────────

    private class ConfigHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Return full config + module status as JSON
                StringBuilder sb = new StringBuilder("{");
                sb.append("\"settings\":").append(config.toJson()).append(",");
                sb.append("\"modules\":[");
                boolean first = true;
                for (Config.Module m : Config.Module.values()) {
                    if (!first) sb.append(",");
                    sb.append("{")
                            .append("\"id\":\"").append(m.name()).append("\",")
                            .append("\"name\":\"").append(m.displayName).append("\",")
                            .append("\"desc\":\"").append(m.description).append("\",")
                            .append("\"icon\":\"").append(m.icon).append("\",")
                            .append("\"enabled\":").append(config.isEnabled(m))
                            .append("}");
                    first = false;
                }
                sb.append("]}");
                byte[] body = sb.toString()
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();

            } else if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Update a single config value
                // Body: {"key":"dns.recursive.port","value":"5350"}
                String body = new String(exchange.getRequestBody().readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8);
                String key   = extractJsonString(body, "key");
                String value = extractJsonString(body, "value");
                if (key != null && value != null) {
                    config.set(key, value);
                    byte[] resp = "{\"ok\":true}".getBytes();
                    exchange.getResponseHeaders().set("Content-Type","application/json");
                    exchange.sendResponseHeaders(200, resp.length);
                    exchange.getResponseBody().write(resp);
                } else {
                    byte[] resp = "{\"ok\":false,\"error\":\"missing key or value\"}"
                            .getBytes();
                    exchange.getResponseHeaders().set("Content-Type","application/json");
                    exchange.sendResponseHeaders(400, resp.length);
                    exchange.getResponseBody().write(resp);
                }
                exchange.close();
            } else {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
            }
        }

        private String extractJsonString(String json, String key) {
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start < 0) return null;
            start += search.length();
            int end = json.indexOf("\"", start);
            if (end < 0) return null;
            return json.substring(start, end);
        }
    }

    // ── GET /api/nameindex — name index build status ──────────────────────────

    private class NameIndexStatusHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            String json;
            if (nameIndex == null) {
                json = "{\"ready\":false,\"progress\":0,\"total\":0,"
                        + "\"names\":0,\"pct\":0,\"eta\":-1}";
            } else {
                boolean ready    = nameIndex.isReady();
                int     progress = nameIndex.getBuildProgress();
                int     total    = nameIndex.getBuildTip();
                int     names    = nameIndex.size();
                int     pct      = total > 0 ? (int)(100.0 * progress / total) : (ready ? 100 : 0);
                long    eta      = nameIndex.getEtaSeconds();
                json = String.format(
                        "{\"ready\":%b,\"progress\":%d,\"total\":%d,"
                                + "\"names\":%d,\"pct\":%d,\"eta\":%d}",
                        ready, progress, total, names, pct, eta);
            }
            byte[] body = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}