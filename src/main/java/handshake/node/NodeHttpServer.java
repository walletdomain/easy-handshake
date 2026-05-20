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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
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
    private handshake.wallet.WalletManager walletManager; // optional — set if wallet enabled
    private final Config config;
    private HttpServer       server;

    public void setNameIndex(handshake.node.dns.NameIndex nameIndex) {
        this.nameIndex = nameIndex;
    }

    public void setWalletManager(handshake.wallet.WalletManager wm) {
        this.walletManager = wm;
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
        server.createContext("/api/wallet",          new WalletHandler());
        server.createContext("/wallet",              new StaticHandler());
        server.createContext("/api/status",          new StatusHandler());
        server.createContext("/api/block/",          new BlockHandler());
        server.createContext("/api/events",          new SseHandler());
        server.createContext("/api/nameindex",       new NameIndexStatusHandler());
        server.createContext("/api/config",          new ConfigHandler());
        server.createContext("/api/peers",           new PeersHandler());
        server.createContext("/api/seeds",           new SeedsHandler());
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
                case "/", "/index.html"  -> "/web/index.html";
                case "/style.css"        -> "/web/style.css";
                case "/app.js"           -> "/web/app.js";
                case "/settings",
                     "/settings.html"    -> "/web/settings.html";
                case "/settings.js"      -> "/web/settings.js";
                case "/wallet",
                     "/wallet.html"      -> "/web/wallet.html";
                case "/wallet.js"        -> "/web/wallet.js";
                case "/favicon.ico"      -> "/web/favicon.ico";
                case "/favicon.svg"      -> "/web/favicon.svg";
                case "/hns-logo.svg"     -> "/web/hns-logo.svg";
                default                  -> null;
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

    // ── /api/wallet — wallet REST API ─────────────────────────────────────────
    //
    // GET  /api/wallet              → list all wallets + lock status
    // GET  /api/wallet/{id}         → wallet details, addresses, balance, names
    // POST /api/wallet/create       → create new wallet
    // POST /api/wallet/restore      → restore from mnemonic
    // POST /api/wallet/{id}/unlock  → unlock wallet
    // POST /api/wallet/{id}/lock    → lock wallet
    // GET  /api/wallet/{id}/address → next receive address
    // GET  /api/wallet/{id}/names   → owned names

    private class WalletHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");

            if (walletManager == null) {
                // Lazily initialize wallet manager when first accessed
                // (covers the case where wallet was enabled after startup)
                walletManager = handshake.wallet.WalletManager.get();
            }

            String path   = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();
            String body   = method.equals("POST")
                    ? new String(exchange.getRequestBody().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8)
                    : "";

            try {
                // POST /api/wallet/create
                if (path.endsWith("/create") && method.equals("POST")) {
                    handleCreate(exchange, body);
                    // POST /api/wallet/restore
                } else if (path.endsWith("/restore") && method.equals("POST")) {
                    handleRestore(exchange, body);
                    // GET /api/wallet
                } else if (path.equals("/api/wallet") && method.equals("GET")) {
                    handleList(exchange);
                    // POST /api/wallet/{id}/unlock
                } else if (path.endsWith("/unlock") && method.equals("POST")) {
                    String id = extractWalletId(path, "/unlock");
                    handleUnlock(exchange, id, body);
                    // POST /api/wallet/{id}/lock
                } else if (path.endsWith("/lock") && method.equals("POST")) {
                    String id = extractWalletId(path, "/lock");
                    walletManager.lock(id);
                    sendJson(exchange, 200, "{\"ok\":true}");
                    // GET /api/wallet/{id}/address
                } else if (path.endsWith("/address") && method.equals("GET")) {
                    String id = extractWalletId(path, "/address");
                    String addr = walletManager.getNextReceiveAddress(id);
                    sendJson(exchange, 200,
                            "{\"address\":\"" + addr + "\"}");
                    // GET /api/wallet/{id}/names
                } else if (path.endsWith("/names") && method.equals("GET")) {
                    String id = extractWalletId(path, "/names");
                    sendJson(exchange, 200, namesToJson(id));
                    // GET /api/wallet/{id}
                } else if (method.equals("GET")) {
                    String id = path.substring("/api/wallet/".length());
                    handleDetail(exchange, id);
                } else {
                    sendJson(exchange, 404, "{\"error\":\"Not found\"}");
                }
            } catch (IllegalStateException e) {
                // Wallet locked
                sendJson(exchange, 403,
                        "{\"error\":\"" + e.getMessage() + "\",\"locked\":true}");
            } catch (Exception e) {
                sendJson(exchange, 500,
                        "{\"error\":\"" + e.getMessage().replace("\"","'") + "\"}");
            }
        }

        private void handleList(com.sun.net.httpserver.HttpExchange ex)
                throws IOException {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (var w : walletManager.getAllWallets()) {
                if (!first) sb.append(",");
                sb.append(walletToJson(w));
                first = false;
            }
            sb.append("]");
            sendJson(ex, 200, sb.toString());
        }

        private void handleDetail(com.sun.net.httpserver.HttpExchange ex,
                                  String id) throws IOException {
            var wallet = walletManager.getAllWallets().stream()
                    .filter(w -> w.id.equals(id)).findFirst().orElse(null);
            if (wallet == null) {
                sendJson(ex, 404, "{\"error\":\"Wallet not found\"}");
                return;
            }
            boolean unlocked = walletManager.isUnlocked(id);
            long balance     = walletManager.getBalance(id);
            var addrs        = walletManager.getAddresses(id);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"wallet\":").append(walletToJson(wallet));
            sb.append(",\"unlocked\":").append(unlocked);
            sb.append(",\"balance\":").append(balance);
            sb.append(",\"addresses\":[");
            boolean first = true;
            for (var a : addrs) {
                if (!first) sb.append(",");
                sb.append(a.toJson());
                first = false;
            }
            sb.append("]}");
            sendJson(ex, 200, sb.toString());
        }

        private void handleCreate(com.sun.net.httpserver.HttpExchange ex,
                                  String body) throws Exception {
            String name     = extractJsonString(body, "name");
            String password = extractJsonString(body, "password");
            String words    = extractJsonString(body, "words");
            if (name == null || password == null) {
                sendJson(ex, 400, "{\"error\":\"name and password required\"}");
                return;
            }
            boolean use24 = !"12".equals(words);
            var result = walletManager.createWallet(
                    name, password.toCharArray(), use24);
            sendJson(ex, 200, String.format(
                    "{\"ok\":true,\"walletId\":\"%s\",\"mnemonic\":\"%s\"}",
                    result.walletId(), result.mnemonic()));
        }

        private void handleRestore(com.sun.net.httpserver.HttpExchange ex,
                                   String body) throws Exception {
            String name       = extractJsonString(body, "name");
            String mnemonic   = extractJsonString(body, "mnemonic");
            String password   = extractJsonString(body, "password");
            String passphrase = extractJsonString(body, "passphrase");
            if (name == null || mnemonic == null || password == null) {
                sendJson(ex, 400,
                        "{\"error\":\"name, mnemonic and password required\"}");
                return;
            }
            var result = walletManager.restoreWallet(
                    name, mnemonic, password.toCharArray(),
                    passphrase != null ? passphrase : "");
            sendJson(ex, 200, String.format(
                    "{\"ok\":true,\"walletId\":\"%s\"}",
                    result.walletId()));
        }

        private void handleUnlock(com.sun.net.httpserver.HttpExchange ex,
                                  String id, String body) throws IOException {
            String password   = extractJsonString(body, "password");
            String passphrase = extractJsonString(body, "passphrase");
            if (password == null) {
                sendJson(ex, 400, "{\"error\":\"password required\"}");
                return;
            }
            boolean ok = walletManager.unlock(id, password.toCharArray(),
                    passphrase != null ? passphrase : "");
            sendJson(ex, ok ? 200 : 401,
                    ok ? "{\"ok\":true}"
                            : "{\"ok\":false,\"error\":\"Incorrect password\"}");
        }

        private String walletToJson(handshake.wallet.WalletDB.WalletRecord w) {
            return String.format(
                    "{\"id\":\"%s\",\"name\":\"%s\",\"addressCount\":%d,"
                            + "\"createdAt\":%d,\"unlocked\":%b}",
                    w.id, w.name.replace("\"","'"), w.addressCount,
                    w.createdAt, walletManager.isUnlocked(w.id));
        }

        private String namesToJson(String walletId) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (var n : walletManager.getNames(walletId)) {
                if (!first) sb.append(",");
                sb.append(n.toJson());
                first = false;
            }
            sb.append("]");
            return sb.toString();
        }

        private String extractWalletId(String path, String suffix) {
            String after = path.substring("/api/wallet/".length());
            return after.substring(0, after.length() - suffix.length());
        }

        private String extractJsonString(String json, String key) {
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start < 0) return null;
            start += search.length();
            int end = json.indexOf("\"", start);
            return end < 0 ? null : json.substring(start, end);
        }

        private void sendJson(com.sun.net.httpserver.HttpExchange ex,
                              int code, String json) throws IOException {
            byte[] body = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(code, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        }
    }

    // ── /api/seeds — seed management ─────────────────────────────────────────

    private class SeedsHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            String method = exchange.getRequestMethod().toUpperCase();

            switch (method) {
                case "GET" -> {
                    // Return all seeds as JSON
                    byte[] body = SeedDatabase.get().toJson()
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type","application/json");
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                    exchange.close();
                }
                case "POST" -> {
                    // Add a custom seed
                    // Body: {"key":"...","ip":"...","port":44806,"label":"..."}
                    String body = new String(exchange.getRequestBody().readAllBytes(),
                            java.nio.charset.StandardCharsets.UTF_8);
                    String key   = extractJsonString(body, "key");
                    String ip    = extractJsonString(body, "ip");
                    String portS = extractJsonString(body, "port");
                    String label = extractJsonString(body, "label");
                    if (key == null || ip == null) {
                        sendJson(exchange, 400, "{\"ok\":false,\"error\":\"missing key or ip\"}");
                        return;
                    }
                    int port = 44806;
                    try { if (portS != null) port = Integer.parseInt(portS); }
                    catch (Exception ignored) {}
                    boolean ok = SeedDatabase.get().addSeed(key, ip, port,
                            label != null ? label : "");
                    sendJson(exchange, ok ? 200 : 409,
                            ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"seed already exists\"}");
                }
                case "DELETE" -> {
                    // Remove or disable a seed: /api/seeds?ip=1.2.3.4&action=remove|disable|enable
                    String query  = exchange.getRequestURI().getQuery();
                    Map<String,String> params = parseQuery(query);
                    String ip     = params.get("ip");
                    String action = params.getOrDefault("action", "disable");
                    if (ip == null) {
                        sendJson(exchange, 400, "{\"ok\":false,\"error\":\"missing ip\"}");
                        return;
                    }
                    boolean ok = switch (action) {
                        case "remove"  -> SeedDatabase.get().removeSeed(ip);
                        case "enable"  -> SeedDatabase.get().setEnabled(ip, true);
                        default        -> SeedDatabase.get().setEnabled(ip, false);
                    };
                    sendJson(exchange, 200,
                            ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"not found or builtin\"}");
                }
                default -> {
                    exchange.sendResponseHeaders(405, -1);
                    exchange.close();
                }
            }
        }

        private void sendJson(com.sun.net.httpserver.HttpExchange ex,
                              int code, String json) throws IOException {
            byte[] body = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(code, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        }

        private String extractJsonString(String json, String key) {
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start >= 0) {
                start += search.length();
                int end = json.indexOf("\"", start);
                if (end >= 0) return json.substring(start, end);
            }
            // Try without quotes (number values)
            search = "\"" + key + "\":";
            start = json.indexOf(search);
            if (start >= 0) {
                start += search.length();
                int end = json.indexOf(",", start);
                int end2 = json.indexOf("}", start);
                if (end < 0 || (end2 >= 0 && end2 < end)) end = end2;
                if (end >= 0) return json.substring(start, end).trim();
            }
            return null;
        }

        private Map<String,String> parseQuery(String query) {
            Map<String,String> map = new LinkedHashMap<>();
            if (query == null) return map;
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) map.put(kv[0], kv[1]);
            }
            return map;
        }
    }

    // ── GET /api/peers — peer scores and status ───────────────────────────────

    private class PeersHandler implements HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange)
                throws IOException {
            // Merge scored peers with all known peers (seeds + discovered)
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;

            // All known peers from seeds + discovery
            Set<String> shown = new HashSet<>();
            for (handshake.node.Seed s : PeerDiscovery.get().getAllPeers()) {
                if (!first) sb.append(",");
                String ip = s.ipAddress();
                shown.add(ip);
                PeerScorecard.PeerRecord r = PeerScorecard.get().getRecord(ip);
                int    score   = r != null ? r.score   : 50;
                String status  = r != null ? r.status() : "UNKNOWN";
                String agent   = r != null && r.lastVersion != null
                        ? r.lastVersion : "";
                int    height  = r != null ? r.lastKnownHeight : 0;
                boolean backoff = r != null && r.isBackedOff();
                sb.append(String.format(
                        "{\"ip\":\"%s\",\"score\":%d,\"status\":\"%s\","
                                + "\"ok\":%d,\"fail\":%d,\"inv\":%d,\"height\":%d,"
                                + "\"version\":\"%s\",\"backoff\":%b}",
                        ip, score, status,
                        r != null ? r.successCount : 0,
                        r != null ? r.failureCount : 0,
                        r != null ? r.invalidBlockCount : 0,
                        height,
                        agent.replace("\"",""),
                        backoff));
                first = false;
            }

            // Also show any scored peers not in the known list
            for (PeerScorecard.PeerRecord r : PeerScorecard.get().getAllRecords()) {
                if (!shown.contains(r.ip)) {
                    if (!first) sb.append(",");
                    sb.append(String.format(
                            "{\"ip\":\"%s\",\"score\":%d,\"status\":\"%s\","
                                    + "\"ok\":%d,\"fail\":%d,\"inv\":%d,\"height\":%d,"
                                    + "\"version\":\"%s\",\"backoff\":%b}",
                            r.ip, r.score, r.status(),
                            r.successCount, r.failureCount, r.invalidBlockCount,
                            r.lastKnownHeight,
                            r.lastVersion != null ? r.lastVersion.replace("\"","") : "",
                            r.isBackedOff()));
                    first = false;
                }
            }

            sb.append("]");
            byte[] body = sb.toString()
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