package handshake.node;

import com.sun.net.httpserver.*;
import handshake.database.Database;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * HTTPS server on port 8443 for Easy Handshake.
 *
 * Serves the same endpoints as NodeHttpServer (port 8888) but over TLS:
 *   - Dashboard UI
 *   - REST API
 *   - JSON-RPC
 *   - DoH (DNS over HTTPS, RFC 8484) — primary purpose
 *
 * Certificate is managed by TLSManager — self-signed, 10-year validity,
 * generated on first run and stored in node.keystore.
 *
 * DoH endpoint: https://<host>:8443/dns-query
 * Dashboard:    https://localhost:8443
 *
 * Users need to accept the self-signed certificate once in their browser.
 * The SHA-256 fingerprint is printed at startup for verification.
 */
public class HttpsNodeServer {

    public static final int HTTPS_PORT = 8443;

    private final NodeHttpServer httpServer;
    private final TLSManager     tls;
    private HttpsServer          httpsServer;

    public HttpsNodeServer(NodeHttpServer httpServer, TLSManager tls) {
        this.httpServer = httpServer;
        this.tls        = tls;
    }

    /**
     * Starts the HTTPS server, sharing all handlers from NodeHttpServer.
     * The HTTPS server mirrors the HTTP server exactly — same endpoints,
     * same handlers, just wrapped in TLS.
     */
    public void start() throws Exception {
        SSLContext sslContext = tls.getSslContext();

        httpsServer = HttpsServer.create(
                new InetSocketAddress("0.0.0.0", HTTPS_PORT), 0);

        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext ctx = getSSLContext();
                    SSLParameters sslParams = ctx.getDefaultSSLParameters();
                    // Allow TLS 1.2 and 1.3 only
                    sslParams.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    System.out.println("[HTTPS] SSL config error: " + e.getMessage());
                }
            }
        });

        // Register all the same contexts from NodeHttpServer
        // We do this by creating a delegating server that shares handlers
        registerContexts();

        httpsServer.setExecutor(Executors.newCachedThreadPool());
        httpsServer.start();

        System.out.println("[HTTPS] Server started on port " + HTTPS_PORT);
        System.out.println("[HTTPS] Dashboard: https://localhost:" + HTTPS_PORT);
        System.out.println("[HTTPS] DoH:       https://localhost:" + HTTPS_PORT + "/dns-query");
        System.out.println("[HTTPS] Cert fingerprint: " + tls.getCertFingerprint());
    }

    /**
     * Registers HTTP contexts on the HTTPS server.
     * Each context delegates to the same handler instance used by NodeHttpServer,
     * so all logic is shared — only the transport differs.
     */
    private void registerContexts() {
        // Get the HTTP server's contexts and mirror them
        // We use the httpServer's internal server reference to copy handlers
        httpServer.registerContextsOn(httpsServer);
    }

    public void stop() {
        if (httpsServer != null) {
            httpsServer.stop(0);
            System.out.println("[HTTPS] Server stopped.");
        }
    }
}