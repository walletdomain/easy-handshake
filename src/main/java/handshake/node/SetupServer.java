package handshake.node;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

/**
 * Minimal HTTP server that serves the first-run setup wizard.
 *
 * Only runs when Config.isFirstRun() is true. Serves a single-page
 * wizard that lets the user select which modules to enable and configure
 * ports. On form submission, saves config and signals Main.java to
 * proceed with the full node startup.
 *
 * Flow:
 *   Main detects first run
 *   → SetupServer.start()
 *   → browser opens http://localhost:8888
 *   → user selects modules, clicks "Start Node"
 *   → POST /setup → config saved → latch released
 *   → SetupServer.stop()
 *   → HNSPeerManager.main() starts with selected modules
 */
public class SetupServer {

    private final Config        config;
    private final int           port;
    private final CountDownLatch setupDone;
    private HttpServer          server;

    public SetupServer(Config config) {
        this.config    = config;
        this.port      = config.httpPort();
        this.setupDone = new CountDownLatch(1);
    }

    /** Starts the setup server and blocks until setup is complete. */
    public void runUntilComplete() throws Exception {
        String bind = config.httpBind();
        server = HttpServer.create(new InetSocketAddress(bind, port), 0);
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.createContext("/",       this::handleRoot);
        server.createContext("/setup",  this::handleSetup);
        server.createContext("/health", this::handleHealth);
        server.start();

        System.out.println("=================================================");
        System.out.println("  Easy Handshake — First Run Setup");
        System.out.println("=================================================");
        System.out.println("  Open your browser and navigate to:");
        System.out.println("  http://localhost:" + port);
        System.out.println("=================================================");
        System.out.println();

        // Block until setup form is submitted
        setupDone.await();
        stop();
    }

    public void stop() {
        if (server != null) server.stop(0);
    }

    // ── Handlers ─────────────────────────────────────────────────────────────

    private void handleRoot(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }
        String html = buildWizardHtml();
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private void handleSetup(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        // Parse form body: module.FULL_NODE=on&module.DNS=on&http.port=8888&...
        String body = new String(exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8);
        Map<String, String> params = parseFormBody(body);

        // Determine which modules were selected
        Set<Config.Module> enabled = new LinkedHashSet<>();
        for (Config.Module m : Config.Module.values()) {
            String key = "module." + m.name();
            if ("on".equals(params.get(key)) || "true".equals(params.get(key)))
                enabled.add(m);
        }

        // Always enable FULL_NODE — it's the foundation
        enabled.add(Config.Module.FULL_NODE);

        // Save deployment type and set bind address accordingly
        String deployType = params.getOrDefault("deployment.type",
                Config.DeploymentType.DESKTOP.name());
        try {
            Config.DeploymentType dt = Config.DeploymentType.valueOf(deployType);
            config.setDeploymentType(dt);
            System.out.println("[Setup] Deployment type: " + dt.displayName
                    + " (bind=" + dt.defaultBind + ")");
        } catch (Exception e) {
            config.set(Config.KEY_DEPLOYMENT_TYPE,
                    Config.DeploymentType.DESKTOP.name());
        }

        // Save port settings
        saveIfValid(params, Config.KEY_HTTP_PORT,      Config.DEFAULT_HTTP_PORT);
        saveIfValid(params, Config.KEY_P2P_PORT,       Config.DEFAULT_P2P_PORT);
        saveIfValid(params, Config.KEY_DNS_AUTH_PORT,  Config.DEFAULT_DNS_AUTH);
        saveIfValid(params, Config.KEY_DNS_REC_PORT,   Config.DEFAULT_DNS_REC);
        saveIfValid(params, Config.KEY_DNS_UPSTREAM,   Config.DEFAULT_DNS_UPSTREAM);

        // Complete setup
        config.completeSetup(enabled);

        System.out.println("[Setup] Modules enabled: " + enabled);
        System.out.println("[Setup] Configuration saved. Starting node...");

        // Respond with redirect to loading page
        String redirect = buildLoadingHtml(enabled);
        byte[] respBytes = redirect.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, respBytes.length);
        exchange.getResponseBody().write(respBytes);
        exchange.close();

        // Signal Main.java to proceed
        setupDone.countDown();
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        byte[] body = "{\"status\":\"setup\"}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private void saveIfValid(Map<String, String> params, String key, String def) {
        String val = params.getOrDefault(key, def).trim();
        if (!val.isEmpty()) config.set(key, val);
    }

    // ── Form parser ───────────────────────────────────────────────────────────

    private static Map<String, String> parseFormBody(String body) {
        Map<String, String> map = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) return map;
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                map.put(urlDecode(kv[0]), urlDecode(kv[1]));
            } else if (kv.length == 1) {
                map.put(urlDecode(kv[0]), "");
            }
        }
        return map;
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    // ── HTML builder ──────────────────────────────────────────────────────────

    private String buildWizardHtml() {
        StringBuilder sb = new StringBuilder();
        sb.append("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Easy Handshake — Setup</title>
              <style>
                :root {
                  --bg:      #0d1117;
                  --surface: #161b22;
                  --border:  #30363d;
                  --text:    #e6edf3;
                  --muted:   #7d8590;
                  --accent:  #58a6ff;
                  --accent2: #3fb950;
                  --warn:    #d29922;
                  --danger:  #f85149;
                  --mono:    'Space Mono', 'Courier New', monospace;
                }
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body {
                  background: var(--bg);
                  color: var(--text);
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                  min-height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  padding: 2rem;
                }
                .wizard {
                  max-width: 620px;
                  width: 100%;
                }
                .logo {
                  display: flex;
                  align-items: center;
                  gap: 0.8rem;
                  margin-bottom: 2rem;
                }
                .logo h1 {
                  font-size: 1.4rem;
                  font-weight: 700;
                  color: var(--text);
                }
                .logo .badge {
                  font-size: 0.65rem;
                  background: var(--accent);
                  color: #fff;
                  padding: 0.15rem 0.5rem;
                  border-radius: 20px;
                  font-family: var(--mono);
                }
                .step-title {
                  font-size: 1.1rem;
                  font-weight: 600;
                  margin-bottom: 0.4rem;
                }
                .step-sub {
                  font-size: 0.85rem;
                  color: var(--muted);
                  margin-bottom: 1.5rem;
                  line-height: 1.5;
                }
                .modules {
                  display: flex;
                  flex-direction: column;
                  gap: 0.75rem;
                  margin-bottom: 1.5rem;
                }
                .module {
                  background: var(--surface);
                  border: 1px solid var(--border);
                  border-radius: 8px;
                  padding: 1rem 1.1rem;
                  cursor: pointer;
                  transition: border-color 0.15s, background 0.15s;
                  display: flex;
                  align-items: flex-start;
                  gap: 0.9rem;
                }
                .module:hover { border-color: var(--accent); }
                .module.selected {
                  border-color: var(--accent);
                  background: #1c2433;
                }
                .module.required {
                  border-color: var(--accent2);
                  background: #1a2420;
                  cursor: default;
                  opacity: 0.9;
                }
                .module-check {
                  width: 18px;
                  height: 18px;
                  border: 2px solid var(--border);
                  border-radius: 4px;
                  flex-shrink: 0;
                  margin-top: 2px;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  transition: all 0.15s;
                  font-size: 11px;
                }
                .module.selected .module-check,
                .module.required .module-check {
                  background: var(--accent);
                  border-color: var(--accent);
                  color: #fff;
                }
                .module.required .module-check {
                  background: var(--accent2);
                  border-color: var(--accent2);
                }
                .module-body { flex: 1; min-width: 0; }
                .module-header {
                  display: flex;
                  align-items: center;
                  gap: 0.5rem;
                  margin-bottom: 0.25rem;
                }
                .module-icon { font-size: 1rem; }
                .module-name { font-weight: 600; font-size: 0.9rem; }
                .module-tag {
                  font-size: 0.6rem;
                  background: var(--accent2);
                  color: #fff;
                  padding: 0.1rem 0.4rem;
                  border-radius: 10px;
                  font-family: var(--mono);
                }
                .module-desc {
                  font-size: 0.78rem;
                  color: var(--muted);
                  line-height: 1.4;
                }
                .storage-note {
                  font-size: 0.72rem;
                  color: var(--warn);
                  margin-top: 0.3rem;
                  font-family: var(--mono);
                }
                details {
                  margin-bottom: 1.5rem;
                  border: 1px solid var(--border);
                  border-radius: 8px;
                  overflow: hidden;
                }
                details summary {
                  padding: 0.75rem 1rem;
                  cursor: pointer;
                  font-size: 0.82rem;
                  color: var(--muted);
                  background: var(--surface);
                  list-style: none;
                  display: flex;
                  align-items: center;
                  gap: 0.5rem;
                }
                details summary::-webkit-details-marker { display: none; }
                details summary::before {
                  content: '▶';
                  font-size: 0.6rem;
                  transition: transform 0.2s;
                }
                details[open] summary::before { transform: rotate(90deg); }
                .advanced-grid {
                  display: grid;
                  grid-template-columns: 1fr 1fr;
                  gap: 0.75rem;
                  padding: 1rem;
                  background: var(--surface);
                  border-top: 1px solid var(--border);
                }
                .field { display: flex; flex-direction: column; gap: 0.3rem; }
                .field label {
                  font-size: 0.72rem;
                  color: var(--muted);
                  font-family: var(--mono);
                }
                .field input {
                  background: var(--bg);
                  border: 1px solid var(--border);
                  border-radius: 4px;
                  color: var(--text);
                  font-family: var(--mono);
                  font-size: 0.8rem;
                  padding: 0.4rem 0.6rem;
                  width: 100%;
                  transition: border-color 0.15s;
                }
                .field input:focus {
                  outline: none;
                  border-color: var(--accent);
                }
                .field.full { grid-column: 1 / -1; }
                .btn-start {
                  width: 100%;
                  padding: 0.9rem;
                  background: var(--accent);
                  color: #fff;
                  border: none;
                  border-radius: 8px;
                  font-size: 0.95rem;
                  font-weight: 600;
                  cursor: pointer;
                  transition: background 0.15s, transform 0.1s;
                  letter-spacing: 0.01em;
                }
                .btn-start:hover  { background: #79b8ff; }
                .btn-start:active { transform: scale(0.99); }
                .disclaimer {
                  margin-top: 1rem;
                  font-size: 0.72rem;
                  color: var(--muted);
                  text-align: center;
                  line-height: 1.5;
                }
                @media (max-width: 500px) {
                  .advanced-grid { grid-template-columns: 1fr; }
                }
              </style>
            </head>
            <body>
              <div class="wizard">
                <div class="logo">
                  <span style="font-size:1.8rem">🤝</span>
                  <h1>Easy Handshake</h1>
                  <span class="badge">FIRST RUN</span>
                </div>

                <div class="step-title">Welcome — Select your modules</div>
                <div class="step-sub">
                  Choose which components you'd like to run. You can enable or
                  disable modules at any time from the dashboard.
                </div>

                <form method="POST" action="/setup" id="setup-form">
                  <div class="modules">
            """);

        // Module cards
        for (Config.Module m : Config.Module.values()) {
            boolean required = m == Config.Module.FULL_NODE;
            String storage   = storageNote(m);
            sb.append(String.format("""
                    <div class="module%s" id="card-%s" onclick="%s">
                      <div class="module-check">%s</div>
                      <div class="module-body">
                        <div class="module-header">
                          <span class="module-icon">%s</span>
                          <span class="module-name">%s</span>
                          %s
                        </div>
                        <div class="module-desc">%s</div>
                        %s
                      </div>
                      <input type="checkbox" name="module.%s" id="chk-%s"
                             style="display:none" %s>
                    </div>
                """,
                    required ? " required selected" : " selected",
                    m.name(),
                    required ? "" : "toggleModule('" + m.name() + "')",
                    "✓",
                    m.icon,
                    m.displayName,
                    required ? "<span class=\"module-tag\">required</span>" : "",
                    m.description,
                    storage.isEmpty() ? "" : "<div class=\"storage-note\">" + storage + "</div>",
                    m.name(), m.name(),
                    (required || m.defaultEnabled) ? "checked" : ""
            ));
        }

        sb.append("""
                  </div><!-- end modules -->

                  <div class="step-title" style="margin-top:1.5rem">
                    Where are you running this node?
                  </div>
                  <div class="step-sub">
                    This determines who can access your dashboard.
                  </div>

                  <div class="modules" style="margin-bottom:1.2rem">
                    <div class="module selected" id="deploy-DESKTOP"
                         onclick="selectDeploy('DESKTOP')">
                      <div class="module-check">✓</div>
                      <div class="module-body">
                        <div class="module-header">
                          <span class="module-icon">🖥</span>
                          <span class="module-name">Personal desktop</span>
                        </div>
                        <div class="module-desc">
                          Dashboard only accessible on this machine (127.0.0.1)
                        </div>
                      </div>
                      <input type="radio" name="deployment.type" value="DESKTOP"
                             id="radio-DESKTOP" style="display:none" checked>
                    </div>
                    <div class="module" id="deploy-HOME_SERVER"
                         onclick="selectDeploy('HOME_SERVER')">
                      <div class="module-check"></div>
                      <div class="module-body">
                        <div class="module-header">
                          <span class="module-icon">🏠</span>
                          <span class="module-name">Home server</span>
                        </div>
                        <div class="module-desc">
                          Dashboard accessible on your local network (0.0.0.0)
                        </div>
                      </div>
                      <input type="radio" name="deployment.type" value="HOME_SERVER"
                             id="radio-HOME_SERVER" style="display:none">
                    </div>
                    """ +
                // VPS card — pre-selected if running headless
                (Config.isHeadless()
                        ? "<div class=\"module selected\" id=\"deploy-VPS\" onclick=\"selectDeploy('VPS')\">"
                          + "<div class=\"module-check\">✓</div>"
                        : "<div class=\"module\" id=\"deploy-VPS\" onclick=\"selectDeploy('VPS')\">"
                          + "<div class=\"module-check\"></div>") +
                """
                  <div class="module-body">
                    <div class="module-header">
                      <span class="module-icon">☁</span>
                      <span class="module-name">VPS / Cloud server</span>
                    </div>
                    <div class="module-desc">
                      Dashboard accessible remotely (0.0.0.0) — secure with a firewall
                    </div>
                    <div class="storage-note">&#9888; Restrict port """ + config.httpPort() + """
 with your firewall</div>
                      </div>
                      <input type="radio" name="deployment.type" value="VPS"
                             id="radio-VPS" style="display:none" """ +
                (Config.isHeadless() ? "checked" : "") +
                """
                  >
                </div>
              </div>
                <summary>⚙ Advanced — Port Configuration</summary>
                <div class="advanced-grid">
                  <div class="field">
                    <label>HTTP Dashboard Port</label>
                    <input type="number" name="http.port" value="8888" min="1024" max="65535">
                  </div>
                  <div class="field">
                    <label>P2P Brontide Port</label>
                    <input type="number" name="p2p.port" value="44806" min="1024" max="65535">
                  </div>
                  <div class="field">
                    <label>DNS Authoritative Port</label>
                    <input type="number" name="dns.auth.port" value="5349" min="1024" max="65535">
                  </div>
                  <div class="field">
                    <label>DNS Recursive Port</label>
                    <input type="number" name="dns.recursive.port" value="5350" min="1024" max="65535">
                  </div>
                  <div class="field full">
                    <label>Upstream DNS Override (leave blank for auto-detect)</label>
                    <input type="text" name="dns.upstream" value=""
                           placeholder="e.g. 10.2.0.1 — your router or ISP DNS">
                  </div>
                </div>
              </details>

              <button type="submit" class="btn-start">Start Node →</button>
            </form>

            <div class="disclaimer">
              Settings are saved to <code>config.mv.db</code> in the working directory.<br>
              Blockchain data will be stored in <code>chain.mv.db</code> (~10 GB for full node).
            </div>
          </div>

          <script>
            function toggleModule(name) {
              const card = document.getElementById('card-' + name);
              const chk  = document.getElementById('chk-' + name);
              const sel  = card.classList.toggle('selected');
              chk.checked = sel;
            }
            function selectDeploy(type) {
              ['DESKTOP','HOME_SERVER','VPS'].forEach(t => {
                const card  = document.getElementById('deploy-' + t);
                const radio = document.getElementById('radio-' + t);
                const check = card.querySelector('.module-check');
                if (t === type) {
                  card.classList.add('selected');
                  radio.checked = true;
                  check.textContent = '✓';
                } else {
                  card.classList.remove('selected');
                  radio.checked = false;
                  check.textContent = '';
                }
              });
              // Auto-open advanced when VPS selected
              if (type === 'VPS' || type === 'HOME_SERVER')
                document.getElementById('advanced').open = true;
            }
            // Show advanced section if DNS is selected
            document.querySelectorAll('input[type=checkbox]').forEach(chk => {
              chk.addEventListener('change', () => {
                const dnsChk = document.getElementById('chk-DNS');
                if (dnsChk && dnsChk.checked)
                  document.getElementById('advanced').open = true;
              });
            });
          </script>
        </body>
        </html>
        """);

        return sb.toString();
    }

    private static String storageNote(Config.Module m) {
        return switch (m) {
            case FULL_NODE -> "⚠ Requires ~10 GB disk space for full blockchain";
            case DNS       -> "Requires full blockchain (included with Full Node)";
            case WALLET    -> "Lightweight — only tracks your owned names";
            case MINER     -> "Requires Full Node · GPU recommended for competitive mining";
        };
    }

    private String buildLoadingHtml(Set<Config.Module> enabled) {
        String moduleList = enabled.stream()
                .map(m -> m.icon + " " + m.displayName)
                .reduce((a, b) -> a + ", " + b)
                .orElse("None");
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta http-equiv="refresh" content="4;url=http://localhost:%d">
              <title>Starting Easy Handshake...</title>
              <style>
                body {
                  background: #0d1117; color: #e6edf3;
                  font-family: -apple-system, sans-serif;
                  display: flex; align-items: center; justify-content: center;
                  min-height: 100vh; flex-direction: column; gap: 1rem;
                  text-align: center; padding: 2rem;
                }
                .spinner {
                  width: 40px; height: 40px;
                  border: 3px solid #30363d;
                  border-top-color: #58a6ff;
                  border-radius: 50%;
                  animation: spin 0.8s linear infinite;
                }
                @keyframes spin { to { transform: rotate(360deg); } }
                h2 { font-size: 1.2rem; }
                p  { font-size: 0.85rem; color: #7d8590; }
                code { color: #58a6ff; font-family: monospace; }
              </style>
            </head>
            <body>
              <div class="spinner"></div>
              <h2>Starting Easy Handshake...</h2>
              <p>Enabled: <code>%s</code></p>
              <p>Redirecting to dashboard in a moment...</p>
            </body>
            </html>
            """.formatted(config.httpPort(), moduleList);
    }
}