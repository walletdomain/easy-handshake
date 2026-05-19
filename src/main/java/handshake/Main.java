package handshake;

import handshake.node.Config;
import handshake.node.SetupServer;
import handshake.node.HNSPeerManager;

import java.util.*;

/**
 * Application entry point for Easy Handshake Node.
 *
 * Startup flow:
 *   1. Parse CLI args
 *   2. Load config from config.mv.db
 *   3. If --setup or first run → setup wizard (web or CLI)
 *   4. Start enabled modules
 *
 * CLI usage:
 *   java -jar easy-handshake.jar
 *     → Normal startup, setup wizard if first run
 *
 *   java -jar easy-handshake.jar --setup
 *     → Force re-run setup wizard
 *
 *   java -jar easy-handshake.jar --headless \
 *       --modules=FULL_NODE,DNS \
 *       --bind=0.0.0.0 \
 *       --http-port=8888 \
 *       --deployment=VPS
 *     → Non-interactive setup for servers/Docker/scripts
 */
public class Main {

    public static void main(String[] args) throws Exception {
        Map<String, String> flags = parseArgs(args);

        // Load configuration (creates config.mv.db on first run)
        Config config = Config.load();

        // --headless: non-interactive CLI setup
        if (flags.containsKey("headless")) {
            applyHeadlessConfig(config, flags);
            HNSPeerManager.main(args);
            return;
        }

        // --setup: force re-run setup wizard
        if (flags.containsKey("setup")) {
            config.resetSetup();
        }

        if (config.isFirstRun()) {
            if (Config.isHeadless()) {
                // Running headless with no config — print instructions and exit
                printHeadlessInstructions(config);
                // Apply safe headless defaults and continue
                applyHeadlessDefaults(config);
            } else {
                // GUI environment — serve web wizard and auto-open browser
                SetupServer setup = new SetupServer(config);
                // Try to open the browser automatically
                tryOpenBrowser("http://localhost:" + config.httpPort());
                setup.runUntilComplete();
                Thread.sleep(500);
            }
        }

        HNSPeerManager.main(args);
    }

    // ── Headless setup ────────────────────────────────────────────────────────

    private static void applyHeadlessConfig(Config config,
                                            Map<String, String> flags) {
        // --modules=FULL_NODE,DNS,WALLET,MINER
        if (flags.containsKey("modules")) {
            Set<Config.Module> enabled = new LinkedHashSet<>();
            for (String m : flags.get("modules").split(",")) {
                try { enabled.add(Config.Module.valueOf(m.trim().toUpperCase())); }
                catch (Exception ignored) {}
            }
            if (!enabled.isEmpty())
                config.completeSetup(enabled);
        }
        // --bind=0.0.0.0
        if (flags.containsKey("bind"))
            config.set(Config.KEY_HTTP_BIND, flags.get("bind"));
        // --http-port=8888
        if (flags.containsKey("http-port"))
            config.set(Config.KEY_HTTP_PORT, flags.get("http-port"));
        // --deployment=VPS
        if (flags.containsKey("deployment")) {
            try {
                Config.DeploymentType dt = Config.DeploymentType.valueOf(
                        flags.get("deployment").toUpperCase());
                config.setDeploymentType(dt);
            } catch (Exception ignored) {}
        }
        // --dns-upstream=10.2.0.1
        if (flags.containsKey("dns-upstream"))
            config.set(Config.KEY_DNS_UPSTREAM, flags.get("dns-upstream"));

        if (config.isFirstRun())
            applyHeadlessDefaults(config);
    }

    private static void applyHeadlessDefaults(Config config) {
        // Safe defaults for a headless full node + DNS server
        config.completeSetup(Set.of(
                Config.Module.FULL_NODE,
                Config.Module.DNS));
        config.setDeploymentType(Config.DeploymentType.VPS);
        System.out.println("[Setup] Applied headless defaults: "
                + "FULL_NODE + DNS, bind=0.0.0.0");
    }

    /**
     * Attempts to open the default browser on the current platform.
     * Fails silently — the user can always navigate manually.
     */
    private static void tryOpenBrowser(String url) {
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop()
                        .browse(java.net.URI.create(url));
                return;
            }
        } catch (Exception ignored) {}

        // Fallback: try platform-specific commands
        String os = System.getProperty("os.name", "").toLowerCase();
        try {
            if (os.contains("win")) {
                Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + url);
            } else if (os.contains("mac")) {
                Runtime.getRuntime().exec("open " + url);
            } else {
                Runtime.getRuntime().exec("xdg-open " + url);
            }
        } catch (Exception ignored) {
            System.out.println("Open your browser and navigate to: " + url);
        }
    }

    private static void printHeadlessInstructions(Config config) {
        System.out.println();
        System.out.println("=================================================");
        System.out.println("  Easy Handshake — Headless First Run");
        System.out.println("=================================================");
        System.out.println("  No configuration found. Applying defaults.");
        System.out.println();
        System.out.println("  To configure manually, use:");
        System.out.println("    --headless --modules=FULL_NODE,DNS \\");
        System.out.println("    --bind=0.0.0.0 --deployment=VPS");
        System.out.println();
        System.out.println("  Or access the dashboard remotely at:");
        System.out.println("    http://<your-server-ip>:" + config.httpPort());
        System.out.println("=================================================");
        System.out.println();
    }

    // ── CLI parser ────────────────────────────────────────────────────────────

    /**
     * Parses --key=value and --flag args into a map.
     * --setup          → {"setup": ""}
     * --bind=0.0.0.0   → {"bind": "0.0.0.0"}
     * --headless        → {"headless": ""}
     */
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String arg : args) {
            if (arg.startsWith("--")) {
                String stripped = arg.substring(2);
                int eq = stripped.indexOf('=');
                if (eq >= 0) {
                    map.put(stripped.substring(0, eq).toLowerCase(),
                            stripped.substring(eq + 1));
                } else {
                    map.put(stripped.toLowerCase(), "");
                }
            }
        }
        return map;
    }
}