package handshake;

import handshake.node.Config;
import handshake.node.HNSPeerManager;

/**
 * Application entry point for Easy Handshake Node.
 *
 * Startup flow:
 *   1. Load config from config.mv.db
 *   2. If first run → start HTTP server only, serve setup wizard
 *   3. If configured → start enabled modules
 *
 * To run from the fat JAR:
 *   java -Xmx2g -jar easy-handshake.jar
 *
 * To run from IntelliJ:
 *   Right-click Main.java → Run 'Main.main()'
 *   (set Working Directory in run config to your desired data directory)
 */
public class Main {

    public static void main(String[] args) throws Exception {
        // Load configuration (creates config.mv.db on first run)
        Config config = Config.load();

        if (config.isFirstRun()) {
            // First run — start setup wizard only
            // TODO: start SetupServer on http port and serve wizard
            System.out.println("=== Easy Handshake — First Run Setup ===");
            System.out.println("No configuration found.");
            System.out.println("Starting setup wizard at http://localhost:"
                    + config.httpPort());
            System.out.println("(Setup wizard coming soon — starting with defaults for now)");
            System.out.println();

            // For now, auto-complete setup with FULL_NODE + DNS enabled
            // until the setup wizard is built
            config.completeSetup(java.util.Set.of(
                    Config.Module.FULL_NODE,
                    Config.Module.DNS));
        }

        // Start enabled modules
        HNSPeerManager.main(args);
    }
}