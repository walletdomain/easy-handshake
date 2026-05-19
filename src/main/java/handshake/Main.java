package handshake;

import handshake.node.Config;
import handshake.node.SetupServer;
import handshake.node.HNSPeerManager;

/**
 * Application entry point for Easy Handshake Node.
 *
 * Startup flow:
 *   1. Load config from config.mv.db
 *   2. If first run → start SetupServer, serve wizard, wait for completion
 *   3. If configured → start enabled modules via HNSPeerManager
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
            // First run — serve setup wizard and wait for user to configure
            SetupServer setup = new SetupServer(config);
            setup.runUntilComplete();
            // Small pause to let the browser receive the redirect response
            Thread.sleep(500);
        }

        // Start the node with the configured modules
        HNSPeerManager.main(args);
    }
}