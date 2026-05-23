package handshake.node;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Node configuration — persistent key/value store backed by MVStore.
 *
 * Stored in config.mv.db alongside chain.mv.db. Separate from the chain
 * database so config survives chain resets/rebuilds.
 *
 * Usage:
 *   Config config = Config.load();
 *   config.isFirstRun()                        → true on first start
 *   config.isEnabled(Module.DNS)               → true/false
 *   config.get("dns.recursive.port", "5350")   → "5350"
 *   config.set("dns.recursive.port", "5351")   → persists immediately
 *   config.completeSetup(Set.of(Module.FULL_NODE, Module.DNS))
 *
 * Default values are defined in Module and in the get() overloads below.
 * Callers should always use get(key, defaultValue) rather than get(key).
 */
public class Config implements AutoCloseable {

    // ── Module definitions ────────────────────────────────────────────────────

    public enum Module {
        FULL_NODE(
                "Full Node",
                "Sync the blockchain, serve blocks to peers, expose REST/RPC APIs",
                "⛓", true),
        DNS(
                "DNS Resolver",
                "HNS-first recursive DNS resolver — resolves Handshake and ICANN names",
                "🌐", false),
        WALLET(
                "Wallet",
                "Manage HNS addresses, TLD ownership, and renewal alerts",
                "💰", false),
        MINER(
                "Miner",
                "Mine HNS blocks (CPU/GPU) and serve as a Stratum mining pool",
                "⛏", false);

        public final String  displayName;
        public final String  description;
        public final String  icon;
        public final boolean defaultEnabled;

        Module(String displayName, String description,
               String icon, boolean defaultEnabled) {
            this.displayName    = displayName;
            this.description    = description;
            this.icon           = icon;
            this.defaultEnabled = defaultEnabled;
        }

        /** Config key for this module's enabled state. */
        public String key() { return "module." + name().toLowerCase(); }
    }

    // ── Built-in config keys with defaults ────────────────────────────────────

    public static final String KEY_SETUP_COMPLETE  = "setup.complete";
    public static final String KEY_SETUP_VERSION   = "setup.version";
    public static final String KEY_NODE_VERSION    = "node.version";

    // HTTP
    public static final String KEY_HTTP_PORT       = "http.port";
    public static final String DEFAULT_HTTP_PORT   = "8888";

    // P2P
    public static final String KEY_P2P_PORT        = "p2p.port";
    public static final String DEFAULT_P2P_PORT    = "44806";

    // DNS
    public static final String KEY_DNS_AUTH_PORT   = "dns.auth.port";
    public static final String KEY_DNS_REC_PORT    = "dns.recursive.port";
    public static final String KEY_DNS_UPSTREAM    = "dns.upstream";
    public static final String DEFAULT_DNS_AUTH    = "5349";
    public static final String DEFAULT_DNS_REC     = "5350";
    public static final String DEFAULT_DNS_UPSTREAM= "";  // auto-detect

    // Wallet
    public static final String KEY_WALLET_NAMES    = "wallet.tracked.names"; // comma-sep

    // Miner
    public static final String KEY_STRATUM_PORT    = "miner.stratum.port";
    public static final String DEFAULT_STRATUM_PORT= "3008";

    // ── Singleton / factory ───────────────────────────────────────────────────

    private static volatile Config instance;

    /**
     * Loads (or creates) the config from the default location.
     * Subsequent calls return the same instance.
     */
    public static Config load() {
        if (instance == null) {
            synchronized (Config.class) {
                if (instance == null) {
                    instance = new Config(defaultConfigPath());
                }
            }
        }
        return instance;
    }

    /** Loads config from a specific path — used in tests. */
    public static Config load(Path path) {
        return new Config(path);
    }

    /** Returns the singleton instance, or throws if not yet loaded. */
    public static Config get() {
        if (instance == null)
            throw new IllegalStateException("Config not loaded — call Config.load() first");
        return instance;
    }

    private static Path defaultConfigPath() {
        return Paths.get("config.mv.db");
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final MVStore             store;
    private final MVMap<String,String> settings;

    private Config(Path path) {
        try {
            Files.createDirectories(path.getParent() == null
                    ? Paths.get(".") : path.getParent());
        } catch (IOException ignored) {}

        this.store    = new MVStore.Builder()
                .fileName(path.toString())
                .compress()
                .open();
        this.settings = store.openMap("settings");

        // Apply defaults for any missing keys
        applyDefaults();
    }

    private void applyDefaults() {
        setIfAbsent(KEY_HTTP_PORT,        DEFAULT_HTTP_PORT);
        setIfAbsent(KEY_HTTP_BIND,        DEFAULT_HTTP_BIND);
        setIfAbsent(KEY_P2P_PORT,         DEFAULT_P2P_PORT);
        setIfAbsent(KEY_DNS_AUTH_PORT,    DEFAULT_DNS_AUTH);
        setIfAbsent(KEY_DNS_REC_PORT,     DEFAULT_DNS_REC);
        setIfAbsent(KEY_DNS_UPSTREAM,     DEFAULT_DNS_UPSTREAM);
        setIfAbsent(KEY_STRATUM_PORT,     DEFAULT_STRATUM_PORT);
        setIfAbsent(KEY_DEPLOYMENT_TYPE,
                isHeadless()
                        ? DeploymentType.VPS.name()
                        : DeploymentType.DESKTOP.name());
        // Module defaults
        for (Module m : Module.values())
            setIfAbsent(m.key(), String.valueOf(m.defaultEnabled));
        store.commit();
    }

    // ── Setup wizard state ────────────────────────────────────────────────────

    /** Returns true if this is the first time the node has been run. */
    public boolean isFirstRun() {
        return !"true".equals(settings.get(KEY_SETUP_COMPLETE));
    }

    /**
     * Marks setup as complete and enables the selected modules.
     * Called by the setup wizard when the user clicks "Start Node".
     */
    public void completeSetup(Set<Module> enabledModules) {
        // Disable all modules first
        for (Module m : Module.values())
            settings.put(m.key(), "false");
        // Enable selected ones
        for (Module m : enabledModules)
            settings.put(m.key(), "true");
        settings.put(KEY_SETUP_COMPLETE, "true");
        settings.put(KEY_SETUP_VERSION,  "1");
        store.commit();
    }

    /** Resets setup state — forces setup wizard on next start. */
    public void resetSetup() {
        settings.remove(KEY_SETUP_COMPLETE);
        store.commit();
    }

    // ── Module management ─────────────────────────────────────────────────────

    /** Returns true if the given module is enabled. */
    public boolean isEnabled(Module module) {
        return "true".equals(settings.get(module.key()));
    }

    /** Enables or disables a module and persists the change. */
    public void setEnabled(Module module, boolean enabled) {
        settings.put(module.key(), String.valueOf(enabled));
        store.commit();
        EventBus.get().system((enabled ? "Enabled" : "Disabled")
                + " module: " + module.displayName);
    }

    /** Returns the set of currently enabled modules. */
    public Set<Module> enabledModules() {
        Set<Module> result = new LinkedHashSet<>();
        for (Module m : Module.values())
            if (isEnabled(m)) result.add(m);
        return Collections.unmodifiableSet(result);
    }

    // ── Key/value access ──────────────────────────────────────────────────────

    /** Gets a config value, returning defaultValue if not set. */
    public String get(String key, String defaultValue) {
        String val = settings.get(key);
        return val != null ? val : defaultValue;
    }

    /** Gets a config value as int, returning defaultValue if not set or invalid. */
    public int getInt(String key, int defaultValue) {
        try { return Integer.parseInt(get(key, String.valueOf(defaultValue))); }
        catch (NumberFormatException e) { return defaultValue; }
    }

    /** Gets a config value as boolean. */
    public boolean getBool(String key, boolean defaultValue) {
        String val = settings.get(key);
        if (val == null) return defaultValue;
        return "true".equalsIgnoreCase(val);
    }

    /** Gets the relay node URL for transaction broadcast (e.g. http://74.208.31.75:12037). */
    public String getRelayNodeUrl() {
        return get("relay.node.url", null);
    }

    /** Gets the relay node API key for transaction broadcast. */
    public String getRelayNodeApiKey() {
        return get("relay.node.apikey", null);
    }

    /** Sets a config value and persists immediately. */
    public void set(String key, String value) {
        settings.put(key, value);
        store.commit();
    }

    /** Sets a config value only if it isn't already set. */
    private void setIfAbsent(String key, String value) {
        if (!settings.containsKey(key))
            settings.put(key, value);
    }

    // ── Deployment type ───────────────────────────────────────────────────────

    public enum DeploymentType {
        DESKTOP("Personal desktop",
                "Dashboard accessible on this machine only",
                "127.0.0.1"),
        HOME_SERVER("Home server",
                "Dashboard accessible on your local network",
                "0.0.0.0"),
        VPS("VPS / Cloud server",
                "Dashboard accessible remotely — secure with a firewall",
                "0.0.0.0");

        public final String displayName;
        public final String description;
        public final String defaultBind;

        DeploymentType(String displayName, String description, String defaultBind) {
            this.displayName  = displayName;
            this.description  = description;
            this.defaultBind  = defaultBind;
        }
    }

    public static final String KEY_DEPLOYMENT_TYPE = "deployment.type";
    public static final String KEY_HTTP_BIND       = "http.bind";
    public static final String DEFAULT_HTTP_BIND   = autoDetectBind();

    /** Auto-detects appropriate bind address based on environment. */
    private static String autoDetectBind() {
        try {
            boolean headless = java.awt.GraphicsEnvironment.isHeadless();
            return headless ? "0.0.0.0" : "127.0.0.1";
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }

    /** Returns true if running in a headless (server/VPS) environment. */
    public static boolean isHeadless() {
        try {
            return java.awt.GraphicsEnvironment.isHeadless();
        } catch (Exception e) {
            return true; // assume headless if we can't tell
        }
    }

    public DeploymentType getDeploymentType() {
        try {
            return DeploymentType.valueOf(
                    get(KEY_DEPLOYMENT_TYPE, DeploymentType.DESKTOP.name()));
        } catch (Exception e) {
            return DeploymentType.DESKTOP;
        }
    }

    public void setDeploymentType(DeploymentType type) {
        set(KEY_DEPLOYMENT_TYPE, type.name());
        set(KEY_HTTP_BIND, type.defaultBind);
    }

    public String httpBind() {
        return get(KEY_HTTP_BIND, DEFAULT_HTTP_BIND);
    }

    public int httpPort()      { return getInt(KEY_HTTP_PORT,      8888); }
    public int p2pPort()       { return getInt(KEY_P2P_PORT,       44806); }
    public int dnsAuthPort()   { return getInt(KEY_DNS_AUTH_PORT,  5349); }
    public int dnsRecPort()    { return getInt(KEY_DNS_REC_PORT,   5350); }
    public int stratumPort()   { return getInt(KEY_STRATUM_PORT,   3008); }
    public String dnsUpstream(){ return get(KEY_DNS_UPSTREAM,      ""); }

    // ── Snapshot of all settings (for HTTP config API) ────────────────────────

    /** Returns all settings as an unmodifiable map. */
    public Map<String, String> all() {
        return Collections.unmodifiableMap(new TreeMap<>(settings));
    }

    /** Returns all settings as a JSON string. */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : new TreeMap<>(settings).entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.getKey()).append("\":");
            sb.append("\"").append(
                    e.getValue().replace("\\", "\\\\").replace("\"", "\\\"")
            ).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /** Returns the underlying MVStore — used to share with PeerScorecard. */
    public MVStore getStore() { return store; }

    @Override
    public void close() {
        if (!store.isClosed()) {
            store.commit();
            store.close();
        }
    }
}