package handshake.node;

/**
 * A Handshake P2P seed node identified by its brontide public key,
 * IP address, and port.
 *
 * Seeds are now managed by handshake.node.SeedDatabase which persists
 * them to config.mv.db and allows adding/removing custom seeds at runtime.
 */
public record Seed(String key, String ipAddress, int port) {}