package handshake.node;

import java.net.Socket;

/**
 * Represents a Handshake node that has successfully completed the brontide
 * handshake. Holds the authenticated socket, the live BrontideState for
 * post-handshake encrypted messaging, and the measured response time.
 */
public class Peer {

    public final Seed          seed;
    public final long          responseTimeMs;
    public final Socket        socket;
    public final BrontideState brontide;

    public Peer(Seed seed, long responseTimeMs, Socket socket, BrontideState brontide) {
        this.seed           = seed;
        this.responseTimeMs = responseTimeMs;
        this.socket         = socket;
        this.brontide       = brontide;
    }

    /**
     * Constructor for inbound (server-side) connections where we don't
     * have a Seed object — just the raw socket and remote IP.
     */
    public Peer(Socket socket, String remoteIp) {
        this.seed           = new Seed("", remoteIp, 44806);
        this.responseTimeMs = 0;
        this.socket         = socket;
        this.brontide       = null; // set separately via HNSPeer
    }

    @Override
    public String toString() {
        return seed.ipAddress() + " (" + responseTimeMs + "ms, brontide authenticated)";
    }
}