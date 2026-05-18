package handshake.node.api;

import handshake.database.Database;

import java.util.List;

import static handshake.node.api.JsonBuilder.*;

/**
 * Handshake name and DNS record API methods.
 *
 * REST (planned):
 *   GET /name/:name            → name info and current state
 *   GET /name/:name/resource   → DNS resource records
 *
 * RPC (planned):
 *   getnameinfo        — name state (owner, value, expiry, etc.)
 *   getnameresource    — DNS records (NS, A, AAAA, TXT, etc.)
 *   getnameproof       — Urkel tree proof for a name
 *   getnames           — list of all registered names
 *
 * Implementation requires the name index to be built from
 * covenant transactions in the block database (REGISTER, UPDATE,
 * TRANSFER, FINALIZE, REVOKE covenants). This will be populated
 * by the DNS resolver component.
 */
public class NameApi {

    @SuppressWarnings("unused")
    private final Database db;

    public NameApi(Database db) {
        this.db = db;
    }

    // ── REST ──────────────────────────────────────────────────────────────────

    public String getNameInfo(String name) {
        return error("getnameinfo not yet implemented — DNS resolver coming soon", -1);
    }

    public String getNameResource(String name) {
        return error("getnameresource not yet implemented — DNS resolver coming soon", -1);
    }

    // ── RPC ───────────────────────────────────────────────────────────────────

    public String rpcGetNameInfo(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("name required", -8);
        return getNameInfo(str(params.getFirst()));
    }

    public String rpcGetNameResource(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("name required", -8);
        return getNameResource(str(params.getFirst()));
    }
}