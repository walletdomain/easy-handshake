package handshake.node.api;

import handshake.database.Database;
import handshake.node.dns.NameIndex;
import handshake.wallet.HNSResource;

import java.util.List;

import static handshake.node.api.JsonBuilder.*;

/**
 * Handshake name and DNS record API methods.
 */
public class NameApi {

    @SuppressWarnings("unused")
    private final Database db;
    private volatile NameIndex nameIndex;

    public NameApi(Database db) {
        this.db = db;
    }

    public void setNameIndex(NameIndex nameIndex) {
        this.nameIndex = nameIndex;
    }

    // ── REST ──────────────────────────────────────────────────────────────────

    public String getNameInfo(String name) {
        if (nameIndex == null)
            return error("Name index not ready", -1);
        byte[] resource = nameIndex.lookup(name);
        if (resource == null)
            return "null";
        List<HNSResource.Record> records = HNSResource.decode(resource);
        return String.format(
                "{\"name\":\"%s\",\"state\":\"CLOSED\",\"registered\":true," +
                        "\"records\":%s,\"resourceSize\":%d}",
                esc(name),
                HNSResource.toJson(records),
                resource.length);
    }

    public String getNameResource(String name) {
        if (nameIndex == null)
            return error("Name index not ready", -1);
        byte[] resource = nameIndex.lookup(name);
        if (resource == null)
            return "null";
        List<HNSResource.Record> records = HNSResource.decode(resource);
        return String.format("{\"records\":%s}", HNSResource.toJson(records));
    }

    // ── RPC ───────────────────────────────────────────────────────────────────

    public String rpcGetNameInfo(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("name required", -8);
        return getNameInfo(params.get(0).toString());
    }

    public String rpcGetNameResource(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("name required", -8);
        return getNameResource(params.get(0).toString());
    }

    public String rpcGetNameProof(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("name required", -8);
        return "{\"proof\":null,\"note\":\"Urkel proof not yet implemented\"}";
    }

    public String rpcGetNames(List<Object> params) {
        if (nameIndex == null)
            return error("Name index not ready", -1);
        return String.format(
                "[{\"total\":%d,\"note\":\"Use getnameinfo <name> for specific lookup\"}]",
                nameIndex.size());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String error(String msg, int code) {
        return String.format("{\"error\":{\"message\":\"%s\",\"code\":%d}}",
                msg, code);
    }
}