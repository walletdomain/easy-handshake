package handshake.node.api;

import handshake.database.Database;
import handshake.node.HNSPeer;

import java.math.BigInteger;
import java.util.List;

import static handshake.node.api.JsonBuilder.*;

/**
 * Chain, block, and header API methods.
 *
 * REST:
 *   GET /block/:hashOrHeight   → full block (verbose) or raw hex
 *   GET /header/:hashOrHeight  → header only
 *
 * RPC:
 *   getblockchaininfo, getbestblockhash, getblockcount,
 *   getblockhash, getdifficulty, getchaintips,
 *   getblock, getblockbyheight, getblockheader
 */
public class ChainApi {

    static final String NETWORK = "main";

    private final Database       db;
    private final ApiSerializer  serial;
    private final String         version;

    public ChainApi(Database db, String version) {
        this.db      = db;
        this.serial  = new ApiSerializer(db);
        this.version = version;
    }

    // ── REST ──────────────────────────────────────────────────────────────────

    public String getBlock(String hashOrHeight, boolean details) {
        int height = resolveHeight(hashOrHeight);
        if (height < 0) return error("Block not found: " + hashOrHeight, -5);
        byte[] raw = db.getRawBlock(height);
        if (raw == null) return error("Block not found at height " + height, -5);
        return details ? serial.serializeBlock(height, raw) : q(toHex(raw));
    }

    public String getHeader(String hashOrHeight) {
        int height = resolveHeight(hashOrHeight);
        if (height < 0) return error("Header not found: " + hashOrHeight, -5);
        byte[] raw = db.getHeaderAtHeight(height);
        if (raw == null) return error("Header not found at height " + height, -5);
        return serial.serializeHeader(HNSPeer.BlockHeader.parse(raw, 0), height);
    }

    // ── RPC ───────────────────────────────────────────────────────────────────

    public String rpcGetBlockchainInfo() {
        int    tip      = db.getTipHeight();
        double diff     = getDifficulty();
        double progress = tip > 0
                ? Math.min(1.0, (double) db.getBlockDataTip() / tip) : 0.0;

        return json(
                "chain",                q(NETWORK),
                "blocks",               str(tip),
                "headers",              str(tip),
                "bestblockhash",        q(hashAtHeight(tip)),
                "difficulty",           str(diff),
                "mediantime",           str(db.getMedianTime(tip)),
                "verificationprogress", str(progress),
                "chainwork",            q("0".repeat(64)),
                "pruned",               "false"
        );
    }

    public String rpcGetBestBlockHash() {
        return q(hashAtHeight(db.getTipHeight()));
    }

    public String rpcGetBlockCount() {
        return str(db.getTipHeight());
    }

    public String rpcGetBlockHash(List<Object> params) {
        if (params.isEmpty()) throw new JsonBuilder.RpcException("height required", -8);
        int    height = toInt(params.getFirst());
        byte[] hash   = db.getHashAtHeight(height);
        if (hash == null)
            throw new JsonBuilder.RpcException("Block not found at height " + height, -5);
        return q(toHex(hash));
    }

    public String rpcGetDifficulty() {
        return str(getDifficulty());
    }

    public String rpcGetChainTips() {
        int tip = db.getTipHeight();
        return "[" + json(
                "height",    str(tip),
                "hash",      q(hashAtHeight(tip)),
                "branchlen", "0",
                "status",    q("active")
        ) + "]";
    }

    public String rpcGetBlock(List<Object> params) {
        if (params.isEmpty()) throw new JsonBuilder.RpcException("hash required", -8);
        String hash    = str(params.getFirst());
        int    verbose = params.size() > 1 ? toInt(params.get(1)) : 1;
        int    height  = db.getHeightForHash(fromHex(hash));
        if (height < 0) throw new JsonBuilder.RpcException("Block not found", -5);
        byte[] raw = db.getRawBlock(height);
        if (raw == null) throw new JsonBuilder.RpcException("Block data not found", -5);
        return verbose == 0 ? q(toHex(raw)) : serial.serializeBlock(height, raw);
    }

    public String rpcGetBlockByHeight(List<Object> params) {
        if (params.isEmpty()) throw new JsonBuilder.RpcException("height required", -8);
        int    height  = toInt(params.getFirst());
        int    verbose = params.size() > 1 ? toInt(params.get(1)) : 1;
        byte[] raw     = db.getRawBlock(height);
        if (raw == null)
            throw new JsonBuilder.RpcException("Block not found at height " + height, -5);
        return verbose == 0 ? q(toHex(raw)) : serial.serializeBlock(height, raw);
    }

    public String rpcGetBlockHeader(List<Object> params) {
        if (params.isEmpty()) throw new JsonBuilder.RpcException("hash required", -8);
        int    height = db.getHeightForHash(fromHex(str(params.getFirst())));
        if (height < 0) throw new JsonBuilder.RpcException("Header not found", -5);
        byte[] raw    = db.getHeaderAtHeight(height);
        if (raw == null) throw new JsonBuilder.RpcException("Header not found", -5);
        return serial.serializeHeader(HNSPeer.BlockHeader.parse(raw, 0), height);
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    /** Resolves a hash string or decimal height string to a block height. */
    int resolveHeight(String hashOrHeight) {
        try {
            return Integer.parseInt(hashOrHeight);
        } catch (NumberFormatException e) {
            byte[] hash = fromHex(hashOrHeight);
            return hash != null ? db.getHeightForHash(hash) : -1;
        }
    }

    /** Returns block hash at height as hex, or 64 zeros if not found. */
    String hashAtHeight(int height) {
        byte[] hash = db.getHashAtHeight(height);
        return hash != null ? toHex(hash) : "0".repeat(64);
    }

    /** Computes current network difficulty from the tip header's bits field. */
    double getDifficulty() {
        byte[] raw = db.getHeaderAtHeight(db.getTipHeight());
        if (raw == null) return 1.0;
        HNSPeer.BlockHeader h = HNSPeer.BlockHeader.parse(raw, 0);
        BigInteger diff1   = Database.blockWork(0x207fffffL);
        BigInteger current = Database.blockWork(h.bits & 0xFFFFFFFFL);
        if (current.signum() == 0) return 1.0;
        return diff1.multiply(BigInteger.valueOf(100))
                .divide(current).doubleValue() / 100.0;
    }
}