package handshake.node;

import handshake.database.Database;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Implements the Handshake node REST and JSON-RPC APIs.
 *
 * REST endpoints (matching HSD's HTTP API):
 *   GET  /                        → server info
 *   GET  /block/:hashOrHeight     → full block
 *   GET  /header/:hashOrHeight    → header only
 *   GET  /tx/:txhash              → transaction by hash
 *   GET  /coin/:txhash/:index     → UTXO by outpoint
 *
 * JSON-RPC endpoint:
 *   POST /                        → JSON-RPC dispatcher
 *
 * All methods return JSON strings ready to send as HTTP responses.
 * Errors are returned as {"error": {"message": "...", "code": N}}.
 */
public class ApiHandler {

    private static final String NETWORK   = "main";
    private static final int    HNS_PORT  = 44806;
    private static final String USER_AGENT = "/easy-handshake:1.0.0/";

    private final Database db;
    private final String   version;

    public ApiHandler(Database db, String version) {
        this.db      = db;
        this.version = version;
    }

    // =========================================================================
    // REST API
    // =========================================================================

    // ── GET / ────────────────────────────────────────────────────────────────

    @SuppressWarnings("unused") // served at GET / (planned REST route)
    public String getServerInfo() {
        int tip = db.getTipHeight();
        return json(
                "version", q(version),
                "network", q(NETWORK),
                "chain", raw(json(
                        "height", str(tip),
                        "tip",    q(hashAtHeight(tip)),
                        "progress", str(tip > 0 ? 1.0 : 0.0)
                )),
                "pool", raw(json(
                        "host",    q("0.0.0.0"),
                        "port",    str(HNS_PORT),
                        "agent",   q(USER_AGENT)
                )),
                "mempool", raw(json(
                        "tx",   "0",
                        "size", "0"
                ))
        );
    }

    // ── GET /block/:hashOrHeight ─────────────────────────────────────────────

    public String getBlock(String hashOrHeight, boolean details) {
        int height = resolveHeight(hashOrHeight);
        if (height < 0) return error("Block not found: " + hashOrHeight, -5);

        byte[] raw = db.getRawBlock(height);
        if (raw == null) return error("Block not found at height " + height, -5);

        if (!details) return q(toHex(raw));

        return serializeBlock(height, raw);
    }

    // ── GET /header/:hashOrHeight ────────────────────────────────────────────

    public String getHeader(String hashOrHeight) {
        int height = resolveHeight(hashOrHeight);
        if (height < 0) return error("Header not found: " + hashOrHeight, -5);

        byte[] raw = db.getHeaderAtHeight(height);
        if (raw == null) return error("Header not found at height " + height, -5);

        HNSPeer.BlockHeader h = HNSPeer.BlockHeader.parse(raw, 0);
        return serializeHeader(h, height);
    }

    // ── GET /tx/:txhash ──────────────────────────────────────────────────────

    public String getTx(String txhash) {
        byte[] txid = fromHex(txhash);
        if (txid == null || txid.length != 32)
            return error("Invalid txhash", -8);

        // Scan recent blocks for the transaction
        // NOTE: without a tx index this requires scanning blocks.
        // We scan from the tip backward up to a reasonable limit.
        int tip = db.getBlockDataTip();
        for (int h = tip; h >= Math.max(0, tip - 10000); h--) {
            byte[] raw = db.getRawBlock(h);
            if (raw == null) continue;
            HNSBlock block = HNSBlock.parse(raw);
            for (HNSBlock.Tx tx : block.txs) {
                byte[] id = computeTxId(tx);
                if (Arrays.equals(id, txid))
                    return serializeTx(tx, id, h);
            }
        }
        return error("Transaction not found: " + txhash, -5);
    }

    // ── GET /coin/:txhash/:index ─────────────────────────────────────────────

    public String getCoin(String txhash, int index) {
        byte[] txid = fromHex(txhash);
        if (txid == null || txid.length != 32)
            return error("Invalid txhash", -8);

        byte[] coin = db.getUtxo(txid, index);
        if (coin == null)
            return error("Coin not found: " + txhash + "/" + index, -5);

        return serializeCoin(txid, index, coin);
    }

    // =========================================================================
    // JSON-RPC dispatcher
    // =========================================================================

    /**
     * Dispatches a JSON-RPC request.
     * @param method  the RPC method name
     * @param params  parsed parameter list (strings/numbers/booleans)
     * @param id      the request id (for response)
     * @return full JSON-RPC response string
     */
    public String rpc(String method, List<Object> params, Object id) {
        try {
            String result = dispatch(method, params);
            return rpcResponse(result, id);
        } catch (RpcException e) {
            return rpcError(e.getMessage(), e.code, id);
        } catch (Exception e) {
            return rpcError(e.getMessage(), -32603, id);
        }
    }

    private String dispatch(String method, List<Object> params) {
        return switch (method.toLowerCase()) {

            // ── Chain ─────────────────────────────────────────────────────
            case "getblockchaininfo"  -> rpcGetBlockchainInfo();
            case "getbestblockhash"   -> q(hashAtHeight(db.getTipHeight()));
            case "getblockcount"      -> str(db.getTipHeight());
            case "getblockhash"       -> rpcGetBlockHash(params);
            case "getdifficulty"      -> str(getDifficulty());
            case "getchaintips"       -> rpcGetChainTips();

            // ── Blocks ────────────────────────────────────────────────────
            case "getblock"           -> rpcGetBlock(params);
            case "getblockbyheight"   -> rpcGetBlockByHeight(params);
            case "getblockheader"     -> rpcGetBlockHeader(params);

            // ── Transactions ──────────────────────────────────────────────
            case "getrawtransaction"    -> rpcGetRawTransaction(params);
            case "decoderawtransaction" -> rpcDecodeRawTransaction(params);
            case "sendrawtransaction"   -> rpcSendRawTransaction(params);

            // ── UTXO ──────────────────────────────────────────────────────
            case "gettxout"           -> rpcGetTxOut(params);
            case "gettxoutsetinfo"    -> rpcGetTxOutSetInfo();

            // ── Network ───────────────────────────────────────────────────
            case "getinfo"            -> rpcGetInfo();
            case "getnetworkinfo"     -> rpcGetNetworkInfo();
            case "getconnectioncount" -> "0";
            case "getpeerinfo"        -> "[]";
            case "getrawmempool"      -> rpcGetRawMempool();

            // ── Mempool stubs ─────────────────────────────────────────────
            case "getmempoolinfo"     -> json(
                    "size",  "0",
                    "bytes", "0",
                    "usage", "0"
            );
            case "estimatefee"        -> str(0.01);

            // ── Node ──────────────────────────────────────────────────────
            case "stop"               -> q("Stopping.");
            case "getmemoryinfo"      -> rpcGetMemoryInfo();

            default -> throw new RpcException("Method not found: " + method, -32601);
        };
    }

    // =========================================================================
    // RPC implementations
    // =========================================================================

    private String rpcGetBlockchainInfo() {
        int    tip      = db.getTipHeight();
        String tipHash  = hashAtHeight(tip);
        double diff     = getDifficulty();
        double progress = tip > 0 ? Math.min(1.0,
                (double) db.getBlockDataTip() / tip) : 0.0;

        return json(
                "chain",                q(NETWORK),
                "blocks",               str(tip),
                "headers",              str(tip),
                "bestblockhash",        q(tipHash),
                "difficulty",           str(diff),
                "mediantime",           str(db.getMedianTime(tip)),
                "verificationprogress", str(progress),
                "chainwork",            q("0".repeat(64)),
                "pruned",               "false"
        );
    }

    private String rpcGetBlockHash(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("height required", -8);
        int height = toInt(params.getFirst());
        byte[] hash = db.getHashAtHeight(height);
        if (hash == null) throw new RpcException("Block not found at height " + height, -5);
        return q(toHex(hash));
    }

    private String rpcGetChainTips() {
        int    tip  = db.getTipHeight();
        String hash = hashAtHeight(tip);
        return "[" + json(
                "height",    str(tip),
                "hash",      q(hash),
                "branchlen", "0",
                "status",    q("active")
        ) + "]";
    }

    private String rpcGetBlock(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("hash required", -8);
        String hash    = str(params.getFirst());
        int    verbose = params.size() > 1 ? toInt(params.get(1)) : 1;
        int    height  = db.getHeightForHash(fromHex(hash));
        if (height < 0) throw new RpcException("Block not found", -5);
        byte[] raw = db.getRawBlock(height);
        if (raw == null) throw new RpcException("Block data not found", -5);
        if (verbose == 0) return q(toHex(raw));
        return serializeBlock(height, raw);
    }

    private String rpcGetBlockByHeight(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("height required", -8);
        int    height  = toInt(params.getFirst());
        int    verbose = params.size() > 1 ? toInt(params.get(1)) : 1;
        byte[] raw     = db.getRawBlock(height);
        if (raw == null) throw new RpcException("Block not found at height " + height, -5);
        if (verbose == 0) return q(toHex(raw));
        return serializeBlock(height, raw);
    }

    private String rpcGetBlockHeader(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("hash required", -8);
        String hash   = str(params.getFirst());
        int    height = db.getHeightForHash(fromHex(hash));
        if (height < 0) throw new RpcException("Header not found", -5);
        byte[] raw = db.getHeaderAtHeight(height);
        if (raw == null) throw new RpcException("Header not found", -5);
        HNSPeer.BlockHeader h = HNSPeer.BlockHeader.parse(raw, 0);
        return serializeHeader(h, height);
    }

    private String rpcGetRawTransaction(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("txhash required", -8);
        String txhash = str(params.getFirst());
        boolean verbose = params.size() > 1 && toInt(params.get(1)) == 1;

        byte[] txid = fromHex(txhash);
        if (txid == null) throw new RpcException("Invalid txhash", -8);

        int tip = db.getBlockDataTip();
        for (int h = tip; h >= Math.max(0, tip - 10000); h--) {
            byte[] raw = db.getRawBlock(h);
            if (raw == null) continue;
            HNSBlock block = HNSBlock.parse(raw);
            for (HNSBlock.Tx tx : block.txs) {
                byte[] id = computeTxId(tx);
                if (Arrays.equals(id, txid)) {
                    if (!verbose) return q(toHex(tx.raw));
                    return serializeTx(tx, id, h);
                }
            }
        }
        throw new RpcException("Transaction not found", -5);
    }

    private String rpcDecodeRawTransaction(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("rawhex required", -8);
        byte[] raw = fromHex(str(params.getFirst()));
        if (raw == null) throw new RpcException("Invalid hex", -8);
        try {
            HNSBlock.Tx tx = HNSBlock.Tx.parse(raw, 0);
            return serializeTx(tx, computeTxId(tx), -1);
        } catch (Exception e) {
            throw new RpcException("Could not decode transaction: " + e.getMessage(), -22);
        }
    }

    private String rpcGetRawMempool() {
        java.util.List<String> txids = handshake.node.HNSMempool.get().getSnapshot();
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < txids.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(txids.get(i)).append("\"");
        }
        return sb.append("]").toString();
    }

    private String rpcSendRawTransaction(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("rawhex required", -8);
        byte[] raw = fromHex(str(params.getFirst()));
        if (raw == null) throw new RpcException("Invalid hex", -8);

        // Parse to verify it's a valid transaction
        HNSBlock.Tx tx;
        try {
            tx = HNSBlock.Tx.parse(raw, 0);
        } catch (Exception e) {
            throw new RpcException("Could not decode transaction: " + e.getMessage(), -22);
        }

        // Compute txid
        String txid = toHex(computeTxId(tx));

        // Broadcast to peers
        handshake.wallet.HNSTxBuilder.SignedTx signed =
                new handshake.wallet.HNSTxBuilder.SignedTx(raw, txid, 0);
        handshake.wallet.HNSBroadcaster.BroadcastResult result =
                handshake.wallet.HNSBroadcaster.broadcast(signed);

        if (result.success)
            return q(txid);
        else
            throw new RpcException(
                    "Broadcast failed: " + (result.errorMessage != null
                            ? result.errorMessage : "no peers accepted"), -25);
    }

    private String rpcGetTxOut(List<Object> params) {
        if (params.size() < 2) throw new RpcException("txhash and index required", -8);
        byte[] txid  = fromHex(str(params.getFirst()));
        int    index = toInt(params.get(1));
        if (txid == null) throw new RpcException("Invalid txhash", -8);
        byte[] coin = db.getUtxo(txid, index);
        if (coin == null) return "null"; // unspent not found — return null per HSD spec
        return serializeCoin(txid, index, coin);
    }

    private String rpcGetTxOutSetInfo() {
        return json(
                "height",        str(db.getTipHeight()),
                "bestblock",     q(hashAtHeight(db.getTipHeight())),
                "transactions",  "0",
                "txouts",        str(db.getUtxoCount()),
                "bogosize",      "0",
                "disk_size",     str(db.getStoreSize())
        );
    }

    private String rpcGetInfo() {
        int tip = db.getTipHeight();
        return json(
                "version",         q(version),
                "protocolversion", "70015",
                "walletversion",   "0",
                "balance",         "0",
                "blocks",          str(tip),
                "timeoffset",      "0",
                "connections",     "0",
                "difficulty",      str(getDifficulty()),
                "testnet",         "false",
                "keypoolsize",     "0",
                "paytxfee",        "0",
                "relayfee",        "0.00001",
                "errors",          q("")
        );
    }

    private String rpcGetNetworkInfo() {
        return json(
                "version",         q(version),
                "subversion",      q(USER_AGENT),
                "protocolversion", "70015",
                "localservices",   q("000000000000040d"),
                "localrelay",      "true",
                "timeoffset",      "0",
                "networkactive",   "true",
                "connections",     "0",
                "relayfee",        "0.00001",
                "incrementalfee",  "0.00001"
        );
    }

    private String rpcGetMemoryInfo() {
        Runtime rt = Runtime.getRuntime();
        long usedMB  = (rt.totalMemory() - rt.freeMemory()) / 1_048_576;
        long totalMB = rt.totalMemory() / 1_048_576;
        long maxMB   = rt.maxMemory() / 1_048_576;
        return json(
                "used",  str(usedMB),
                "total", str(totalMB),
                "max",   str(maxMB),
                "free",  str(totalMB - usedMB)
        );
    }

    // =========================================================================
    // Serialization helpers
    // =========================================================================

    private String serializeBlock(int height, byte[] rawBlock) {
        HNSBlock          block  = HNSBlock.parse(rawBlock);
        byte[]            hdrRaw = db.getHeaderAtHeight(height);
        HNSPeer.BlockHeader hdr  = hdrRaw != null
                ? HNSPeer.BlockHeader.parse(hdrRaw, 0) : null;
        byte[] hash = db.getHashAtHeight(height);

        // Build tx array
        StringBuilder txArr = new StringBuilder("[");
        for (int i = 0; i < block.txs.size(); i++) {
            if (i > 0) txArr.append(',');
            HNSBlock.Tx tx = block.txs.get(i);
            txArr.append(serializeTx(tx, computeTxId(tx), height));
        }
        txArr.append(']');

        return json(
                "hash",         q(hash != null ? toHex(hash) : ""),
                "height",       str(height),
                "depth",        str(db.getTipHeight() - height),
                "version",      str(hdr != null ? hdr.version : 0),
                "prevBlock",    q(hdr != null ? toHex(hdr.prevBlock) : ""),
                "merkleRoot",   q(hdr != null ? toHex(hdr.merkleRoot) : ""),
                "witnessRoot",  q(hdr != null ? toHex(hdr.witnessRoot) : ""),
                "treeRoot",     q(hdr != null ? toHex(hdr.treeRoot) : ""),
                "reservedRoot", q(hdr != null ? toHex(hdr.reservedRoot) : ""),
                "time",         str(hdr != null ? hdr.time : 0),
                "bits",         str(hdr != null ? hdr.bits : 0),
                "nonce",        str(hdr != null ? hdr.nonce : 0),
                "txs",          raw(txArr.toString()),
                "size",         str(rawBlock.length),
                "strippedsize", str(rawBlock.length)
        );
    }

    private String serializeHeader(HNSPeer.BlockHeader h, int height) {
        byte[] hash = db.getHashAtHeight(height);
        return json(
                "hash",         q(hash != null ? toHex(hash) : ""),
                "height",       str(height),
                "depth",        str(db.getTipHeight() - height),
                "version",      str(h.version),
                "prevBlock",    q(toHex(h.prevBlock)),
                "merkleRoot",   q(toHex(h.merkleRoot)),
                "witnessRoot",  q(toHex(h.witnessRoot)),
                "treeRoot",     q(toHex(h.treeRoot)),
                "reservedRoot", q(toHex(h.reservedRoot)),
                "time",         str(h.time),
                "bits",         str(h.bits),
                "nonce",        str(h.nonce)
        );
    }

    private String serializeTx(HNSBlock.Tx tx, byte[] txid, int height) {
        // Inputs
        StringBuilder inputs = new StringBuilder("[");
        for (int i = 0; i < tx.inputs.size(); i++) {
            if (i > 0) inputs.append(',');
            HNSBlock.Input inp = tx.inputs.get(i);
            inputs.append(json(
                    "prevout", raw(json(
                            "hash",  q(toHex(inp.prevHash)),
                            "index", str(inp.prevIndex)
                    )),
                    "sequence", str(inp.sequence)
            ));
        }
        inputs.append(']');

        // Outputs
        StringBuilder outputs = new StringBuilder("[");
        for (int i = 0; i < tx.outputs.size(); i++) {
            if (i > 0) outputs.append(',');
            HNSBlock.Output out = tx.outputs.get(i);
            String addr = encodeAddress(out.addrVersion, out.addrHash);
            outputs.append(json(
                    "value",    str(out.value),
                    "address",  q(addr),
                    "covenant", raw(serializeCovenant(out.covenant))
            ));
        }
        outputs.append(']');

        return json(
                "hash",     q(txid != null ? toHex(txid) : ""),
                "version",  str(tx.version),
                "locktime", str(tx.locktime),
                "inputs",   raw(inputs.toString()),
                "outputs",  raw(outputs.toString()),
                "height",   str(height),
                "size",     str(tx.rawSize)
        );
    }

    private String serializeCovenant(HNSBlock.Covenant cov) {
        if (cov == null)
            return json("type", "0", "action", q("NONE"), "items", raw("[]"));

        String action = switch (cov.type) {
            case HNSBlock.Covenant.NONE     -> "NONE";
            case HNSBlock.Covenant.CLAIM    -> "CLAIM";
            case HNSBlock.Covenant.OPEN     -> "OPEN";
            case HNSBlock.Covenant.BID      -> "BID";
            case HNSBlock.Covenant.REVEAL   -> "REVEAL";
            case HNSBlock.Covenant.REDEEM   -> "REDEEM";
            case HNSBlock.Covenant.REGISTER -> "REGISTER";
            case HNSBlock.Covenant.UPDATE   -> "UPDATE";
            case HNSBlock.Covenant.RENEW    -> "RENEW";
            case HNSBlock.Covenant.TRANSFER -> "TRANSFER";
            case HNSBlock.Covenant.FINALIZE -> "FINALIZE";
            case HNSBlock.Covenant.REVOKE   -> "REVOKE";
            default                         -> "UNKNOWN";
        };

        StringBuilder items = new StringBuilder("[");
        for (int i = 0; i < cov.items.size(); i++) {
            if (i > 0) items.append(',');
            items.append(q(toHex(cov.items.get(i))));
        }
        items.append(']');

        return json(
                "type",   str(cov.type),
                "action", q(action),
                "items",  raw(items.toString())
        );
    }

    private String serializeCoin(byte[] txid, int index, byte[] coin) {
        // Decode coin bytes: value(8 LE) + addrVersion(1) + addrHashLen(1)
        //                    + addrHash(N) + covenantType(1)
        long  value      = 0;
        for (int i = 0; i < 8; i++) value |= (coin[i] & 0xFFL) << (8 * i);
        int   addrVer    = coin[8] & 0xFF;
        int   hashLen    = coin[9] & 0xFF;
        byte[] addrHash  = hashLen > 0
                ? Arrays.copyOfRange(coin, 10, 10 + hashLen) : new byte[0];
        String addr      = encodeAddress(addrVer, addrHash);

        return json(
                "version",  str(addrVer),
                "height",   "-1",
                "value",    str(value),
                "address",  q(addr),
                "coinbase", "false",
                "hash",     q(toHex(txid)),
                "index",    str(index)
        );
    }

    // =========================================================================
    // Utility helpers
    // =========================================================================

    /** Resolves a hash string or height string to a block height. */
    private int resolveHeight(String hashOrHeight) {
        try {
            return Integer.parseInt(hashOrHeight);
        } catch (NumberFormatException e) {
            byte[] hash = fromHex(hashOrHeight);
            return hash != null ? db.getHeightForHash(hash) : -1;
        }
    }

    /** Returns the block hash at height as a hex string, or zeros if not found. */
    private String hashAtHeight(int height) {
        byte[] hash = db.getHashAtHeight(height);
        return hash != null ? toHex(hash) : "0".repeat(64);
    }

    /** Computes current difficulty from the tip's bits field. */
    private double getDifficulty() {
        int    tip = db.getTipHeight();
        byte[] raw = db.getHeaderAtHeight(tip);
        if (raw == null) return 1.0;
        HNSPeer.BlockHeader h = HNSPeer.BlockHeader.parse(raw, 0);
        // difficulty = difficulty_1_target / current_target
        // difficulty_1_target for HNS (0x207fffff)
        BigInteger diff1  = Database.blockWork(0x207fffffL);
        BigInteger current = Database.blockWork(h.bits & 0xFFFFFFFFL);
        if (current.signum() == 0) return 1.0;
        return diff1.multiply(BigInteger.valueOf(100))
                .divide(current).doubleValue() / 100.0;
    }

    /** Computes txid = Blake2b-256 of base (non-witness) tx bytes. */
    private static byte[] computeTxId(HNSBlock.Tx tx) {
        int witnessSize = 0;
        for (HNSBlock.Witness w : tx.witnesses) witnessSize += w.size;
        byte[] base = Arrays.copyOf(tx.raw, tx.raw.length - witnessSize);
        return HNSPeer.Blake2b.hash(base, 32);
    }

    /**
     * Encodes a Handshake address in bech32 format.
     *
     * Handshake uses standard bech32 (BIP 173) with:
     *   HRP = "hs"  (mainnet)
     *   witness version prepended to the 5-bit data array
     *
     * Version 0 produces addresses starting with "hs1q..."
     * The 'q' is the bech32 encoding of witness version 0.
     */
    private static String encodeAddress(int version, byte[] hash) {
        if (hash == null || hash.length == 0) return "";
        try {
            return bech32Encode(version, hash);
        } catch (Exception e) {
            return "";
        }
    }

    /** Bech32 character set. */
    private static final String BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /**
     * Encodes data as a bech32 string with HRP "hs" (Handshake mainnet).
     * @param version witness version (0-16)
     * @param data    raw bytes to encode
     */
    private static String bech32Encode(int version, byte[] data) {
        final String hrp = "hs";
        int[] conv   = convertBits(data);
        int[] values = new int[1 + conv.length];
        values[0] = version;
        System.arraycopy(conv, 0, values, 1, conv.length);

        int[] checksum = bech32Checksum(values);

        StringBuilder sb = new StringBuilder(hrp);
        sb.append('1');
        for (int v : values)   sb.append(BECH32_CHARSET.charAt(v));
        for (int c : checksum) sb.append(BECH32_CHARSET.charAt(c));
        return sb.toString();
    }

    /** Converts 8-bit bytes to 5-bit bech32 groups with padding. */
    private static int[] convertBits(byte[] data) {
        final int fromBits = 8, toBits = 5;
        int acc = 0, bits = 0;
        int maxv = (1 << toBits) - 1;
        java.util.List<Integer> result = new java.util.ArrayList<>();

        for (byte b : data) {
            acc = (acc << fromBits) | (b & 0xFF);
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result.add((acc >> bits) & maxv);
            }
        }
        // pad = true
        if (bits > 0) result.add((acc << (toBits - bits)) & maxv);
        return result.stream().mapToInt(Integer::intValue).toArray();
    }

    /** Computes the bech32 checksum for HRP "hs" and the given data. */
    private static int[] bech32Checksum(int[] data) {
        final String hrp = "hs";
        int[] enc = new int[hrp.length() * 2 + 1 + data.length + 6];
        int pos = 0;

        // HRP expanded: high bits, then 0, then low bits
        for (char c : hrp.toCharArray()) enc[pos++] = c >> 5;
        enc[pos++] = 0;
        for (char c : hrp.toCharArray()) enc[pos++] = c & 31;

        // Data
        for (int v : data) enc[pos++] = v;

        // Six zero bytes for checksum placeholder
        // (already zero from array initialization)

        long mod = bech32Polymod(enc) ^ 1;
        int[] checksum = new int[6];
        for (int i = 0; i < 6; i++)
            checksum[i] = (int)((mod >> (5 * (5 - i))) & 31);
        return checksum;
    }

    /** GF(2^5) generator polynomial for bech32. */
    private static final long[] BECH32_GEN = {
            0x3b6a57b2L, 0x26508e6dL, 0x1ea119faL, 0x3d4233ddL, 0x2a1462b3L
    };

    private static long bech32Polymod(int[] values) {
        long chk = 1;
        for (int v : values) {
            long top = chk >> 25;
            chk = (chk & 0x1ffffffL) << 5 ^ v;
            for (int i = 0; i < 5; i++)
                if (((top >> i) & 1) != 0) chk ^= BECH32_GEN[i];
        }
        return chk;
    }

    // =========================================================================
    // JSON-RPC envelope helpers
    // =========================================================================

    private static String rpcResponse(String result, Object id) {
        return "{\"id\":" + jsonId(id) + ",\"result\":" + result + ",\"error\":null}";
    }

    private static String rpcError(String msg, int code, Object id) {
        return "{\"id\":" + jsonId(id) + ",\"result\":null,\"error\":"
                + json("message", q(msg), "code", str(code)) + "}";
    }

    private static String jsonId(Object id) {
        if (id == null)  return "null";
        if (id instanceof Number) return id.toString();
        return q(id.toString());
    }

    // =========================================================================
    // JSON builder (simple, no library needed)
    // =========================================================================

    /** Builds a JSON object from alternating key/value pairs. */
    static String json(String... kv) {
        if (kv.length % 2 != 0) throw new IllegalArgumentException("kv must be pairs");
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append('"').append(kv[i]).append("\":").append(kv[i+1]);
        }
        return sb.append('}').toString();
    }

    /** Quotes a string value. Escapes special characters. */
    static String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n") + "\"";
    }

    /** Returns a raw JSON fragment (number, boolean, array, nested object). */
    static String raw(String s) { return s; }

    /** Converts a value to its JSON string representation. */
    static String str(Object v) {
        if (v instanceof Double d) return String.format("%.8f", d);
        return v.toString();
    }

    // =========================================================================
    // Error helpers
    // =========================================================================

    static String error(String msg, int code) {
        return json("error", raw(json("message", q(msg), "code", str(code))));
    }

    static class RpcException extends RuntimeException {
        final int code;
        RpcException(String msg, int code) { super(msg); this.code = code; }
    }

    // =========================================================================
    // Byte/hex helpers
    // =========================================================================

    static String toHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static byte[] fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) return null;
        try {
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < b.length; i++)
                b[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
            return b;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static int toInt(Object v) {
        if (v instanceof Number n) return n.intValue();
        try { return Integer.parseInt(v.toString()); }
        catch (NumberFormatException e) {
            throw new RpcException("Expected integer, got: " + v, -8);
        }
    }
}