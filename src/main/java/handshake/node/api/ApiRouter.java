package handshake.node.api;

import handshake.database.Database;

import java.time.Instant;
import java.util.List;

import static handshake.node.api.JsonBuilder.*;

/**
 * Central API router for Easy Handshake node.
 *
 * Routes REST requests and JSON-RPC method calls to the appropriate
 * API class. NodeHttpServer calls this class exclusively — it never
 * needs to know which category a method belongs to.
 *
 * API classes:
 *   ChainApi   — chain info, blocks, headers
 *   TxApi      — transactions, UTXOs
 *   NodeApi    — node/network info, mempool stubs
 *   NameApi    — Handshake names and DNS records (planned)
 *   WalletApi  — wallet operations (planned)
 *   MinerApi   — mining/stratum (planned)
 */
public class ApiRouter {

    private final ChainApi chain;
    private final TxApi    tx;
    private final NodeApi  node;
    private final NameApi  name;

    public ApiRouter(Database db, String version, Instant startTime) {
        this.chain = new ChainApi(db, version);
        this.tx    = new TxApi(db);
        this.node  = new NodeApi(db, version, startTime);
        this.name  = new NameApi(db);
    }

    // =========================================================================
    // REST API
    // =========================================================================

    public String getBlock(String hashOrHeight, boolean details) {
        return chain.getBlock(hashOrHeight, details);
    }

    public String getHeader(String hashOrHeight) {
        return chain.getHeader(hashOrHeight);
    }

    public String getTx(String txhash) {
        return tx.getTx(txhash);
    }

    public String getCoin(String txhash, int index) {
        return tx.getCoin(txhash, index);
    }

    public String getNameInfo(String nameStr) {
        return name.getNameInfo(nameStr);
    }

    public String getNameResource(String nameStr) {
        return name.getNameResource(nameStr);
    }

    // =========================================================================
    // JSON-RPC dispatcher
    // =========================================================================

    /**
     * Dispatches a JSON-RPC request and returns the full response envelope.
     */
    public String rpc(String method, List<Object> params, Object id) {
        try {
            String result = dispatch(method, params);
            return rpcResponse(result, id);
        } catch (JsonBuilder.RpcException e) {
            return rpcError(e.getMessage(), e.code, id);
        } catch (Exception e) {
            return rpcError(e.getMessage() != null
                    ? e.getMessage() : "Internal error", -32603, id);
        }
    }

    private String dispatch(String method, List<Object> params) {
        return switch (method.toLowerCase()) {

            // ── Chain ─────────────────────────────────────────────────────
            case "getblockchaininfo"    -> chain.rpcGetBlockchainInfo();
            case "getbestblockhash"     -> chain.rpcGetBestBlockHash();
            case "getblockcount"        -> chain.rpcGetBlockCount();
            case "getblockhash"         -> chain.rpcGetBlockHash(params);
            case "getdifficulty"        -> chain.rpcGetDifficulty();
            case "getchaintips"         -> chain.rpcGetChainTips();

            // ── Blocks ────────────────────────────────────────────────────
            case "getblock"             -> chain.rpcGetBlock(params);
            case "getblockbyheight"     -> chain.rpcGetBlockByHeight(params);
            case "getblockheader"       -> chain.rpcGetBlockHeader(params);

            // ── Transactions ──────────────────────────────────────────────
            case "getrawtransaction"    -> tx.rpcGetRawTransaction(params);
            case "decoderawtransaction" -> tx.rpcDecodeRawTransaction(params);

            // ── UTXO ──────────────────────────────────────────────────────
            case "gettxout"             -> tx.rpcGetTxOut(params);
            case "gettxoutsetinfo"      -> tx.rpcGetTxOutSetInfo();

            // ── Names ─────────────────────────────────────────────────────
            case "getnameinfo"          -> name.rpcGetNameInfo(params);
            case "getnameresource"      -> name.rpcGetNameResource(params);

            // ── Node ──────────────────────────────────────────────────────
            case "getinfo"              -> node.rpcGetInfo();
            case "getnetworkinfo"       -> node.rpcGetNetworkInfo();
            case "getmemoryinfo"        -> node.rpcGetMemoryInfo();
            case "getmempoolinfo"       -> node.rpcGetMempoolInfo();
            case "getconnectioncount"   -> "0";
            case "getpeerinfo",
                 "getrawmempool"        -> "[]";
            case "estimatefee"          -> str(0.01);
            case "stop"                 -> q("Stopping.");

            default -> throw new JsonBuilder.RpcException(
                    "Method not found: " + method, -32601);
        };
    }
}