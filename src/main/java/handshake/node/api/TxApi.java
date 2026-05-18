package handshake.node.api;

import handshake.database.Database;
import handshake.node.HNSBlock;

import java.util.Arrays;
import java.util.List;

import static handshake.node.api.JsonBuilder.*;
import static handshake.node.api.ApiSerializer.computeTxId;

/**
 * Transaction and UTXO/coin API methods.
 *
 * REST:
 *   GET /tx/:txhash            → transaction by hash
 *   GET /coin/:txhash/:index   → UTXO by outpoint
 *
 * RPC:
 *   getrawtransaction, decoderawtransaction,
 *   gettxout, gettxoutsetinfo
 */
public class TxApi {

    private final Database      db;
    private final ApiSerializer serial;

    public TxApi(Database db) {
        this.db     = db;
        this.serial = new ApiSerializer(db);
    }

    // ── REST ──────────────────────────────────────────────────────────────────

    public String getTx(String txhash) {
        byte[] txid = fromHex(txhash);
        if (txid == null || txid.length != 32)
            return error("Invalid txhash", -8);

        TxResult result = findTx(txid);
        if (result == null)
            return error("Transaction not found: " + txhash, -5);

        return serial.serializeTx(result.tx, txid, result.height);
    }

    public String getCoin(String txhash, int index) {
        byte[] txid = fromHex(txhash);
        if (txid == null || txid.length != 32)
            return error("Invalid txhash", -8);

        byte[] coin = db.getUtxo(txid, index);
        if (coin == null)
            return error("Coin not found: " + txhash + "/" + index, -5);

        return serial.serializeCoin(txid, index, coin);
    }

    // ── RPC ───────────────────────────────────────────────────────────────────

    public String rpcGetRawTransaction(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("txhash required", -8);
        String  txhash  = str(params.getFirst());
        boolean verbose = params.size() > 1 && toInt(params.get(1)) == 1;

        byte[] txid = fromHex(txhash);
        if (txid == null) throw new RpcException("Invalid txhash", -8);

        TxResult result = findTx(txid);
        if (result == null) throw new RpcException("Transaction not found", -5);

        return verbose
                ? serial.serializeTx(result.tx, txid, result.height)
                : q(toHex(result.tx.raw));
    }

    public String rpcDecodeRawTransaction(List<Object> params) {
        if (params.isEmpty()) throw new RpcException("rawhex required", -8);
        byte[] raw = fromHex(str(params.getFirst()));
        if (raw == null) throw new RpcException("Invalid hex", -8);
        try {
            HNSBlock.Tx tx = HNSBlock.Tx.parse(raw, 0);
            return serial.serializeTx(tx, computeTxId(tx), -1);
        } catch (Exception e) {
            throw new RpcException("Could not decode transaction: "
                    + e.getMessage(), -22);
        }
    }

    public String rpcGetTxOut(List<Object> params) {
        if (params.size() < 2) throw new RpcException("txhash and index required", -8);
        byte[] txid  = fromHex(str(params.getFirst()));
        int    index = toInt(params.get(1));
        if (txid == null) throw new RpcException("Invalid txhash", -8);
        byte[] coin = db.getUtxo(txid, index);
        if (coin == null) return "null"; // per HSD spec: null if spent/missing
        return serial.serializeCoin(txid, index, coin);
    }

    public String rpcGetTxOutSetInfo() {
        int tip = db.getTipHeight();
        return json(
                "height",       str(tip),
                "bestblock",    q(toHex(db.getHashAtHeight(tip))),
                "transactions", "0",
                "txouts",       str(db.getUtxoCount()),
                "bogosize",     "0",
                "disk_size",    str(db.getStoreSize())
        );
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    /**
     * Scans recent blocks (up to 10,000 from tip) to find a transaction by id.
     * NOTE: a full tx index would make this O(1) — planned for future release.
     */
    private TxResult findTx(byte[] txid) {
        int tip = db.getBlockDataTip();
        for (int h = tip; h >= Math.max(0, tip - 10_000); h--) {
            byte[] raw = db.getRawBlock(h);
            if (raw == null) continue;
            HNSBlock block = HNSBlock.parse(raw);
            for (HNSBlock.Tx tx : block.txs) {
                if (Arrays.equals(computeTxId(tx), txid))
                    return new TxResult(tx, h);
            }
        }
        return null;
    }

    private record TxResult(HNSBlock.Tx tx, int height) {}
}