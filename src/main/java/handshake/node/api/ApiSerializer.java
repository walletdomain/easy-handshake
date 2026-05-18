package handshake.node.api;

import handshake.database.Database;
import handshake.node.HNSBlock;
import handshake.node.HNSPeer;

import java.util.Arrays;

import static handshake.node.api.JsonBuilder.*;

/**
 * Serializes blockchain objects (blocks, headers, transactions,
 * covenants, coins) to JSON strings for API responses.
 *
 * Used by ChainApi, TxApi, and CoinApi.
 */
public class ApiSerializer {

    private final Database db;

    public ApiSerializer(Database db) {
        this.db = db;
    }

    // ── Block ─────────────────────────────────────────────────────────────────

    public String serializeBlock(int height, byte[] rawBlock) {
        HNSBlock            block  = HNSBlock.parse(rawBlock);
        byte[]              hdrRaw = db.getHeaderAtHeight(height);
        HNSPeer.BlockHeader hdr    = hdrRaw != null
                ? HNSPeer.BlockHeader.parse(hdrRaw, 0) : null;
        byte[] hash = db.getHashAtHeight(height);

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

    // ── Header ────────────────────────────────────────────────────────────────

    public String serializeHeader(HNSPeer.BlockHeader h, int height) {
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

    // ── Transaction ───────────────────────────────────────────────────────────

    public String serializeTx(HNSBlock.Tx tx, byte[] txid, int height) {
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

        StringBuilder outputs = new StringBuilder("[");
        for (int i = 0; i < tx.outputs.size(); i++) {
            if (i > 0) outputs.append(',');
            HNSBlock.Output out  = tx.outputs.get(i);
            String          addr = Bech32.encode(out.addrVersion, out.addrHash);
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

    // ── Covenant ──────────────────────────────────────────────────────────────

    public String serializeCovenant(HNSBlock.Covenant cov) {
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

    // ── Coin (UTXO) ───────────────────────────────────────────────────────────

    public String serializeCoin(byte[] txid, int index, byte[] coin) {
        long   value   = 0;
        for (int i = 0; i < 8; i++) value |= (coin[i] & 0xFFL) << (8 * i);
        int    addrVer = coin[8] & 0xFF;
        int    hashLen = coin[9] & 0xFF;
        byte[] addrHash = hashLen > 0
                ? Arrays.copyOfRange(coin, 10, 10 + hashLen) : new byte[0];

        return json(
                "version",  str(addrVer),
                "height",   "-1",
                "value",    str(value),
                "address",  q(Bech32.encode(addrVer, addrHash)),
                "coinbase", "false",
                "hash",     q(toHex(txid)),
                "index",    str(index)
        );
    }

    // ── Shared utility ────────────────────────────────────────────────────────

    /** Computes txid = Blake2b-256 of base (non-witness) tx bytes. */
    public static byte[] computeTxId(HNSBlock.Tx tx) {
        // baseSize is recorded during parsing — exact byte count before witnesses
        byte[] base = Arrays.copyOf(tx.raw, tx.baseSize);
        return HNSPeer.Blake2b.hash(base, 32);
    }
}