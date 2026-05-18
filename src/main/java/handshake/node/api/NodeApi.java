package handshake.node.api;

import handshake.database.Database;

import java.time.Duration;
import java.time.Instant;

import static handshake.node.api.JsonBuilder.*;

/**
 * Node info, network, and mempool API methods.
 *
 * REST:
 *   GET /   → server info
 *
 * RPC:
 *   getinfo, getnetworkinfo, getconnectioncount,
 *   getpeerinfo, getmempoolinfo, getrawmempool,
 *   getmemoryinfo, estimatefee, stop
 */
public class NodeApi {

    private static final String USER_AGENT = "/easy-handshake:1.0.0/";
    private static final int    HNS_PORT   = 44806;

    private final Database db;
    private final String   version;
    private final Instant  startTime;

    public NodeApi(Database db, String version, Instant startTime) {
        this.db        = db;
        this.version   = version;
        this.startTime = startTime;
    }

    // ── REST ──────────────────────────────────────────────────────────────────

    @SuppressWarnings("unused") // served at GET / (planned REST route)
    public String getServerInfo() {
        int tip = db.getTipHeight();
        return json(
                "version", q(version),
                "network", q(ChainApi.NETWORK),
                "chain", raw(json(
                        "height",   str(tip),
                        "tip",      q(toHex(db.getHashAtHeight(tip))),
                        "progress", str(tip > 0 ? 1.0 : 0.0)
                )),
                "pool", raw(json(
                        "host",  q("0.0.0.0"),
                        "port",  str(HNS_PORT),
                        "agent", q(USER_AGENT)
                )),
                "mempool", raw(json(
                        "tx",   "0",
                        "size", "0"
                ))
        );
    }

    // ── RPC ───────────────────────────────────────────────────────────────────

    public String rpcGetInfo() {
        int tip = db.getTipHeight();
        return json(
                "version",         q(version),
                "protocolversion", "70015",
                "walletversion",   "0",
                "balance",         "0",
                "blocks",          str(tip),
                "timeoffset",      "0",
                "connections",     "0",
                "difficulty",      "1",
                "testnet",         "false",
                "keypoolsize",     "0",
                "paytxfee",        "0",
                "relayfee",        "0.00001",
                "errors",          q("")
        );
    }

    public String rpcGetNetworkInfo() {
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

    public String rpcGetMemoryInfo() {
        Runtime rt      = Runtime.getRuntime();
        long    usedMB  = (rt.totalMemory() - rt.freeMemory()) / 1_048_576;
        long    totalMB = rt.totalMemory() / 1_048_576;
        long    maxMB   = rt.maxMemory()   / 1_048_576;
        long    uptime  = Duration.between(startTime, Instant.now()).getSeconds();
        return json(
                "used",          str(usedMB),
                "total",         str(totalMB),
                "max",           str(maxMB),
                "free",          str(totalMB - usedMB),
                "uptimeSeconds", str(uptime)
        );
    }

    public String rpcGetMempoolInfo() {
        return json("size", "0", "bytes", "0", "usage", "0");
    }
}