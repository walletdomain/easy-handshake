package handshake.node;

import java.util.List;

public record Seed(String key, String ipAddress, int port) {
    public static final List<Seed> SEEDS_BRONTIDE = List.of(
            new Seed("aksygghkgmciomeldjf5sc6rs2sgn2m34zfdz4xr7z5vguqvjis4e", "129.153.177.220", 44806),
            new Seed("apt4rf2dfyelbivg63u47wykvdjtsl4kxzfdylkaae5s5ydldlnwu", "159.69.46.23", 44806),
            new Seed("aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54", "172.104.214.189", 44806),
            new Seed("aiwykdz37okry3pb2lzdsgbxeg72uky2zckxmiapzstpqqmb2hnge", "35.154.209.88", 44806),
            new Seed("ai7dgiwueiiwber6uhoeqfjdujxph6ueqpnaml36sicakngmnm3am", "194.50.5.26", 44806),
            new Seed("aokj73pefmtrc7ikoxqiz4nrhgrxeqnnjpv4wxekteup33duneih2", "194.50.5.27", 44806),
            new Seed("ajd6wzdp34c32rymlljybvbosnx75aty4rwmtpkxshvfrqufq6vuk", "194.50.5.28", 44806)
    );
}
