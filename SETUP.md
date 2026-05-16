# Setting Up the Maven Project Structure

IntelliJ IDEA uses its own project format. To publish to GitHub and build
with Maven, the source files need to be in the standard Maven directory layout.

## Directory Structure

```
easy-handshake/                          ← git repository root
├── pom.xml
├── README.md
├── .gitignore
├── deploy.sh
└── src/
    └── main/
        └── java/
            ├── handshake/               ← package handshake;
            │   ├── HNSPeerManager.java
            │   ├── HNSPeer.java
            │   ├── HNSBlock.java
            │   ├── HNSMessage.java
            │   ├── BrontideState.java
            │   ├── BlockSyncCoordinator.java
            │   ├── NodeIdentity.java
            │   ├── PeerServer.java
            │   ├── Peer.java
            │   ├── Seed.java
            │   └── crypto/              ← package handshake.crypto;
            │       ├── CryptoUtils.java
            │       ├── Secp256k1.java
            │       └── Elligator.java
            └── database/               ← package database;
                └── Database.java
```

## Steps in IntelliJ IDEA

1. **Create a new Maven project** in IntelliJ:
   - File → New → Project → Maven
   - GroupId: `is.handshake`
   - ArtifactId: `handshake-java`
   - Version: `1.0.0`

2. **Replace `pom.xml`** with the one from this repository.

3. **Move source files** into the Maven structure:
   - Copy all `handshake/*.java` files → `src/main/java/handshake/`
   - Copy `CryptoUtils.java`, `Secp256k1.java`, `Elligator.java`
     → `src/main/java/handshake/crypto/`
   - Copy `Database.java` → `src/main/java/database/`

4. **Build the fat JAR**:
   - Maven panel → Lifecycle → `package`
   - Or: `mvn clean package`
   - Output: `target/easy-handshake.jar`

## Running Locally

```bash
java -Xmx512m -jar target/easy-handshake.jar
```

## Deploying to IONOS VPS

```bash
# Make deploy script executable
chmod +x deploy.sh

# Deploy (replaces HSD)
./deploy.sh root@your-ip

# After deployment, copy your existing database
# (saves re-syncing the full 41 GB chain)
rsync -avz --progress \
    ~/.easy_handshake/chain.mv.db \
    root@your-ionos-ip:~/.easy_handshake/

rsync -avz --progress \
    ~/.easy_handshake/node.key \
    root@your-ionos-ip:~/.easy_handshake/
```

## Java Version on IONOS VPS

Check if Java 21 is installed:
```bash
java -version
```

If not installed:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-21-jdk -y

# RHEL/CentOS/Rocky
sudo dnf install java-21-openjdk -y
```

## Verifying the Node is Running

```bash
# Check service status
sudo systemctl status easy-handshake

# Watch live logs
journalctl -fu easy-handshake

# Check port is listening
ss -tlnp | grep 44806
```
