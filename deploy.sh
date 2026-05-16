#!/bin/bash
# deploy.sh — builds and deploys easy-handshake
#
# Usage:
#   ./deploy.sh user@your-ip
#
# Prerequisites:
#   - Maven installed locally
#   - SSH key configured for the VPS
#   - Java 21 installed on the VPS

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 user@host"
    exit 1
fi

REMOTE="$1"
JAR="target/easy-handshake.jar"
REMOTE_DIR="/opt/easy-handshake"
SERVICE_NAME="easy-handshake"

echo "=== Building fat JAR ==="
mvn clean package -q
echo "Built: $JAR ($(du -h $JAR | cut -f1))"

echo ""
echo "=== Stopping HSD on remote (if running) ==="
ssh "$REMOTE" "sudo systemctl stop hsd 2>/dev/null || true"
ssh "$REMOTE" "sudo systemctl disable hsd 2>/dev/null || true"
echo "HSD stopped and disabled."

echo ""
echo "=== Verifying ports are free ==="
ssh "$REMOTE" "ss -tlnp | grep -E '44806|12038' || echo 'Ports are free.'"

echo ""
echo "=== Copying JAR to VPS ==="
ssh "$REMOTE" "sudo mkdir -p $REMOTE_DIR && sudo chown \$USER $REMOTE_DIR"
scp "$JAR" "$REMOTE:$REMOTE_DIR/easy-handshake.jar"
echo "Copied to $REMOTE:$REMOTE_DIR/easy-handshake.jar"

echo ""
echo "=== Installing systemd service ==="
ssh "$REMOTE" "cat > /tmp/easy-handshake.service" << EOF
[Unit]
Description=Handshake Java Node
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$REMOTE_DIR
ExecStart=/usr/bin/java -Xmx512m -jar $REMOTE_DIR/easy-handshake.jar
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

ssh "$REMOTE" "sudo mv /tmp/easy-handshake.service /etc/systemd/system/$SERVICE_NAME.service"
ssh "$REMOTE" "sudo systemctl daemon-reload"
ssh "$REMOTE" "sudo systemctl enable $SERVICE_NAME"

echo ""
echo "=== Opening firewall port 44806 ==="
ssh "$REMOTE" "sudo ufw allow 44806/tcp 2>/dev/null || sudo firewall-cmd --permanent --add-port=44806/tcp 2>/dev/null || echo 'Configure firewall manually'"

echo ""
echo "=== Starting Handshake Java Node ==="
ssh "$REMOTE" "sudo systemctl start $SERVICE_NAME"
sleep 2
ssh "$REMOTE" "sudo systemctl status $SERVICE_NAME --no-pager"

echo ""
echo "=== Deployment complete! ==="
echo "Monitor with: ssh $REMOTE journalctl -fu $SERVICE_NAME"
echo ""
echo "NOTE: Copy your existing database to avoid re-syncing:"
echo "  rsync -avz --progress chain.mv.db $REMOTE:$REMOTE_DIR/"
echo "  rsync -avz --progress node.key    $REMOTE:$REMOTE_DIR/"
