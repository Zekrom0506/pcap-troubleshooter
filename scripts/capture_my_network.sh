#!/usr/bin/env bash
# Captures traffic on this computer's network for a few minutes and saves it
# into captures/my_network/, then runs the troubleshooter on it.
#
# Usage:  ./scripts/capture_my_network.sh [seconds] [interface]
#   seconds    how long to capture (default 120)
#   interface  network interface (default: en0 on macOS, the default route's interface on Linux)
#
# tcpdump needs administrator rights, so you will be asked for your password.

set -e

SECONDS_TO_CAPTURE="${1:-120}"
INTERFACE="$2"

if [ -z "$INTERFACE" ]; then
    if [ "$(uname)" = "Darwin" ]; then
        INTERFACE="$(route get default 2>/dev/null | awk '/interface:/ {print $2}')"
        INTERFACE="${INTERFACE:-en0}"
    else
        INTERFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    fi
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/captures/my_network"
OUTPUT_FILE="$OUTPUT_DIR/my_network_$(date +%Y%m%d_%H%M%S).pcap"
mkdir -p "$OUTPUT_DIR"

echo "Capturing on $INTERFACE for $SECONDS_TO_CAPTURE seconds -> $OUTPUT_FILE"
echo "Tip: browse a few sites, and turn Wi-Fi off/on once to capture DHCP."

sudo tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE" &
TCPDUMP_PID=$!
sleep "$SECONDS_TO_CAPTURE"
sudo kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "$OUTPUT_FILE"

echo ""
echo "Running the troubleshooter..."
cd "$PROJECT_DIR"
python3 troubleshoot.py "$OUTPUT_FILE" -f html -o "${OUTPUT_FILE%.pcap}_report.html" || true
python3 troubleshoot.py "$OUTPUT_FILE" || true
