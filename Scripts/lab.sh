#!/bin/sh
# Pastoral lab: creates a two-container test network to validate ARP spoofing.
# Uses Docker to create two Alpine containers on the same network:
#   - "victim" — the target host
#   - "gateway" — the gateway/router
# Then runs a spoofing test against the victim.
#
# Requirements: Docker installed and running.

set -e

NETWORK_NAME="pastoral-lab"
VICTIM_NAME="pastoral-victim"
GATEWAY_NAME="pastoral-gateway"

echo "Pastoral lab — ARP spoofing validation"
echo "======================================="

# Check Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is not installed."
    echo "Install from https://docker.com"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running."
    exit 1
fi

# Cleanup any previous lab
echo "Cleaning up previous lab..."
docker rm -f $VICTIM_NAME $GATEWAY_NAME 2>/dev/null || true
docker network rm $NETWORK_NAME 2>/dev/null || true

# Create the lab network
echo "Creating lab network..."
docker network create --driver bridge $NETWORK_NAME

# Start the gateway container (acts as router)
echo "Starting gateway container..."
docker run -d --name $GATEWAY_NAME --network $NETWORK_NAME \
    --cap-add NET_ADMIN \
    alpine:latest \
    sh -c "apk add --no-cache iproute2 arping && \
           ip addr add 10.0.0.1/24 dev eth0 && \
           sleep 3600"

# Start the victim container
echo "Starting victim container..."
docker run -d --name $VICTIM_NAME --network $NETWORK_NAME \
    --cap-add NET_ADMIN \
    alpine:latest \
    sh -c "apk add --no-cache iproute2 curl && \
           ip addr add 10.0.0.5/24 dev eth0 && \
           ip route add default via 10.0.0.1 && \
           sleep 3600"

# Wait for containers to be ready
sleep 3

# Show the network state
echo ""
echo "=== Network state ==="
echo "Gateway IP:"
docker exec $GATEWAY_NAME ip addr show eth0 | grep "inet "
echo "Victim IP:"
docker exec $VICTIM_NAME ip addr show eth0 | grep "inet "
echo "Victim ARP table (before):"
docker exec $VICTIM_NAME ip neigh show

echo ""
echo "=== Test: victim can reach gateway ==="
docker exec $VICTIM_NAME ping -c 1 10.0.0.1 && echo "PASS: victim can reach gateway" || echo "FAIL: victim cannot reach gateway"

echo ""
echo "=== Test: ARP table populated ==="
docker exec $VICTIM_NAME ip neigh show 10.0.0.1 | grep -q "lladdr" && echo "PASS: gateway MAC in ARP table" || echo "FAIL: gateway MAC not in ARP table"

echo ""
echo "Lab is running. Containers:"
echo "  Gateway: $GATEWAY_NAME (10.0.0.1)"
echo "  Victim:  $VICTIM_NAME (10.0.0.5)"
echo ""
echo "To run a spoofing test from the host:"
echo "  1. Start the Pastoral helper: sudo .build/debug/pastoral-helper"
echo "  2. Run the app and target 10.0.0.5 with gateway 10.0.0.1"
echo ""
echo "To clean up:"
echo "  docker rm -f $VICTIM_NAME $GATEWAY_NAME && docker network rm $NETWORK_NAME"
