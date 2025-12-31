#!/bin/bash
# Veth pair setup script for network stack testing.
#
# Creates a virtual Ethernet pair (veth0 <-> veth1) for testing
# without physical hardware. Your stack binds to veth0, test tools
# use veth1.
#
# Usage:
#   sudo ./setup_veth.sh           # Create veth pair
#   sudo ./setup_veth.sh --teardown # Remove veth pair
#   sudo ./setup_veth.sh --namespace <name> # Place veth1 in network namespace

set -euo pipefail

VETH0="veth0"
VETH1="veth1"
MTU=9000
NAMESPACE=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --teardown           Remove the veth pair"
    echo "  --namespace <name>   Place veth1 in a network namespace"
    echo "  --mtu <size>         Set MTU (default: 9000)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0                        # Create veth0 <-> veth1"
    echo "  sudo $0 --namespace testns     # veth1 in 'testns' namespace"
    echo "  sudo $0 --teardown             # Remove veth pair"
}

teardown() {
    echo "Removing veth pair..."

    # Delete veth0 (this also removes veth1 as they are paired)
    if ip link show "$VETH0" &>/dev/null; then
        ip link delete "$VETH0"
        echo "Deleted $VETH0 (and $VETH1)"
    else
        echo "Veth pair not found, nothing to remove."
    fi

    # Remove namespace if it exists and is empty
    if [ -n "$NAMESPACE" ]; then
        if ip netns list | grep -q "^$NAMESPACE"; then
            ip netns delete "$NAMESPACE" 2>/dev/null || true
            echo "Deleted namespace $NAMESPACE"
        fi
    fi
}

create_veth() {
    # Check if already exists
    if ip link show "$VETH0" &>/dev/null; then
        echo "Error: $VETH0 already exists. Run with --teardown first."
        exit 1
    fi

    echo "Creating veth pair: $VETH0 <-> $VETH1"

    # Create veth pair
    ip link add "$VETH0" type veth peer name "$VETH1"

    # Set MTU for jumbo frame testing
    ip link set "$VETH0" mtu "$MTU"
    ip link set "$VETH1" mtu "$MTU"

    # Disable hardware offloads so stack handles everything in software
    # This ensures packets are processed exactly as sent
    ethtool -K "$VETH0" tx off rx off gso off tso off gro off 2>/dev/null || true
    ethtool -K "$VETH1" tx off rx off gso off tso off gro off 2>/dev/null || true

    # Disable IPv6 to prevent kernel interference
    sysctl -w "net.ipv6.conf.$VETH0.disable_ipv6=1" >/dev/null
    sysctl -w "net.ipv6.conf.$VETH1.disable_ipv6=1" >/dev/null

    # Move veth1 to namespace if specified
    if [ -n "$NAMESPACE" ]; then
        # Create namespace if it doesn't exist
        if ! ip netns list | grep -q "^$NAMESPACE"; then
            ip netns add "$NAMESPACE"
            echo "Created namespace: $NAMESPACE"
        fi

        ip link set "$VETH1" netns "$NAMESPACE"
        ip netns exec "$NAMESPACE" ip link set "$VETH1" up
        echo "Moved $VETH1 to namespace $NAMESPACE"
    fi

    # Bring interfaces up
    ip link set "$VETH0" up
    if [ -z "$NAMESPACE" ]; then
        ip link set "$VETH1" up
    fi

    echo ""
    echo "Veth pair created successfully!"
    echo ""
    echo "  $VETH0 <-> $VETH1"
    echo "  MTU: $MTU"
    if [ -n "$NAMESPACE" ]; then
        echo "  $VETH1 in namespace: $NAMESPACE"
    fi
    echo ""
    ip link show "$VETH0"
    if [ -z "$NAMESPACE" ]; then
        ip link show "$VETH1"
    else
        ip netns exec "$NAMESPACE" ip link show "$VETH1"
    fi
}

# Parse arguments
TEARDOWN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --teardown)
            TEARDOWN=true
            shift
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --mtu)
            MTU="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Execute
if [ "$TEARDOWN" = true ]; then
    teardown
else
    create_veth
fi
