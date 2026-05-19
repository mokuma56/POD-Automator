#!/bin/sh
# VPN entrypoint — connects OpenConnect and adds permanent static routes
# for subnets not pushed by the dCloud VPN server.

VPN_HOST="$1"
VPN_USER="$2"
VPN_PASS="$3"

echo "Connecting to $VPN_HOST as $VPN_USER..."
echo "$VPN_PASS" | openconnect --interface tun0 --user "$VPN_USER" --passwd-on-stdin "$VPN_HOST" &
VPN_PID=$!

# Wait for tun0 to come up (up to 30s)
for i in $(seq 1 30); do
    ip link show tun0 >/dev/null 2>&1 && break
    sleep 1
done

if ip link show tun0 >/dev/null 2>&1; then
    echo "tun0 is up — adding static routes..."
    # 172.16.0.0/12 covers Loopback0 ranges (172.30.255.x etc.)
    # used as ip ssh source-interface on switches — not always pushed by dCloud VPN
    ip route add 172.16.0.0/12 dev tun0 2>/dev/null && echo "  Added 172.16.0.0/12 -> tun0" || echo "  172.16.0.0/12 already present"
else
    echo "WARNING: tun0 did not come up in 30s"
fi

# Keep container alive with VPN process
wait $VPN_PID
