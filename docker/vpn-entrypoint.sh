#!/bin/sh
# VPN entrypoint — connects OpenConnect and adds permanent static routes
# for subnets not pushed by the dCloud VPN server.

VPN_HOST="$1"
VPN_USER="$2"
VPN_PASS="$3"

# Ensure DNS works before openconnect tries to resolve the VPN host.
# Cisco internal DNS first (works on corporate network + via dCloud VPN tunnel),
# public DNS as fallback for home/hotel networks where corporate DNS is unreachable.
printf 'nameserver 64.102.6.247\nnameserver 173.37.137.85\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf

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

    # After VPN tunnel is up, switch back to Cisco DNS — public DNS (1.1.1.1)
    # is blocked inside the dCloud VPN tunnel, but Cisco DNS is reachable via it.
    echo "  Restoring DNS (Cisco internal — reachable via VPN tunnel)..."
    printf 'nameserver 64.102.6.247\nnameserver 173.37.137.85\n' > /etc/resolv.conf
else
    echo "WARNING: tun0 did not come up in 30s"
fi

# Keep container alive with VPN process
wait $VPN_PID
