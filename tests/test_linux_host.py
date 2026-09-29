"""Linux Docker hosts: how containers reach the dashboard, and host memory.

The automator was written on a Mac (Docker Desktop). Two assumptions broke on
the Linux automator host (Ubuntu 24.04, native Docker):
  * containers reached the dashboard at 192.168.65.254 — Docker Desktop's host
    gateway, which does not exist on Linux, so every hostdb call from a
    container would fail;
  * the memory gate read macOS's kern.memorystatus_level, so on Linux it never
    engaged.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hostdb  # noqa: E402

# /proc/net/route from inside vpn-POD-22 on the Mac (header + default + the
# VPN's specific routes), and a Linux-host equivalent.
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
LINUX_ROUTES = ROUTE_HEADER + (
    "eth0\t00000000\t01003DAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"      # default via 172.61.0.1
    "tun0\t000012C6\t00000000\t0001\t0\t0\t0\t0000FEFF\t0\t0\t0\n"      # 198.18.0.0/15
    "tun0\t000010AC\t00000000\t0001\t0\t0\t0\t0000F0FF\t0\t0\t0\n"      # 172.16.0.0/12
    "eth0\t00003DAC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
)


def _write(tmp_path, text):
    p = tmp_path / "route"
    p.write_text(text)
    return str(p)


def test_default_gateway_is_the_eth0_default(tmp_path):
    assert hostdb._default_gateway(_write(tmp_path, LINUX_ROUTES)) == "172.61.0.1"


def test_a_tunnel_default_route_is_never_used(tmp_path):
    """If a VPN ever took the default route, the host is still behind eth0."""
    routes = ROUTE_HEADER + (
        "tun0\t00000000\t0100100A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t00000000\t01003DAC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
    assert hostdb._default_gateway(_write(tmp_path, routes)) == "172.61.0.1"


def test_no_route_file_means_unknown(tmp_path):
    assert hostdb._default_gateway(str(tmp_path / "missing")) == ""


def test_env_override_always_wins(monkeypatch):
    monkeypatch.setenv("DASHBOARD_URL", "http://10.0.0.5:5050/")
    assert hostdb.dashboard_url(_release="6.8.0-58-generic") == "http://10.0.0.5:5050"


def test_docker_desktop_keeps_its_host_gateway(monkeypatch, tmp_path):
    """Mac: the container's default gateway is inside Docker Desktop's VM, not
    the Mac — the behaviour that worked on the Mac must not change."""
    monkeypatch.delenv("DASHBOARD_URL", raising=False)
    url = hostdb.dashboard_url(_release="6.10.14-linuxkit",
                               _route_file=_write(tmp_path, LINUX_ROUTES))
    assert url == "http://192.168.65.254:5050"


def test_linux_host_uses_the_bridge_gateway(monkeypatch, tmp_path):
    monkeypatch.delenv("DASHBOARD_URL", raising=False)
    url = hostdb.dashboard_url(_release="6.8.0-58-generic",
                               _route_file=_write(tmp_path, LINUX_ROUTES))
    assert url == "http://172.61.0.1:5050"


def test_no_hardcoded_docker_desktop_address_left_in_container_code():
    for name in ("onboard_router.py", "onboard.py", "ise_integrations.py",
                 "evpn_fabric.py", "sda_fabric.py"):
        assert "192.168.65.254" not in (ROOT / name).read_text(), name


# ── host memory on Linux ──────────────────────────────────────────────────────

import dashboard as d  # noqa: E402

MEMINFO = ("MemTotal:       24000000 kB\nMemFree:         1000000 kB\n"
           "MemAvailable:    6000000 kB\nBuffers:          100000 kB\n")


def test_linux_meminfo_parses(tmp_path):
    p = tmp_path / "meminfo"
    p.write_text(MEMINFO)
    assert d._linux_meminfo(str(p)) == (24000000 // 1024, 6000000 // 1024)
    assert d._linux_meminfo(str(tmp_path / "missing")) is None


def test_free_pct_uses_linux_meminfo():
    # MemAvailable, not MemFree: page cache is reclaimable.
    assert d._host_mem_free_pct(_meminfo=(24000, 6000)) == 25
