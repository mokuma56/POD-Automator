"""cloud_fabric.py pure helpers.

The `show meraki connect` sample follows the documented section layout
(Meraki Tunnel Config / Meraki Tunnel State / Device Registration). Replace it
with a real capture from a Site_105 switch once one is logged.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cloud_fabric as cf  # noqa: E402

REGISTERED = """
Service meraki connect: enable

Meraki Tunnel Config
  Fetch State:          Config fetch succeeded
  Fetch Fail:           no failure
  Last Fetch(UTC):      2026/10/05 21:02:11
  Primary:              usw.nt.meraki.com
  Secondary:            use.nt.meraki.com

Meraki Tunnel State
  Primary:              Up
  Secondary:            Up
  Primary Last Change(UTC):   2026/10/05 21:02:20

Meraki Device Registration
  Url:                  https://catalyst.meraki.com/nodes/register

  Device Number:        1
    PID:                C9300-24U
    Serial Number:      FOC2345X0AB
    Cloud ID:           Q2AB-CDEF-GH12
    Status:             Registered
"""


def test_registered_switch_yields_cloud_id():
    st = cf.parse_meraki_connect(REGISTERED)
    assert st == {"cloud_id": "Q2AB-CDEF-GH12", "fetch_ok": True,
                  "tunnel_up": True, "registered": True}


def test_tunnel_server_names_are_not_read_as_tunnel_state():
    """The Config section's Primary:/Secondary: are hostnames, not Up/Down."""
    down = REGISTERED.replace("  Primary:              Up", "  Primary:              Down")
    st = cf.parse_meraki_connect(down)
    assert st["fetch_ok"] and not st["tunnel_up"] and not st["registered"]


def test_not_yet_fetched_is_not_registered():
    early = REGISTERED.replace("Config fetch succeeded", "Config fetch in progress")
    assert not cf.parse_meraki_connect(early)["registered"]


def test_no_cloud_id_yet():
    st = cf.parse_meraki_connect(REGISTERED.replace("Cloud ID:           Q2AB-CDEF-GH12", ""))
    assert st["cloud_id"] == "" and not st["registered"]


def test_step_lists_have_unique_names_matching_the_card():
    names = [n for n, _ in cf.DEPLOY_STEPS]
    assert len(names) == len(set(names))
    src = open(os.path.join(os.path.dirname(cf.__file__), "dashboard.py")).read()
    for n in names + [n for n, _ in cf.ROLLBACK_STEPS]:
        assert f'["{n}",' in src, f"{n} missing from CF_*_STEPS in DASHBOARD_HTML"


def test_online_is_not_converted():
    """Seen on POD-17: status online, but still mid-conversion."""
    assert not cf.switch_converted({"firmware": "Not running configured version", "lanIp": None})
    assert not cf.switch_converted({"firmware": "cs-iosxe-26-1-2", "lanIp": None})
    assert cf.switch_converted({"firmware": "cs-iosxe-26-1-2", "lanIp": "198.18.1.123"})


def _devices():
    mk = lambda s, n, m: {"serial": s, "mac": "aa:bb", "lanIp": "198.18.1.5x", "model": m,
                          "name": n, "networkId": "L_1", "tags": []}
    return {"border_spine": mk("Q-B", "Site_105-Border-Spine", "C9300-24U"),
            "leaf1": mk("Q-L1", "Site_105-Leaf1", "C9300-48UB"),
            "leaf2": mk("Q-L2", "Site_105-Leaf2", "C9300-48UB")}


VRF_IDS = {"Main": "v-main", "PROD": "v-prod", "IOT": "v-iot"}


def test_staged_config_matches_the_wizard_capture():
    """Shape recorded from Dashboard's own 'Save to staging' (docs/cloud_fabric_api_capture.md)."""
    cfg = cf.build_fabric_config("539", _devices(), VRF_IDS, with_subnets=False)
    assert set(cfg) == {"version", "devices", "ebgp", "l3Interfaces", "ospf", "subnets", "vrfs"}
    assert cfg["subnets"] == [] and cfg["ospf"] == []
    roles = {d["name"]: d["switchFabricRoles"] for d in cfg["devices"]}
    assert roles == {"Site_105-Border-Spine": ["Border", "Spine"],
                     "Site_105-Leaf1": ["Leaf"], "Site_105-Leaf2": ["Leaf"]}
    l3 = {i["id"]: (i["vrf"], i["vlan"], i["ipv4AndMask"], i["mtu"]) for i in cfg["l3Interfaces"]}
    assert sorted(l3.values()) == [("IOT", 102, "192.168.255.5/31", 9100),
                                   ("Main", 10, "192.168.255.1/31", 9100),
                                   ("PROD", 101, "192.168.255.3/31", 9100)]
    for e in cfg["ebgp"]:   # each peer sources from the L3 interface in its own VRF
        assert l3[e["sourceInterface"]][0] == e["vrf"] and e["remoteAs"] == 65534
    assert [v["payload"]["autoRd"] for v in cfg["vrfs"]] == [False] * 3


def test_subnet_config_puts_each_subnet_on_both_leaves():
    cfg = cf.build_fabric_config("539", _devices(), VRF_IDS, with_subnets=True, fabric_id="F1")
    assert cfg["authKey"] == "" and all(d["fabricId"] == "F1" for d in cfg["devices"])
    by_name = {}
    for s in cfg["subnets"]:
        by_name.setdefault(s["name"], []).append(s)
    assert {n: sorted(x["serial"] for x in v) for n, v in by_name.items()} == {
        "Main": ["Q-L1", "Q-L2"], "PROD": ["Q-L1", "Q-L2"], "IOT": ["Q-L1", "Q-L2"]}
    for v in by_name.values():                 # one correlationId per subnet pair
        assert len({x["correlationId"] for x in v}) == 1
        assert all(x["vni"] == 10000 + x["vlan"] and x["useGlobalVrfForDhcpRelay"]
                   and x["anycastGatewayEnabled"] and not x["broadcastReplicationEnabled"]
                   for x in v)
    assert len({s["id"] for s in cfg["subnets"]}) == 6
    assert [v["payload"]["autoRd"] for v in cfg["vrfs"]] == [True] * 3


def test_ise_summary_matches_the_wizard_contract():
    """Shape from ISE 3.5's own main.js (workFlowPageReducer → POST /summary)."""
    body = cf.build_ise_meraki_summary("KEY", {"id": "539", "name": "PseudoCo-539"},
                                       ["s1", "s2", "s3"], [])
    assert set(body) == {"dashboardConnections", "egressPolicyIds", "sgaclIds", "sgtIds", "settings"}
    conn = body["dashboardConnections"]["connections"][0]
    assert conn == {"name": "PseudoCo_Cloud_Networking", "url": "api.meraki.com", "apiKey": "KEY",
                    "organizations": [{"id": "539", "name": "PseudoCo-539"}]}
    assert body["sgtIds"] == {"selectedIds": ["s1", "s2", "s3"]}
    assert body["sgaclIds"] == {"selectedIds": []} and body["egressPolicyIds"] == {"selectedIds": []}
    assert body["settings"] == {"syncInterval": 12}


def test_cleanup_only_picks_the_lab_switches():
    devs = [{"serial": "S1", "model": "C9300-24U", "name": "Site_105-Border-Spine"},
            {"serial": "S2", "model": "C9300-48UB", "name": "Site_105-Leaf1"},
            {"serial": "S3", "model": "MX68", "name": "Site_105-Leaf2"},       # wrong model
            {"serial": "S4", "model": "C9300-48UB", "name": "Lobby-Switch"},   # not the lab's
            {"serial": "S5", "model": "C9300-48UB", "name": ""}]               # recorded only
    picked = {d["serial"] for d in cf.lab_switches(devs, recorded={"S5"})}
    assert picked == {"S1", "S2", "S5"}


def test_cleanup_keeps_non_lab_named_vlans():
    names = [{"name": "default", "vlanId": "1"}, {"name": "Main", "vlanId": "10"},
             {"name": "PROD", "vlanId": "101"}, {"name": "IOT", "vlanId": "102"},
             {"name": "Voice", "vlanId": "200"}]
    assert cf.lab_vlan_names(names) == [{"name": "default", "vlanId": "1"},
                                        {"name": "Voice", "vlanId": "200"}]


def test_cleanup_order_frees_dependencies_first():
    order = [n for n, _ in cf.CLEANUP_PARTS]
    assert order.index("fabric") < order.index("switches")          # BGP blocks removal
    assert order.index("ISE integration") < order.index("adaptive policy")   # else ISE re-syncs
    assert order.index("switching config") < order.index("adaptive policy")  # VLAN profile refs groups
    assert order.index("VRFs") > order.index("switches") > order.index("fabric")  # VRFs in use until then


def test_vrfs_are_created_before_the_fabric_and_deleted_last():
    deploy = [n for n, _ in cf.DEPLOY_STEPS]
    assert deploy.index("fabric_vrfs") == deploy.index("fabric_create") - 1
    assert [n for n, _ in cf.ROLLBACK_STEPS][-1] == "delete_vrfs"


def test_cloud_mgmt_output_is_parsed_like_the_meraki_form():
    """IOS XE renamed `show meraki connect` → `show cloud-mgmt connect` (POD-18)."""
    renamed = REGISTERED.replace("Meraki Tunnel", "Cloud-mgmt Tunnel").replace(
        "Meraki Device Registration", "Cloud-mgmt Device Registration")
    assert cf.parse_meraki_connect(renamed)["registered"]
    down = renamed.replace("  Primary:              Up", "  Primary:              Down")
    assert not cf.parse_meraki_connect(down)["tunnel_up"]


def test_new_command_is_tried_first():
    assert cf.CONNECT_CMDS[0] == "service cloud-mgmt connect"
    assert cf.SHOW_CMDS[0] == "show cloud-mgmt connect"


def _lldp(ports):  # {port: (remote systemName, remote port)}
    return {"ports": {p: {"lldp": {"systemName": n, "portId": rp}} for p, (n, rp) in ports.items()}}


# POD-18, 2026-10-08: three C9350-24U, still default hostnames (Switch-<mac>).
C9350 = {
    "B": ("94466700b261", ""), "L1": ("e4135c833200", ""), "L2": ("84dd84cff700", "")}
C9350_LLDP = {
    "B":  _lldp({"1": ("Switch-e4135c833200.corp", "Gi1/0/23"), "2": ("Switch-84dd84cff700.corp", "Gi1/0/24"),
                 "24": ("BRANCH-SEC-RTR", "Tw0/0/4")}),
    "L1": _lldp({"10": ("Switch-84dd84cff700.corp", "Gi1/0/10"), "11": ("Switch-84dd84cff700.corp", "Gi1/0/11"),
                 "23": ("Switch-94466700b261.corp", "Gi1/0/1"), "24": ("BRANCH-SEC-RTR", "Tw0/0/5")}),
    "L2": _lldp({"10": ("Switch-e4135c833200.corp", "Gi1/0/10"), "11": ("Switch-e4135c833200.corp", "Gi1/0/11"),
                 "24": ("Switch-94466700b261.corp", "Gi1/0/2")}),
}
# POD-17-like C9300-48, already named in Dashboard (LLDP shows the names).
C9300 = {"B": ("aaaa00000001", "Site_105-Border-Spine"), "L1": ("aaaa00000002", "Site_105-Leaf1"),
         "L2": ("aaaa00000003", "Site_105-Leaf2")}
C9300_LLDP = {
    "B":  _lldp({"1": ("Site_105-Leaf1", "Gi1/0/47"), "2": ("Site_105-Leaf2", "Gi1/0/48")}),
    "L1": _lldp({"10": ("Site_105-Leaf2", "Gi1/0/10"), "11": ("Site_105-Leaf2", "Gi1/0/11"),
                 "47": ("Site_105-Border-Spine", "Gi1/0/1")}),
    "L2": _lldp({"10": ("Site_105-Leaf1", "Gi1/0/10"), "11": ("Site_105-Leaf1", "Gi1/0/11"),
                 "48": ("Site_105-Border-Spine", "Gi1/0/2")}),
}


def test_roles_and_ports_on_c9350_24():
    roles = cf.infer_roles(C9350_LLDP, C9350)
    assert roles == {"border_spine": "B", "leaf1": "L1", "leaf2": "L2"}
    assert cf.underlay_ports(C9350_LLDP, C9350, roles) == {
        ("border_spine", "leaf1"): "1", ("leaf1", "border_spine"): "23",
        ("border_spine", "leaf2"): "2", ("leaf2", "border_spine"): "24"}


def test_roles_and_ports_on_c9300_48():
    roles = cf.infer_roles(C9300_LLDP, C9300)
    assert roles == {"border_spine": "B", "leaf1": "L1", "leaf2": "L2"}
    assert cf.underlay_ports(C9300_LLDP, C9300, roles)[("leaf2", "border_spine")] == "48"


def test_roles_do_not_depend_on_serial_order():
    shuffled = {k: C9350[k] for k in ("L2", "B", "L1")}
    assert cf.infer_roles(C9350_LLDP, shuffled)["border_spine"] == "B"


def test_unreadable_cabling_raises_instead_of_guessing():
    import pytest
    flat = {k: _lldp({}) for k in C9350}
    with pytest.raises(RuntimeError):
        cf.infer_roles(flat, C9350)


def test_stale_idac_card_is_recognised():
    """POD-18's stored iDAC URL (older session) rendered the tile like this."""
    stale = "Cisco Duo\nEmail Found error\nMeraki\nMeraki Org ID Found error\nAPI Key Found error"
    live = "Cisco Duo\nActivate Account\nMeraki Dashboard\nMeraki Org ID 1734868\nView"
    assert cf.idac_card_is_stale(stale) and not cf.idac_card_is_stale(live)


def test_live_idac_url_is_tried_before_the_stored_one():
    assert cf.idac_url_candidates("https://idac/live", "https://idac/old") == ["https://idac/live", "https://idac/old"]
    assert cf.idac_url_candidates("", "https://idac/old") == ["https://idac/old"]
    assert cf.idac_url_candidates("https://idac/x", "https://idac/x") == ["https://idac/x"]


def test_meraki_tile_candidates_never_take_another_tiles_button():
    openers = r"^(log ?in|view|open|go|launch)$"
    btns = [{"i": 4, "label": "Login", "section": "Cisco Duo"},
            {"i": 5, "label": "View", "section": ""},                 # POD-18: Meraki, unattributed
            {"i": 6, "label": "Login", "section": "Cisco Security Cloud Control"},
            {"i": 9, "label": "View", "section": "Meraki Dashboard"}]
    assert [b["i"] for b in cf.meraki_tile_candidates(btns, openers)] == [9, 5]
