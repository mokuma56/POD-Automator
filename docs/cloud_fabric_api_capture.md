# Cloud Fabric — Dashboard API capture (POD-17 / org 539, 2026-10-06)

Recorded from the Dashboard UI while building PseudoCo_Cloud_Fabric per the lab
guide. These endpoints are under `/api/v1/` but answer **only to a logged-in
Dashboard session** on the shard host (n219.dashboard.meraki.com) — the API key
gets 404. Write calls need the page's CSRF handling, so they are issued from
inside the logged-in page (`fetch` with same-origin cookies).

| Step | Call | Notes |
|---|---|---|
| Wizard "Save to staging" | `POST /organizations/{org}/switch/fabric` → 201 | body: `{name, bgpAsn:"65535", status:"staged", skipUnderlayGeneration:true, underlayIpPool:"", underlayLoopbackIpPool:"172.30.255.0/24", config:<base64 JSON>}`; response gives fabric `id` |
| Add subnets → "Save changes" | `PUT /organizations/{org}/switch/fabric/{id}` → 200 | same shape minus bgpAsn/status; `config` is the FULL desired state again, now with `subnets` |
| Deploy → Proceed | `POST /organizations/{org}/switch/fabric/{id}/deploy?async=true` → 200 | body `{devices:[3 serials], stacks:[]}` → `{status:"pending", id:<job>}` |
| Poll | `GET /organizations/{org}/switch/fabric/{id}` | `status:"deployed"`, `lastJob.status/result:"complete"`, `lastJob.errors:[]` (took < 1 min) |
| Rollback | `DELETE /organizations/{org}/switch/fabric/{id}` → 204 | must precede removing switches (BGP blocks removeNetworkDevices) |

Wizard edits (roles, VRFs, L3 interfaces, eBGP, subnets) are held in page memory
only — nothing is sent until "Save to staging" / "Save changes".

## Decoded `config` (final PUT), trimmed to one of each

```json
{
  "authKey": "", "version": "2",
  "devices": [{"id": "<serial>", "serial": "<serial>", "type": "switch", "mac": "...", "lanIp": "198.18.1.53",
               "model": "C9300-24U", "name": "Site_105-Border-Spine", "tags": [], "action": "create",
               "stackId": "", "esiMhPairId": "", "switchFabricRoles": ["Border", "Spine"], "members": [],
               "network": {"id": "<netId>", "name": "SITE_105"}, "online": true, "fabricId": "<fabricId>"}],
  "l3Interfaces": [{"id": "34", "serial": "<border>", "stackId": "", "esiMhPairId": "", "action": "create",
                    "mode": "vlan", "switchModule": "", "switchPort": "", "name": "Main", "vrf": "Main",
                    "mtu": 9100, "vlan": 10, "ipv4AndMask": "192.168.255.1/31", "ipv4MulticastRouting": "disabled",
                    "ipv6": "", "ipv6Eui64Enabled": false, "ipv6Prefix": ""}],
  "ebgp": [{"id": "37", "serial": "<border>", "stackId": "", "esiMhPairId": "", "action": "create", "authKey": "",
            "ip4": "192.168.255.0", "ip6": "", "remoteAs": 65534, "sourceInterface": "34", "vrf": "Main",
            "ip4NeighborAddressFamilyBindingId": "", "ip6NeighborAddressFamilyBindingId": ""}],
  "ospf": [],
  "vrfs": [{"organizationId": "<org>", "payload": {"action": "create", "autoRd": true, "name": "Main", "id": "<vrfId>"}}],
  "subnets": [{"id": "74", "correlationId": "44", "name": "Main", "vlan": 10, "vlanName": "", "vni": 10010,
               "vrf": "Main", "ipv4AndMask": "10.10.255.1/24", "dhcpRelayIps": ["198.18.5.102"], "dhcpRelayIp6s": [],
               "useGlobalVrfForDhcpRelay": true, "anycastGatewayEnabled": true, "broadcastReplicationEnabled": false,
               "ipv6": "", "ipv6Prefix": "", "ipv6Eui64Enabled": false,
               "serial": "<leaf>", "stackId": "", "esiMhPairId": "", "action": "create"}]
}
```

- `id`/`correlationId` inside config are client-side placeholders (small ints as strings);
  `ebgp[].sourceInterface` references an `l3Interfaces[].id`.
- One subnet entry **per leaf**, sharing `correlationId`; VNI = 10000 + VLAN.
- `vrfs[].payload.id` is the org-level VRF id from public `GET /organizations/{org}/routing/vrfs`.
- POST used `autoRd:false`; Dashboard flipped it to `true` once subnets were attached.
