# Explicit private-network planning

`p0 network-plan --snapshot /private/network-inventory.json --network identity
--interface p0v2edge0` is a **pure planning** command. It never executes an IP,
Podman, firewall, service, mount or other Host operation.

The closed input is:

```json
{
  "schemaVersion": 1,
  "interfaces": [{"name": "lo", "prefixes": ["127.0.0.1/8"]}],
  "routes": ["0.0.0.0/0"],
  "reservedPrefixes": []
}
```

This minimal example is synthetic, **not an adequate real Host inventory**.
Supply all Host interfaces/address prefixes and all relevant IPv4 routing tables,
plus explicit known inactive and private-namespace network allocations. The
`snapshot_from_ip_json` library adapter normalizes explicitly supplied `ip -j
address` and `ip -j -4 route show table all` metadata. It does not gather it or
claim Host routes enumerate every engine's persistent/private networks.
Malformed/missing route destinations refuse rather than silently asserting an
empty inventory. Site snapshots and their concrete addresses remain private;
do not publish them in the release repository.

The allocator finds an aligned, entirely nonoverlapping /24 in RFC1918 pools.
Overlapping exclusions collapse to sorted intervals, so a large allocated range
is skipped in one step rather than scanning millions of addresses. Default
**routes** do not allocate the whole address space; an explicit /0 exclusion or
interface address does. Existing requested interface names always refuse: this
new-network planner never infers ownership or adopts a foreign bridge.

Output binds both exact normalized inventory and desired network configuration,
including gateway and proposed ingress address. It declares
`nativeRecheckRequired=true` and `installationCertified=false`. It does not
choose routing/egress/firewall policy or assert that the proposed address is
already assigned/reachable. A later independently reviewed Root applier must
recheck current authoritative inventory, custody/reserves and exact network
ownership, create/verify its own bridge, and qualify actual private
Rootful-to-rootless/return routing before any app depends on it. A stale or
incomplete snapshot is **not** permission to guess a subnet or bypass an overlap.
Idempotent use of an existing managed network requires exact previously recorded
native ownership/configuration, not rerunning this new-network selector.
