# Standalone host deployment contract

A site manifest may explicitly select `"deploymentMode": "standalone"` for the
ordinary native Podman/systemd application stack. This is not an activation skip
flag. The mode is part of the hashed site manifest and generated bundle metadata.
Omitting the field preserves the existing managed-site contract, including its
Latium agent-VM validation and control-checkout requirement. Unknown modes fail.

Standalone manifests also declare, for example:

```json
"storageScope": {"root": "/mnt/stack/example-stack", "dataClass": "production"}
```

Use `synthetic` only for deliberately disposable fixture data. All private domain
state/image/volume roots and named application data stay inside this canonical
scope. The installer claims only an empty directory tree, never nonempty unclaimed
data or retained service accounts. A root-owned, atomically published ownership
marker binds the site, identities and private roots for subsequent operations.
Existing marker identity/path drift is refused; there is no broad adoption flag.

Execute-only per-domain ACLs cover selected state, graph and volume ancestry,
never an operator's private home or another parent above the scope. Authored ACLs
and their masks are preserved rather than unmasked by `setfacl`. Private leaves
remain mode 0700. Standalone preparation does not chmod/re-own the legacy shared
Podman cache parent. CI SSH setup uses its actual IR domain and can claim only a
new/empty fixture directory, not foreign existing keys or a linked path.
Standalone private volumes are initialized through no-follow directory FDs; there
is no legacy-store copy or recursive ownership migration on repeated installs.
Actual allocated subordinate-ID ranges populate the subsequent runtime table,
including when the site lets the installer select an unused range.

Preparation errors/signals are journalled before account/volume/unit work, not
only after unit selection. A copied immutable stage is immediately root-sealed
and standalone stages remain root-private. New receipts also bind encrypted
settings and base-image pin bytes; historical receipt pin sets remain readable.

For an explicitly synthetic, **never-selected initial** preparation only, the
journal supports exact-CAS `--seal-unselected SHA --reviewed-data-state` repair of
the old archive-copy ownership reset, then native
`--retire-unselected-intent SHA --reviewed-data-state`. Seal checks the entire
new derived tree for foreign owners, links and special files before changing any
owner. Retirement requires bound storage, no current/previous pointer, no installed
stack configuration, inactive selected units, absent/disabled boot triggers and
no stack jobs. This does not stop/restart services, erase data or authorize a
production upgrade. Ordinary selected-failure quarantine remains separate.

The storage marker is not a backup, a production-data recovery approval or an
application/recovery acceptance result. Those lifecycle gates remain separate.

A standalone site:

- uses the ordinary `webservices` unit namespace, not the isolated venue profile;
- does not declare an `agentVmSpec` or manage a control checkout;
- does not emit maintenance/software lane-workspace metadata;
- omits the Caddy managed-control socket bind and the explicitly marked Caddy
  control/agent-API route block (ordinary application routes remain selected);
- does not classify controller/VM proof as part of application delivery or defer
  selected notebook/runner workflows merely because of the historical controller;
- bounds generated build services to 30 minutes, two CPUs, 8 GiB and 512 tasks,
  using selected private build scratch rather than unrestricted host `/var/tmp`;
- binds collector journal ingestion to its fixed domain UIDs plus root, requires
  current collector scope hooks, and derives the unit-namespace filter from site
  policy. Existing finance/private-database exclusions still apply;
- allocates ingress/security log storage under the declared volume root and
  refuses retained host log mounts; requires access and error URI-redaction hooks
  rather than letting callback/query credentials enter logs;
- remains subject to the existing source, image, domain, resource and native
  installer safety checks. It is not permission to operate unrelated accounts,
  storage, services or sockets.

The native role verifier requires agreement among the manifest, bundle and domain
metadata, their core provenance/hash bindings, absence of managed-role artifacts,
and absence of the managed control socket in the IR mounts. A venue cannot simply
be relabelled standalone. Passing this structural contract is not application,
shared-login, persistence or recovery acceptance.

The generator refuses an unrecognized control-mount shape or ambiguous Caddy
source block rather than guessing how to strip it. Input materialization changes
happen in the newly generated artifact from owning source; do not patch installed
Caddy output manually.
