# Host operator inspection

The existing `stackctl` front door supports read-only prerequisite and resource
inspection in addition to its existing `users` commands:

```sh
./scripts/stackctl.sh doctor --json
./scripts/stackctl.sh plan --bundle /path/to/generated-podman-bundle --json
```

`doctor` checks tool availability and available memory/storage against explicit
reserves (16 GiB available RAM, 50 GiB root storage, 100 GiB stack storage). It does
not install dependencies or certify versions, network readiness or applications.
Run it in the same operator environment that will perform the intended operation;
root and non-root PATHs may differ.

`plan` verifies the core bundle/IR/provenance/manifest hash bindings and reports the
proposed services and domain identities/storage paths. It rejects duplicate domain
identities and linked or invalid input files. It never reads the secret store,
launches a renderer/test runner, invokes Podman, initializes a graph or modifies
systemd. It warns when inputs still select an isolated experimental venue or a
managed agent-VM contract. The output is not activation authority and is not a
complete verification of all artifact bytes or current live host conflicts.

The version-1 JSON report includes its evidence scope and `mutationsPerformed`.
Never interpret prerequisite success or a resource plan as installed application,
SSO, persistence or recovery acceptance.

Regression source: `scripts/test-stackctl-inspection.py`. Lifecycle mutation remains
owned by the native installer; additional lifecycle commands must not bypass its
provenance, data or authorization gates.
