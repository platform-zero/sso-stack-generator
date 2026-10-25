# Native Root engine context ownership

The optional standalone `podman.rootful_graph_root` and
`podman.rootful_run_root` settings declare a **different, source-owned engine
context**, not permission to redirect the legacy or venue store. Both settings
must be supplied together:

```yaml
podman:
  rootful_state_root: /var/lib/stack-example
  rootful_graph_root: /var/lib/stack-example/rootful-store/graph
  rootful_run_root: /run/stack-example-podman
```

The graph is deliberately under protected `/var/lib` ancestry. An
operator-writable storage-scope parent is not Root engine/control authority,
even when a descendant itself is Root-owned. Ordinary symlinks, an archive,
an existing cache, or a historical receipt cannot establish that authority.
No mounts, namespace changes, confinement changes, capabilities or shared
configuration edits are part of context creation.

## Source and creation

The generator emits a closed `rootfulStore` definition in
`podman-domains.json`. It binds the private metadata/graph/run/network roots
and the existing installation-scope marker hash. Rootless actor roots must
remain disjoint. The actor marker is eligibility/provenance, not a stopped
lease, inventory or permission to erase data.

The existing storage owner's `--prepare-scope` operation initializes the
context, under the canonical inherited FD9 lock. It requires absent new roots
and creates only new exclusive private inodes. It never repairs ownership or
modes on an existing directory, adopts an interrupted initialization, or
substitutes the default store. Interrupted creation evidence remains private
and must receive an owning reviewed disposition.

Private controls include fixed storage/network configuration, empty registry
authentication, creation custody, and image-source records. Record source intent
before loading an image so interruption does not turn it into an unexplained
cache. These records are not permits. Destructive operations still require
fresh scope, offline/trigger/job, namespace, mount, held-FD, hash/CAS and
process-local stopped-lease gates.

## Consumers and startup

Image helpers use explicit graph, run and network roots and a clean environment.
They do not inherit ambient storage/connection overrides or shared Root HOME
credentials. Native preparation, readiness, maintenance and recovery consumers
must use the same owning command context; no default-store fallback is allowed
for a declared but invalid or unavailable context.

Generated Root container/build/network services select the private configuration
and include the existing image helper's bounded read-only
`--validate-rootful-store --require-runtime` startup guard. Runtime entry records
must bind the actual canonical preparing dual records and immutable metadata.
Startup additionally checks live selected dual records; historical creation or
runtime custody alone cannot authorize a start. The sole recognized `current`
link is the private canonical selector, with its exact release target and held
link CAS. Generic links remain refused.

## Capacity and proof boundaries

Keep at least 16 GiB available RAM, 50 GiB on root, 100 GiB on the declared stack
filesystem, and 50 GiB on the **actual graph allocation filesystem**. A private
path is not evidence that its filesystem can hold a proposed import. Account
for layer expansion and temporary/mapped copies before allocating. Stop the
affected unsafe allocation, not independent read-only custody, clean-stop or
safe cleanup work.

Creation, configuration checks, image availability and source/model tests are
not installed application acceptance or cold-reset proof. The owning clean
lifecycle must explicitly inventory and dispose this context's graph/run data,
while preserving private controls, failed evidence and the shared default store.
Until that lifecycle qualifies the context, do not count it as a complete clean
installation or bypass the legacy non-cold default-store refusal.
