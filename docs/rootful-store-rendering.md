# Dedicated rootful store rendering

Rootful container, network and volume Quadlets carry the same implementation-owned
`GlobalArgs` before **every** native command:

- `--root=/mnt/stack/p0-v2/rootful/engine`
- `--runroot=/run/p0-v2-rootful/engine`
- `--storage-driver=overlay`
- `--network-config-dir=/var/lib/p0-v2-rootful/networks`

The graph cannot override these with arbitrary Podman arguments. Rootless and
on-demand test resources do not inherit these flags. Network and volume objects
remain scoped to the runtime class even when logical resource identifiers match.
This prevents the rendered edge from using the existing Host Root default store.

`tests_v2/test_rootful_render.py` checks all three resource types and runs the
installed Quadlet generator in **nonexecuting dry-run mode** against a private
synthetic fixture. Every generated native Exec directive, including cleanup,
must retain all dedicated-store flags. No image, service or native store is
created or accessed by this generator test. Missing generator is an explicit
source-test skip, not installed proof.

## Not activation authority

Rendering is not safe Root installation/activation. Rootful selection is still
refused by the rootless lifecycle. Root-owned independently reviewed byte
supply, directory/mount custody, exact image promotion, stopped/trigger gates,
private IPAM and cross-runtime routing, native data/ownership checks and explicit
Root lifecycle authority remain separate prerequisites. Do not use rendered
units directly as a substitute for them. In particular, a mutable ancestor must
not be accepted merely because these flags name a dedicated store. Inherited
`/proc/self/fd` graphroot aliases are not a portable native Podman API, and must
not replace the canonical fixed store identity.
