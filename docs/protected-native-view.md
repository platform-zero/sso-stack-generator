# Protected native parent view — cross-namespace correction

**Source integration and empty-kernel-fixture evidence only. Not installed.**

A self/private bind at `/mnt/stack/p0-v2` does not protect its pathname when
`/mnt/stack` is owned/writable by another Host actor. Actual empty fixture10
shows UID1000 in an older private mount namespace renaming the Root-owned bind
source directory: the Host mount target follows the renamed dentry with the
same mount ID. Successful initial APPLY/CHECK/private-FD ABI checks remain
scoped evidence, not adversarial canonical-store custody. Do not resume native
provisioning using that assumption or change shared-parent permissions.

Actual empty fixture11 proves a narrower replacement primitive: an independent
Root-owned bind target under a protected Root-owned parent, recursively projected
over an empty fake native parent, keeps the **same canonical native path and data
inode** stable despite successful old-namespace source rename. The protected
target rename is denied. Both exact fixtures were removed; actual namespace,
PostgreSQL, stores, original services and credentials were not touched.

## Fixed source contract

A separately reviewed standalone Root authority must own
`/var/lib/p0-v2-view/stack`, Root0:G0 mode0711 and protected ancestors, with an
independent child `p0-v2` bound to the exact previously owned data directory.
The data stays on StackFS. It must create/verify a Root-private native mount
namespace handle and recursively project that view over `/mnt/stack` **inside
native execution namespaces**, not over the Host shared parent globally.

Rootful container, network **and volume** Quadlet sources carry:

```ini
[Service]
PrivateMounts=true
BindPaths=/var/lib/p0-v2-view/stack:/mnt/stack
```

Native absolute graphroot/staticDir/volume path strings remain unchanged; no
libpod metadata rewrite/project migration is implied. Root helpers must run
fixed native commands in the verified private view, never fall back to Host
pathnames. Source class/config/engine options remain closed.

The dedicated new UID1004 `user@1004.service` manager also needs the exact
Root-managed view, with stopped/source/private-claim/unknown-drop-in gates and
no automatic restart. Rootless control commands must run as a transient **user
service** inheriting that manager's view, not a `--scope` in the caller's old
namespace. Existing other Host users/managers/services are untouched.

A cached old Podman pause process can defeat a corrected caller view. Exact
owned stopped-container/PID-file/executable/UID/namespace/cgroup/pidfd release
and explicit continuation require separate qualification. No broad signal,
prune, `system migrate` or generic cache deletion is authorized by this design.

The unprivileged volume context now refuses a mutable parent before ANY native
callback, then verifies the **actual `podman unshare` view** before native info:
fixed bounded stdlib code compares Root-witnessed parent and data namespace
inodes, not merely UID values translated to overflow IDs in a user namespace.
The held-inode chmod/chown program separately checks that same parent identity
before and after effects. Missing/stale pause view denies; there is no fallback.
Physical 100GiB StackFS reserve uses `/mnt/stack/p0-v2`, not the view parent,
which may reside on RootFS. The 50GiB RootFS/16GiB RAM reserves remain.

## Unqualified delivery work

Root-private v3 authority/explicit complete-v2 transition, modern held-FD
claim/attach/private/boot recovery, private namespace handle, dedicated manager
publication/transition, old pause release and per-command helper prefixes are
engineering dependencies. Existing actual v2 artifacts remain unchanged and
cannot authorize affected provisioning. Native current-core volume-context07
passed its earlier same-namespace contract, not this corrected security gate.
Installed ordinary units, Rootful image promotion, native container forwarding,
fresh-volume preparation/first-use and full identity installation remain
unpassed. Empty fixture11 and nonexecuting Quadlet translation do not certify
those cells.
