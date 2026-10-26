# Closed Host HTTP upstream relay

A rootful ingress container's `127.0.0.1` is **not** the Host loopback. The
`http-socket-relay` builtin describes a bounded alternative in the same graph:

```json
{
  "id": "app-upstream",
  "kind": "http-socket-relay",
  "runtime": "rootful",
  "requires": [{"service": "app", "kind": "ready"}],
  "relay": {"service": "app", "port": 8080}
}
```

The upstream must be a declared rootless service with exactly one corresponding
nonpublic TCP endpoint bound to a literal loopback address. The relay's fixed
native executor forwards to that declared **Host** port; no arbitrary command,
URL, Host path, environment, capabilities or image is admitted. Its name must fit
the native Unix socket path bound. Upstream readiness is a real graph edge, not
fabricated cross-manager `After=` ordering.

Rendering emits ordinary `.socket` and `.service` files under
`systemd/rootful/p0-v2-<id>.socket` and `.service`, not Quadlets.
Reserved `p0-v2-*` system-manager names separate this new application scope from
protected existing Host `p0-*` services. Rootless units in the dedicated runtime
user manager retain their installed `p0-*` names. They are Root-managed but the trusted OS
`systemd-socket-proxyd` process runs as the existing `p0-runtime` account, with no
new Host service user. They have no boot enablement merely from rendering.

An explicitly dependent rootful container can mount only this named resource:

```json
{
  "kind": "upstream",
  "source": "app-upstream",
  "target": "/run/p0/upstreams/app-upstream",
  "readOnly": true
}
```

The source is exactly `/run/p0-v2-upstreams/app-upstream`, never a caller path or
container administrator/PTY socket. Native `--mount` fails if this directory is
absent; `-v` automatic Host-directory creation is deliberately not used. Mounting
the directory rather than the individual socket preserves reconnect semantics
when an explicitly restarted listener replaces `http.sock`. A compatible ingress
profile must explicitly use its private Unix transport; this does not magically
convert existing host:port application configuration.

## Required Root lifecycle (not yet provided by rendering)

Before activation, an independently reviewed Root authority must:

- Validate immutable graph/unit supply and current private namespace/data custody.
- Verify the exact native upstream container/port ownership and real readiness.
- Create **only fresh** approved socket directories, Root-owned with GID of
  `p0-runtime` and mode0710, so that account can traverse known names but model
  tools running mapped UID1000 cannot. Never repair a foreign/existing directory.
- Validate native binary/platform compatibility, then install the exact ordinary
  Root units through its direct-systemd path, not the Quadlet user installer.
- Explicitly start the listener socket, validate ownership/mode0600 and native
  endpoint identity, and qualify actual container-to-socket HTTP forwarding.
- Close the listener **and** its activated service before stopped maintenance;
  service inactivity alone leaves an activation trigger. Retain failed outcomes.

The rootless lifecycle still rejects a selection containing this rootful builtin.
Source tests include an actual local unprivileged native socket-proxy process,
synthetic HTTP backend and genuine socket-activation FD. That proves basic Unix
forwarding only, **not** installed systemd, mapped UID/cgroup isolation, container
bind custody, ingress compatibility, complete routing or SSO/revocation.
Private bridge/IPAM/TLS and any needed return route remain separate explicit
engineering work. No container Host networking or administrative socket is used.
