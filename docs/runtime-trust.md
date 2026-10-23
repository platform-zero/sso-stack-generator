# Runtime public trust and mail leaf delegation

Standalone installation keeps the Caddy signing store root-private. Applications
receive only the root-owned `caddy_ca` public certificate bundle; the declared
`rootlessAccess: read-only` shared-volume policy gives no host-actor write/default
write permission. Installation validates certificate-only contents, revokes old
writable actor ACLs on this derived public artifact, and seals the private store
without changing its key bytes. Exact execute-only ACLs cover the shared public
volume's own ancestry inside the claimed scope (not merely private domain roots),
preserving authored masks and every ancestor above the scope. No system-wide
trust or original cache is changed.

Mail is an explicit, narrower credential delegation, not a CA-store consumer.
`ops/runtime-trust.py --bundle /absolute/installed/release --publish-mail` selects
only the exact mail hostname under the known ACME/local provider paths. It checks
SAN, expiry, non-CA basic constraints and public-key equality, and refuses links,
foreign ownership, multiple/private PEMs in certificate material and unknown
artifacts. A root-owned atomic generation publishes just that leaf certificate
and key to `mail_tls/current`; the mail actor can read but not write them. Obsolete
derived generations are removed, not retained as experimental backups. The CA key
and unrelated server keys are never copied or mounted there.

The native installer prepares permissions before Caddy starts and publishes the
mail leaf before application startup. The same publisher is the rotation entry
point. Automatic refresh/reload integration and installed rotation/recovery tests
remain lifecycle work; seven isolated-root fixtures are not deployed security,
mail workflow, interruption or application/recovery acceptance.

JupyterHub and its spawned notebooks mount only the public bundle at `/ca`, with
normal Python/Requests/Curl TLS verification directed to the combined system and
site certificate bundle. Images remain site-independent. The host path is a
runtime input, not a baked certificate or TLS-verification bypass.
