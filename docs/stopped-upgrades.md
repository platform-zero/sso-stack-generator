# Stopped rootless selection upgrades

`p0 upgrade` is an explicit, initially conservative extension/publication path,
not an image/schema migration or an accepted full-stack upgrade product.

```text
p0 upgrade --state-dir <owned-state> --quadlet-dir <owned-quadlet> \
  --bundle <immutable-bundle> --expected-sha256 <reviewed-release-lock-sha256> \
  --expected-current-sha256 <reviewed-installed-release-lock-sha256>
```

Run through the dedicated rootless runtime identity. Before publication, every
existing owned service **and network/volume resource unit** must be stopped with
no PID, job or populated exact cgroup. Use the explicit complete resource-stop
operation; status never stops anything. The predecessor release and all owned
unit bytes/custody must match. Rootful/test units are refused by this path.

Existing images, executable/environment authority, network bindings, persistent
volume and credential references cannot change. Removal and migration are
refused. Existing secret mounts may explicitly tighten their implicit namespace
UID0/default mode to UID0/mode0400; new hash-bound noncredential configuration and
readiness observations can be admitted. New services can be added. This does not
supply a general image/schema compatibility, rollback or data migration protocol.

The operation checks storage identity/reserves, verified configurations and
actual image availability. It never starts anything or deletes application data.
Generated desired files are prepared in a new private operation directory on the
same filesystem; their exact device/inode/checksum and predecessor identities
are durably claimed before publication. New destinations use exclusive linking,
never replacement of an unowned same-name file, even with matching contents.
Existing owned generated files are replaced only against the recorded identity.
Only exact operation-owned staging links are removed. Final generated files are
single-link, private and owned; directories and records are fsynced.

After an interruption, preserve the evidence and inspect the affected operation.
Roll-forward requires the **same** candidate and predecessor plus `--resume`.
Only recorded old/new inodes and bytes are accepted; foreign edits, symlinks,
changed names, unknown resources or changed input refuse without adoption. A
resume may finish metadata/reload reconciliation even if the final registry was
already published. It still requires the current owned selection stopped and
never repeats a provisioning job. The original indeterminate journal entry is
retained; a later successful exact upgrade supplies explicit reconciliation.
An unfinished intent cannot be overwritten by a fresh upgrade. Completed intent
histories remain in their operation directories as control-journal evidence,
not runtime-data backups. A failed preparation before intent publication is
retained and does not authorize adoption of arbitrary files.

Completion reports `upgraded-not-started`, `requiresExplicitStart: true`,
`dataDeleted: false`, and `installationCertified: false`. Perform the next
explicit start and real component/workflow/persistence qualification. Source
fake-runner interruption tests do not certify native installation or upgrades.
