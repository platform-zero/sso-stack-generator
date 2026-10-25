# Published, never-selected native preparation

The existing journal command `install-journal.py --root <state-root>
--retire-unselected <exact-original-intent-sha256> --reviewed-data-state` owns
terminal disposition. It is an internal serialized lifecycle command, not an
installer alternative. Run only from reviewed, hash-verified Root-private ops
staging on an executable filesystem. Do not execute mutable checkout code as
Root or stage executable code on noexec `/run`.

`native-unselected-disposition.py` handles the narrowly defined case in which a
synthetic preparation published selected unit files and persistent derived Root
environment files but never published runtime adjuncts or selected applications.
It has no CLI and is not a general reset/recovery backend. Only the fixed seven
lab actors, `/var/lib/stack-host-delivery`, and `/mnt/stack/host-stack-lab` are
supported. There is no caller-selected path, account adoption or permission
repair mode. Existing preparation and running verification do **not** admit
failed receipts; the additional failed snapshot mode is read-only source custody
for this exact never-selected synthetic state.

Before the first removal, and repeatedly during disposition, the owner checks:

- Exact original failed dual-record bytes/hash, held record FDs, full immutable
  input pins and the original scope marker.
- Source-derived candidate/previous inventory, all seven actor/subordinate
  identities and original installed parent inode/mount/ACL records.
- Original completed file custody. Every candidate file must be newly published;
  adopted, overwritten, unchanged and previous-only removals are refused.
- Original complete all-domain projection/environment source custody and fresh
  rederivation of persistent Root payloads. Host Root interprets operations data;
  it does not import service Python.
- Original current pointer held by FD, clean-retired predecessor source only,
  absent actor/previous selections, offline actor managers/process identities,
  disabled boot/API triggers, no selected jobs and no published runtime/updater
  triggers. No observer starts an actor manager.
- Exact held/named published file identity, hash, owner, mode, ACL and mount;
  complete Root-store namespace; memory and physical filesystem reserves.

The owner retains `never-selected-original-failure.json` byte-for-byte. It writes
`native-unselected-disposition.json` as a Root-private durable cursor bound to the
original failed intent and the exact source-derived plan. These are evidence,
not permits and not build inputs. A pending cursor entry precedes an atomic
no-replace displacement into a deterministic same-directory inert name. The
original inode/hash is checked again before unlink. A changed displaced inode is
not deleted. Interrupted displacement/unlink resumes only the exact recorded
next path; unrecorded absence, reappearance, foreign store leaves and cursor drift
refuse. There is no automatic predecessor restart, global prune, graph or volume
deletion, or application-data reset.

After all owned publication files are absent, the journal repeats canonical
unselected/offline/configuration checks. Only then does it publish its terminal
`retired-failed` receipt and clear the allocator lease or restore the exact bytes
of an already clean-retired current receipt. The current symlink is not rewritten.
An interrupted terminal-leaf write uses the completed read-only cursor check,
not another deletion authority. Original sources, projections and failed controls
remain available; actual data reset remains the separate owning lifecycle.

Regression entrypoints:

- `python3 -B scripts/test-native-unselected-disposition.py` — real temporary
  FDs/renames/cursors and modeled NSS/UID/mount/offline transport facts; no host
  activation or installed proof.
- `python3 -B scripts/test-install-journal.py` — genuinely Root-required isolated
  permission/journal fixtures. Stage the ops closure and test hash-verified under
  Root-private executable `/var/lib`, use a private fixture TMPDIR, and never
  change original checkout permissions to make tests pass.

Neither regression, disposition, generation nor native preflight is application
acceptance. Installed workflows and complete repeated clean runs remain required.
