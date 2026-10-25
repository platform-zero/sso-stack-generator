# Engineering-only owned synthetic data reset

This is a deliberately narrower operation than the
[complete host clean reset](standalone-host.md). It is not a cold-store proof,
installation acceptance, recovery test, or a counted clean-host run.

A failed, never-selected preparation must first be disposed through the
[unselected-intent lifecycle](native-unselected-disposition.md). The reset then
requires authenticated retained `retired-clean` authority and authentic prior
complete-reset history. History establishes eligibility only: it never replays
old targets, inventory, deletion plans, custody, or stopped leases.

Use the existing journal owner from protected, hash-verified executable source,
with the canonical inherited FD9 lock, exact current intent SHA, and the usual
private environment:

```sh
python3 -B /protected/ops/install-journal.py \
  --root /var/lib/stack-host-delivery \
  --reset-owned-synthetic-data --expected EXACT_CURRENT_INTENT_SHA256
```

The command performs the same fresh complete scope/custody review, source,
account/subordinate-ID, namespace/mount, ACL/ownership, held-FD, stopped-trigger,
whole-inventory and per-removal CAS checks as the owning reset backend. A new
process-local stopped lease binds the exact data-only plan. A data-only lease
cannot authorize a complete-clean plan or vice versa.

Only the source-declared synthetic actor scope and recognized scoped external
runtime/install material are removal authority. This includes actor-owned image
stores within that declared synthetic scope, not unrelated/shared caches.
The default Root store, its images/layers/cache, and its network/kernel state
are read-only observations. They are never passed to the cleanup dispatcher;
initial and final inventories must agree. Unknown ownership, live consumers,
changed custody, nonempty own cgroups, foreign data, or inventory drift refuse.
No global process fallback, forced removal, permission repair, cache adoption,
or predecessor restart is introduced.

The durable result says `completeCleanReset=false`,
`rootfulStoreColdAcceptance=false`, `defaultStorePreserved=true`, and
`phase=complete-owned-synthetic-data-only`. Only after durable evidence and exact
Root-record CAS does the journal append `syntheticDataOnlyReset`. It preserves
the original `completeCleanReset` history unchanged; that history is not a claim
that the current default store is cold. Application acceptance remains false.

This mode cannot resolve a complete-clean requirement blocked by non-cold shared
Root images and grants no deletion authority over those images. Do not count it
as the reset between the two required complete identical-input acceptance runs.
