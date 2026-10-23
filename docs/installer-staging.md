# Bundle staging safety

`scripts/install-bundle.sh` stages the legacy `dist/build` layout; it does not
implement native Podman activation or establish installed application acceptance.
Native Podman bundles use `ops/install-podman-bundle.sh` as described in
[podman-transition.md](podman-transition.md).

A staging destination must be empty or bear the exact
`.webservices-bundle-root` version-1 marker from an earlier successful stage.
Unknown destination contents, linked targets/payloads, non-regular wrappers,
overlapping source/target trees and unsafe locks refuse before selection changes.
Unmarked legacy installations require explicit operator review, not silent adoption.

Staging holds an exclusive per-root lock, prepares the entire replacement before
selection, keeps `build.previous`, and preserves `runtime` and `quarantine`.
Tested build/wrapper move failures restore the old selected build and wrappers.
The prior-prior build is discarded only after successful staging. This is artifact
retention, not data-aware failed-upgrade rollback.

An abrupt interruption may retain `.webservices-install-pending` and the private
`.install.next.*` directory containing rollback inputs. A subsequent invocation
refuses replay; inspect exact ownership and selected/previous artifacts before
recovery. Do not remove the pending record to force a retry or treat this legacy
stager as the completed native installation/recovery interface.

Run the source-only regression entry point:

```sh
bash scripts/test-install-bundle.sh
```

All test mutations are confined to private temporary directories. Passing these
regressions does not prove a host installation, real SSO, backup/restore or upgrade
rollback.
