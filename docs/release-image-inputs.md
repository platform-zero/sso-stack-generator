# Immutable release image inputs

The native installer deliberately refuses a selected bare `sha256:…` image without
explicit root-owned, hash-bound image inputs. Do not bypass this admission check.
Application data, container writable layers and whole image stores are not release
inputs and must not be archived to preserve disposable experiments.

## Rebind store labels when changing site account policy

Registry and build-base pins include a Linux authority label as well as the image
reference/configuration ID. A different domain-account policy must not keep the
old labels. Convert using explicit old/new policies, review the new file, and
commit it as site source:

```sh
python3 scripts/rebind-image-authorities.py \
  --from-policy old-stack.config.yaml --to-policy new-stack.config.yaml \
  --pins registry-image-ids.json --output registry-image-ids.new.json
```

The same command supports build-base pin objects. It requires identical logical
domain membership, refuses unknown/colliding accounts, changes only authority
labels, preserves immutable identities/registry references, and never overwrites
an existing output or invokes a container runtime. It is not image availability
or installed proof.

## Package selected images from an explicit build cache

`runtime-generator/podman-ops/package-release-images.py` packages **only** the
immutable IDs selected by a hash-bound generated IR. It is a root operator tool
for an explicit root-private Buildah cache, never a default/lane store. The output
parent and the separately provided runtime directory must already be root-private,
plain directories. Choose a fresh output child:

```sh
sudo python3 runtime-generator/podman-ops/package-release-images.py \
  --bundle /path/to/generated-bundle --source-store /private/build-cache \
  --run-root /run/release-package --output /var/lib/release-inputs/new-release
```

Requires Buildah, ordinary core utilities and the documented memory/storage
reserves. No build or application container is started. Push destinations are
local OCI archives only; operator credentials, remote authorities and registry
logins are not inherited. Exports have a 10-minute per-image default and a one-hour
overall deadline. Reserve/deadline/interruption failure cancels only the owned
export process group and retains an explicitly pending output; never auto-replay
it or treat it as a complete input set.

Before publishing the manifest the tool verifies the selected configuration ID,
Linux/amd64 platform and every referenced OCI blob digest/size without filesystem
extraction; linked, duplicate, escaping and unselected regular members are refused.
It fsyncs the archives and publishes a hash-bound input manifest only after the
whole selection succeeds. This establishes artifact integrity, **not** source
rebuild equivalence, application, SSO, data backup/restore or installation acceptance.

During engineering, unfrozen local builds are discovery. Freeze reviewed outputs
and their owning source/dependency inputs before counting either clean install.
A changed image, module or source pin resets the accepted run count.
