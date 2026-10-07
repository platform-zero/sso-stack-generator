#!/usr/bin/env bash
# Builds a gated TWO-service fixture for disposable VM activation tests only.
# It contains no production data, SOPS material, or Worklane images.
set -Eeuo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if ! { [ "$#" -eq 2 ] && [ "$1" = --output-root ]; }; then
  echo "usage: $0 --output-root NEW_NVME_DIR" >&2; exit 2
fi
output="$2"
parent="$(realpath -e "$(dirname "$output")")"
[ ! -e "$output" ] || { echo 'output must be new' >&2; exit 2; }
[[ "$(df -P "$parent" | awk 'END {print $1}')" == /dev/nvme* ]] || { echo 'fixture must live on local NVMe' >&2; exit 2; }
[ -z "$(git -C "$root" status --porcelain --untracked-files=all)" ] || { echo 'generator is dirty' >&2; exit 2; }
mkdir -m 700 "$output"
output="$(realpath -e "$output")"
mkdir -p "$output/site" "$output/modules/example/stack.config/example" "$output/env"
printf 'fixture\n' > "$output/modules/example/stack.config/example/value.txt"
cat > "$output/modules/example/stack.module.json" <<'EOF'
{"schemaVersion":1,"id":"example","dependencies":[],"overlays":["stack.config/example","stack.runtime.yaml"]}
EOF
cat > "$output/modules/example/stack.runtime.yaml" <<'EOF'
schemaVersion: 1
module: example
target: core
services:
  caddy:
    image: docker.io/library/caddy:2.11.3
    lifecycle: daemon
    networks:
      caddy: {}
  worker:
    image: docker.io/library/alpine:3.22
    command: ["sleep", "infinity"]
    lifecycle: daemon
    networks:
      caddy: {}
networks:
  caddy:
    driver: bridge
EOF
cat > "$output/site/manifest.json" <<'EOF'
{"schemaVersion":2,"site":"synthetic","stackConfig":"stack.config.yaml","secretStore":"secrets.json","modules":["example"]}
EOF
cat > "$output/site/stack.config.yaml" <<'EOF'
storage:
  volume_root: /mnt/stack/volumes
podman:
  rootful_modules: []
  rootful_services: [caddy]
  domains:
    test:
      user: webservices-test
      uid: 1890
      subuid_start: 3145728
      modules: [example]
EOF
printf '{}\n' > "$output/site/secrets.json"
git -C "$output/modules/example" init -q -b main
git -C "$output/modules/example" remote add origin https://example.invalid/synthetic-example.git
git -C "$output/modules/example" add .
git -C "$output/modules/example" -c user.name=SyntheticTest -c user.email=test@example.invalid commit -qm source
module_commit="$(git -C "$output/modules/example" rev-parse HEAD)"
generator_commit="$(git -C "$root" rev-parse HEAD)"
python3 - "$output/site" "$module_commit" "$generator_commit" <<'PY'
from pathlib import Path
import json,sys
site=Path(sys.argv[1]);module=sys.argv[2];generator=sys.argv[3]
remote='https://example.invalid/synthetic-example.git'
(site/'modules.json').write_text(json.dumps({'schemaVersion':1,'modules':[{'name':'example','git':remote,'ref':'main','commit':module,'overrides':['stack.config/example','stack.runtime.yaml']}]})+'\n')
(site/'module-lock.v2.json').write_text(json.dumps({'schemaVersion':2,'roots':['example'],'modules':[{'id':'example','repo':'synthetic-example','git':remote,'ref':'main','commit':module,'dependencies':[],'overrides':['stack.config/example','stack.runtime.yaml']}]})+'\n')
(site/'.webservices-generator.json').write_text(json.dumps({'generatorRemote':'https://github.com/platform-zero/sso-stack-generator.git','generatorCommit':generator,'moduleManifestCommit':'0'*40})+'\n')
PY
git -C "$output/site" init -q -b main
git -C "$output/site" remote add origin https://example.invalid/synthetic-site.git
git -C "$output/site" add .
git -C "$output/site" -c user.name=SyntheticTest -c user.email=test@example.invalid commit -qm 'immutable synthetic module lock'
lock_commit="$(git -C "$output/site" rev-parse HEAD)"
python3 - "$output/site/.webservices-generator.json" "$lock_commit" <<'PY'
import json,sys
p=sys.argv[1];doc=json.load(open(p));doc['moduleManifestCommit']=sys.argv[2];open(p,'w').write(json.dumps(doc)+'\n')
PY
git -C "$output/site" add .webservices-generator.json
git -C "$output/site" -c user.name=SyntheticTest -c user.email=test@example.invalid commit -qm 'pin immutable lock'
# The installer requires a rendered per-service env file; neither fixture
# service uses secrets. Empty files are intentional and must stay synthetic.
: > "$output/env/caddy.env"
: > "$output/env/worker.env"
STACK_GENERATOR_BUILD_LOCAL_ARTIFACTS=0 "$root/generate.sh" --site "$output/site/manifest.json" \
  --modules-dir "$output/modules" --backend podman --output "$output/bundle" >"$output/generate.log"
python3 "$root/scripts/verify-podman-source.py" --bundle "$output/bundle" \
  --site "$output/site" >"$output/source-gate.log"
"$root/runtime-generator/podman-ops/install-podman-bundle.sh" --bundle "$output/bundle" \
  --env-dir "$output/env" >"$output/preflight.log"
jq -e '(.services | keys | sort) == ["caddy", "worker"]' "$output/bundle/stack.ir.json" >/dev/null
printf '[synthetic-bundle] 2-service source gate and installer preflight accepted; no activation: %s\n' "$output"
