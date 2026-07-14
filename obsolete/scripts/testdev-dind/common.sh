#!/usr/bin/env bash
set -euo pipefail

testdev_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P
}

testdev_deploy_root() {
  cd "$(dirname "$(testdev_root)")" && pwd -P
}

testdev_project_name() {
  local deploy_root name_hash
  deploy_root="$(testdev_deploy_root)"
  name_hash="$(printf '%s' "$deploy_root" | sha256sum | awk '{print substr($1,1,10)}')"
  printf '%s\n' "${TESTDEV_PROJECT_NAME:-webservices_testdev_${name_hash}}"
}

testdev_dind_name() {
  printf '%s-dind\n' "$(testdev_project_name)"
}

testdev_network_name() {
  printf '%s-net\n' "$(testdev_project_name)"
}

testdev_volume_name() {
  printf '%s-home\n' "$(testdev_project_name)"
}

testdev_bundle_path() {
  printf '/workspace-home/deploy/bundle\n'
}

testdev_require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker CLI is required for testdev" >&2
    exit 1
  }
}

testdev_unsafe_override_enabled() {
  [ "${TESTDEV_UNSAFE_ALLOW_NON_LABWARE_HOST:-}" = "I_UNDERSTAND_THIS_TOUCHES_LOCAL_DOCKER" ]
}

testdev_require_local_docker_context() {
  if [ -n "${DOCKER_HOST:-}" ] && ! testdev_unsafe_override_enabled; then
    cat >&2 <<EOF
testdev outer orchestration must use the Docker daemon on the disposable VM host.

Refusing because DOCKER_HOST is set:
  DOCKER_HOST=$DOCKER_HOST

Run testdev through labware, or clear DOCKER_HOST before running these scripts.
Set TESTDEV_UNSAFE_ALLOW_NON_LABWARE_HOST=I_UNDERSTAND_THIS_TOUCHES_LOCAL_DOCKER
only for deliberate local debugging.
EOF
    exit 1
  fi
}

testdev_hostname_allowed() {
  local current expected
  current="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  for expected in ${TESTDEV_ALLOWED_HOSTS:-labware}; do
    if [ "$current" = "$expected" ]; then
      return 0
    fi
  done
  return 1
}

testdev_require_virtualized_host() {
  if testdev_unsafe_override_enabled; then
    return 0
  fi

  local virt
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  if [ -n "$virt" ] && [ "$virt" != "none" ] && testdev_hostname_allowed; then
    return 0
  fi

  cat >&2 <<'EOF'
testdev must run on the disposable labware VM, not on the workstation or production host.

Expected flow:
  1. Copy the testdev bundle into labware.
  2. Run ./testdev-up.sh and ./testdev-verify.sh from inside labware.
  3. Let testdev create its own nested Docker-in-Docker daemon there.

Default allowed host:
  labware

For a different disposable VM, set TESTDEV_ALLOWED_HOSTS to its short hostname.
Set TESTDEV_UNSAFE_ALLOW_NON_LABWARE_HOST=I_UNDERSTAND_THIS_TOUCHES_LOCAL_DOCKER
only for deliberate local debugging.
EOF
  exit 1
}

testdev_ensure_dind() {
  local dind_name network_name volume_name
  dind_name="$(testdev_dind_name)"
  network_name="$(testdev_network_name)"
  volume_name="$(testdev_volume_name)"

  docker network inspect "$network_name" >/dev/null 2>&1 || docker network create "$network_name" >/dev/null
  docker volume inspect "$volume_name" >/dev/null 2>&1 || docker volume create "$volume_name" >/dev/null

  if ! docker inspect "$dind_name" >/dev/null 2>&1; then
    docker run -d \
      --privileged \
      --name "$dind_name" \
      --network "$network_name" \
      -e DOCKER_TLS_CERTDIR= \
      -v "$volume_name:/workspace-home" \
      docker:29-dind \
      --host=tcp://0.0.0.0:2375 \
      --host=unix:///var/run/docker.sock >/dev/null
  elif [ "$(docker inspect "$dind_name" --format '{{.State.Running}}')" != "true" ]; then
    docker start "$dind_name" >/dev/null
  fi

  docker run --rm --network "$network_name" -e "DOCKER_HOST=tcp://$dind_name:2375" docker:29-cli sh -lc '
    i=0
    while [ "$i" -lt 90 ]; do
      docker info >/dev/null 2>&1 && exit 0
      i=$((i + 1))
      sleep 1
    done
    docker info
  '

  docker exec "$dind_name" sh -lc '
    sysctl -w fs.inotify.max_user_instances="${TESTDEV_INOTIFY_MAX_USER_INSTANCES:-1024}" >/dev/null 2>&1 || true
    sysctl -w fs.inotify.max_user_watches="${TESTDEV_INOTIFY_MAX_USER_WATCHES:-524288}" >/dev/null 2>&1 || true
  '
}

testdev_copy_bundle_to_volume() {
  local deploy_root volume_name
  deploy_root="$(testdev_deploy_root)"
  volume_name="$(testdev_volume_name)"

  docker run --rm \
    -v "$volume_name:/workspace-home" \
    -v "$deploy_root:/source:ro" \
    alpine:3.21 \
    sh -lc '
      rm -rf /workspace-home/deploy/bundle
      mkdir -p /workspace-home/deploy/bundle
      cp -a /source/. /workspace-home/deploy/bundle
      cd /workspace-home/deploy/bundle
      ln -sfn ../runtime build/runtime
      if [ -f runtime/stack.env ]; then
        if grep -q "^WORKSPACE_RUNTIME_PUBLIC_ADDRESS=" runtime/stack.env; then
          sed -i "s/^WORKSPACE_RUNTIME_PUBLIC_ADDRESS=.*/WORKSPACE_RUNTIME_PUBLIC_ADDRESS=host-gateway/" runtime/stack.env
        else
          printf "%s\n" "WORKSPACE_RUNTIME_PUBLIC_ADDRESS=host-gateway" >> runtime/stack.env
        fi
        if grep -q "^WORKSPACE_RUNTIME_HTTP_BIND_ADDRESS=" runtime/stack.env; then
          sed -i "s/^WORKSPACE_RUNTIME_HTTP_BIND_ADDRESS=.*/WORKSPACE_RUNTIME_HTTP_BIND_ADDRESS=0.0.0.0/" runtime/stack.env
        else
          printf "%s\n" "WORKSPACE_RUNTIME_HTTP_BIND_ADDRESS=0.0.0.0" >> runtime/stack.env
        fi
      fi
    '
}

testdev_seed_host_images() {
  [ "${TESTDEV_SEED_HOST_IMAGES:-1}" = "1" ] || return 0

  local compose_file dind_name tmp_images seeded
  compose_file="$(testdev_deploy_root)/build/runtime-contract.yml"
  dind_name="$(testdev_dind_name)"
  tmp_images="$(mktemp)"
  seeded=0

  python3 - "$compose_file" >"$tmp_images" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    compose = json.load(handle)

images = {
    service.get("image")
    for service in compose.get("services", {}).values()
    if service.get("image")
}

for image in sorted(images):
    if "$" in image:
        continue
    has_namespace = "/" in image
    first = image.split("/", 1)[0]
    is_registry_ref = has_namespace and ("." in first or ":" in first or first == "localhost")
    if not is_registry_ref or image.startswith("webservices/") or image.startswith("webservices-"):
        print(image)
PY

  while IFS= read -r image_ref; do
    [ -n "$image_ref" ] || continue
    docker image inspect "$image_ref" >/dev/null 2>&1 || continue
    if docker exec "$dind_name" docker image inspect "$image_ref" >/dev/null 2>&1; then
      continue
    fi
    echo "[testdev] seeding host image cache: $image_ref"
    docker save "$image_ref" | docker exec -i "$dind_name" docker load >/dev/null
    seeded=$((seeded + 1))
  done <"$tmp_images"

  rm -f "$tmp_images"
  echo "[testdev] seeded $seeded host image(s) into $dind_name"
}

testdev_pull_workspace_base_images() {
  [ "${TESTDEV_PULL_WORKSPACE_BASE_IMAGES:-1}" = "1" ] || return 0

  testdev_run_cli sh -lc '
    set -eu
    cd /workspace-home/deploy/bundle
    sed -n "s/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1/p" \
      build/stack.containers/agent-workspace/Dockerfile \
      build/stack.containers/agent-workspace-notebook/Dockerfile 2>/dev/null |
      sort -u |
      while IFS= read -r image_ref; do
        [ -n "$image_ref" ] || continue
        case "$image_ref" in
          scratch|*\$*) continue ;;
        esac
        echo "[testdev] pre-pulling workspace base image: $image_ref"
        docker pull "$image_ref" >/dev/null
      done
  '
}

testdev_run_cli() {
  local network_name volume_name dind_name docker_config_dir
  local -a command_args docker_config_args
  network_name="$(testdev_network_name)"
  volume_name="$(testdev_volume_name)"
  dind_name="$(testdev_dind_name)"
  docker_config_dir="${TESTDEV_DOCKER_CONFIG:-${DOCKER_CONFIG:-}}"
  command_args=("$@")

  if [ -z "$docker_config_dir" ] && [ -f "${HOME:-}/.docker/config.json" ]; then
    docker_config_dir="${HOME}/.docker"
  fi

  if [ -n "$docker_config_dir" ] && [ -f "$docker_config_dir/config.json" ]; then
    docker_config_args=(
      -e DOCKER_CONFIG=/testdev-docker-config
      -v "$docker_config_dir:/testdev-docker-config-source:ro"
    )
    command_args=(
      sh
      -lc
      'mkdir -p "$DOCKER_CONFIG"; cp -a /testdev-docker-config-source/. "$DOCKER_CONFIG"/; exec "$@"'
      testdev-cli
      "$@"
    )
  fi

  docker run --rm \
    --network "$network_name" \
    -e "DOCKER_HOST=tcp://$dind_name:2375" \
    -e "COMPOSE_PROJECT_NAME=$(testdev_project_name)" \
    -e "COMPOSE_PARALLEL_LIMIT=${COMPOSE_PARALLEL_LIMIT:-1}" \
    "${docker_config_args[@]}" \
    -v "$volume_name:/workspace-home" \
    docker:29-cli "${command_args[@]}"
}
