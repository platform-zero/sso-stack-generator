#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/bin" "$WORK_DIR/root/alpha/.worklane"
cat >"$WORK_DIR/manifest.json" <<EOF
{"schemaVersion":1,"owner":"test","root":"$WORK_DIR/root","workspaces":[{"name":"alpha","role":"software","startAtBoot":true}]}
EOF
cat >"$WORK_DIR/root/alpha/.worklane/lane.toml" <<'EOF'
schema_version = 5
id = "lane-id"
name = "alpha"
session_name = "alpha"
container_name = "worklane-alpha-lane-id"
EOF
cat >"$WORK_DIR/bin/podman" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$P0_TEST_LOG"
case "$*" in
  'inspect --format {{json .Config.Labels}} worklane-alpha-lane-id')
    printf '%s\n' '{"io.worklane.id":"lane-id","io.worklane.name":"alpha"}' ;;
  'inspect --format {{.State.Status}} worklane-alpha-lane-id') printf '%s\n' exited ;;
  'start worklane-alpha-lane-id') printf '%s\n' worklane-alpha-lane-id ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$WORK_DIR/bin/podman"
P0_TEST_LOG="$WORK_DIR/podman.log" PATH="$WORK_DIR/bin:$PATH" \
  python3 "$ROOT_DIR/ops/maintenance/start-worklane-containers.py" --manifest "$WORK_DIR/manifest.json"
grep -Fx 'start worklane-alpha-lane-id' "$WORK_DIR/podman.log" >/dev/null

sed -i 's/"lane-id"/"wrong-id"/' "$WORK_DIR/bin/podman"
if P0_TEST_LOG="$WORK_DIR/podman.log" PATH="$WORK_DIR/bin:$PATH" \
  python3 "$ROOT_DIR/ops/maintenance/start-worklane-containers.py" --manifest "$WORK_DIR/manifest.json" >/dev/null 2>&1; then
  printf 'autostart accepted a container with mismatched ownership labels\n' >&2
  exit 1
fi

mkdir -p "$WORK_DIR/home" "$WORK_DIR/root/alpha/.local/share/worklane/agent-work"
sed -i "s/\"owner\":\"test\"/\"owner\":\"$(id -un)\"/" "$WORK_DIR/manifest.json"
cat >"$WORK_DIR/bin/podman" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$P0_TEST_LOG"
case "$*" in
  'inspect --format {{.State.Status}} worklane-alpha-lane-id') printf '%s\n' running ;;
  'exec --user dev worklane-alpha-lane-id herdr --session alpha agent list')
    printf '%s\n' '{"result":{"agents":[{"agent":"codex","agent_status":"idle","state_change_seq":7}]}}' ;;
  'stop --time 30 worklane-alpha-lane-id') printf '%s\n' worklane-alpha-lane-id ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$WORK_DIR/bin/podman"
: >"$WORK_DIR/podman.log"
HOME="$WORK_DIR/home" P0_TEST_LOG="$WORK_DIR/podman.log" PATH="$WORK_DIR/bin:$PATH" \
  python3 "$ROOT_DIR/ops/maintenance/reap-idle-worklanes.py" --manifest "$WORK_DIR/manifest.json" --now 100
if grep -q '^stop ' "$WORK_DIR/podman.log"; then
  printf 'idle reaper stopped a lane before its threshold\n' >&2
  exit 1
fi
HOME="$WORK_DIR/home" P0_TEST_LOG="$WORK_DIR/podman.log" PATH="$WORK_DIR/bin:$PATH" \
  python3 "$ROOT_DIR/ops/maintenance/reap-idle-worklanes.py" --manifest "$WORK_DIR/manifest.json" --now 14501
grep -Fx 'stop --time 30 worklane-alpha-lane-id' "$WORK_DIR/podman.log" >/dev/null

touch "$WORK_DIR/root/alpha/.local/share/worklane/agent-work/agent--test.md"
: >"$WORK_DIR/podman.log"
HOME="$WORK_DIR/home" P0_TEST_LOG="$WORK_DIR/podman.log" PATH="$WORK_DIR/bin:$PATH" \
  python3 "$ROOT_DIR/ops/maintenance/reap-idle-worklanes.py" --manifest "$WORK_DIR/manifest.json" --idle-seconds 0 --now 20000
if grep -q '^stop ' "$WORK_DIR/podman.log"; then
  printf 'idle reaper stopped a claimed lane\n' >&2
  exit 1
fi

printf '[worklane-autostart-test] ok\n'
