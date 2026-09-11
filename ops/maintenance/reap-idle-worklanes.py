#!/usr/bin/env python3
"""Stop manifest-declared Worklane containers after a safe idle interval."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import time
import tomllib


def command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def attached(container: str) -> bool:
    uid = os.getuid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
            if f"Uid:\t{uid}\t" not in status:
                continue
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if container in cmdline and any(token in cmdline for token in (" attach ", " exec ", "lane attach")):
            return True
    return False


def agent_signature(container: str, session: str) -> tuple[bool, str] | None:
    result = command("podman", "exec", container, "herdr", "--session", session, "agent", "list")
    if result.returncode:
        return None
    try:
        agents = json.loads(result.stdout).get("result", {}).get("agents", [])
    except (json.JSONDecodeError, AttributeError):
        return None
    rows = []
    protected = False
    for agent in agents:
        state = str(agent.get("agent_status", agent.get("status", "unknown"))).lower()
        protected = protected or state in {"working", "blocked"}
        rows.append((str(agent.get("agent", "")), state, str(agent.get("state_change_seq", ""))))
    return protected, json.dumps(sorted(rows), separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path.home() / ".config/platform-zero/workspaces.json")
    parser.add_argument("--idle-seconds", type=int, default=4 * 60 * 60)
    parser.add_argument("--now", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    now = args.now if args.now is not None else int(time.time())
    manifest = json.loads(args.manifest.read_text())
    if manifest.get("schemaVersion") != 1 or manifest.get("owner") != pwd.getpwuid(os.getuid()).pw_name:
        raise SystemExit("worklane idle reaper: invalid manifest owner or schema")
    root = Path(manifest["root"]).resolve()
    state_root = Path.home() / ".local/state/platform-zero/worklane-idle"
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for workspace in manifest["workspaces"]:
        name = workspace["name"]
        project = Path(workspace.get("projectPath", root / name)).resolve()
        if project != root and root not in project.parents:
            raise SystemExit(f"worklane idle reaper: workspace escapes root: {project}")
        lane_path = project / ".worklane/lane.toml"
        if not lane_path.is_file():
            continue
        lane = tomllib.loads(lane_path.read_text())
        container = str(lane.get("container_name", ""))
        session = str(lane.get("session_name", lane.get("name", "")))
        state_path = state_root / f"{name}.json"
        inspection = command("podman", "inspect", "--format", "{{.State.Status}}", container)
        if inspection.returncode or inspection.stdout.strip() != "running":
            state_path.unlink(missing_ok=True)
            continue
        claims = project / ".local/share/worklane/agent-work"
        if any(claims.glob("agent--*.md")) or attached(container):
            state_path.unlink(missing_ok=True)
            continue
        agents = agent_signature(container, session)
        if agents is None or agents[0]:
            state_path.unlink(missing_ok=True)
            continue
        signature = agents[1]
        previous = {}
        if state_path.is_file():
            try:
                previous = json.loads(state_path.read_text())
            except json.JSONDecodeError:
                pass
        idle_since = int(previous.get("idleSince", now)) if previous.get("signature") == signature else now
        state_path.write_text(json.dumps({"signature": signature, "idleSince": idle_since}, sort_keys=True) + "\n")
        state_path.chmod(0o600)
        if now - idle_since >= args.idle_seconds:
            print(f"stopping idle lane {name}: {container}")
            if not args.dry_run:
                stopped = command("podman", "stop", "--time", "30", container)
                if stopped.returncode:
                    print(stopped.stderr.strip(), file=os.sys.stderr)
                    continue
                state_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
