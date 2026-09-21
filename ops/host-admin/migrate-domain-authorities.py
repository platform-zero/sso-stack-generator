#!/usr/bin/env python3
"""Guarded one-time migration from domain accounts to grouped authorities."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"authority-migration: {message}")


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def account(name: str) -> pwd.struct_passwd | None:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def translate_tree(root: Path, old_uid: int, old_subid: int, new_uid: int, new_gid: int, new_subid: int) -> None:
    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        stat = path.lstat()

        def mapped(value: int, direct: int, target_direct: int) -> int:
            if value == direct:
                return target_direct
            if old_subid <= value < old_subid + 65536:
                return new_subid + value - old_subid
            return value

        uid = mapped(stat.st_uid, old_uid, new_uid)
        gid = mapped(stat.st_gid, old_uid, new_gid)
        if (uid, gid) != (stat.st_uid, stat.st_gid):
            os.lchown(path, uid, gid)


def merge_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = destination / child.name
        if target.exists():
            fail(f"volume collision: {child} -> {target}")
        shutil.move(str(child), str(target))


def stack_is_stopped(users: set[str]) -> bool:
    for user in users:
        row = account(user)
        if row is None:
            continue
        result = subprocess.run(
            ["runuser", "-u", user, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{row.pw_uid}", "podman", "ps", "-q"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if result.stdout.strip():
            return False
    return True


def rewrite_subids(old: str, new: str, expected: int) -> None:
    for filename in (Path("/etc/subuid"), Path("/etc/subgid")):
        rows = filename.read_text().splitlines()
        replacement = f"{new}:{expected}:65536"
        rendered = [replacement if row.startswith(f"{old}:") else row for row in rows]
        if not any(row.startswith(f"{new}:") for row in rendered):
            rendered.append(replacement)
        filename.write_text("\n".join(dict.fromkeys(rendered)) + "\n")


def snapshot(plan: dict, snapshot_dir: Path) -> None:
    if snapshot_dir.exists():
        saved_plan = snapshot_dir / "plan.json"
        if (snapshot_dir / "APPLIED").exists() or not saved_plan.exists() or json.loads(saved_plan.read_text()) != plan:
            fail(f"snapshot already exists and is not reusable: {snapshot_dir}")
        print(f"[authority-migration] reusing complete unapplied snapshot {snapshot_dir}")
        return
    snapshot_dir.mkdir(parents=True, mode=0o700)
    shutil.copy2(args.plan, snapshot_dir / "plan.json")
    etc = snapshot_dir / "etc"
    etc.mkdir()
    for name in ("passwd", "group", "shadow", "gshadow", "subuid", "subgid"):
        path = Path("/etc") / name
        if path.exists():
            shutil.copy2(path, etc / name)
    for target in plan["targets"]:
        for source in target["sources"]:
            for root in (Path("/mnt/stack/podman"), Path("/mnt/stack/rootless")):
                path = root / source["name"]
                if path.exists():
                    destination = snapshot_dir / path.relative_to("/")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    run("cp", "-a", "--reflink=auto", str(path), str(destination))


def apply(plan: dict, snapshot_dir: Path) -> None:
    users = {source["user"] for target in plan["targets"] for source in target["sources"]}
    if not stack_is_stopped(users):
        fail("a source authority still has running containers")
    snapshot(plan, snapshot_dir)
    for user in sorted(users):
        if account(user) is not None:
            subprocess.run(["loginctl", "terminate-user", user], check=False)
    for target in plan["targets"]:
        survivor = next(source for source in target["sources"] if source["name"] == target["survivor"])
        old_user, new_user = survivor["user"], target["user"]
        old_domain, new_domain = survivor["name"], target["name"]
        if old_user != new_user:
            run("usermod", "--login", new_user, "--home", f"/home/{new_user}", "--move-home", old_user)
            old_group = subprocess.check_output(["id", "-gn", new_user], text=True).strip()
            if old_group == old_user:
                run("groupmod", "--new-name", new_user, old_group)
            rewrite_subids(old_user, new_user, int(target["subid"]))
        for root in (Path("/mnt/stack/podman"), Path("/mnt/stack/rootless")):
            old_path, new_path = root / old_domain, root / new_domain
            if old_path.exists() and old_path != new_path:
                if new_path.exists():
                    fail(f"target path already exists: {new_path}")
                old_path.rename(new_path)
        destination = Path("/mnt/stack/rootless") / new_domain
        for source in target["sources"]:
            if source["name"] == old_domain:
                continue
            source_root = Path("/mnt/stack/rootless") / source["name"]
            translate_tree(source_root, int(source["uid"]), int(source["subid"]), int(target["uid"]), int(target["uid"]), int(target["subid"]))
            merge_tree(source_root, destination)
            podman_root = Path("/mnt/stack/podman") / source["name"]
            if podman_root.exists():
                shutil.rmtree(podman_root)
            if source_root.exists():
                source_root.rmdir()
            run("userdel", source["user"])
        translate_tree(destination, int(survivor["uid"]), int(survivor["subid"]), int(target["uid"]), int(target["uid"]), int(target["subid"]))
    (snapshot_dir / "APPLIED").write_text(f"{int(time.time())}\n")


def verify(plan: dict) -> None:
    errors: list[str] = []
    for target in plan["targets"]:
        row = account(target["user"])
        if row is None or row.pw_uid != int(target["uid"]):
            errors.append(f"missing or wrong target account: {target['user']}")
        for source in target["sources"]:
            if source["user"] != target["user"] and account(source["user"]) is not None:
                errors.append(f"absorbed account remains: {source['user']}")
    if errors:
        fail("; ".join(errors))
    print("[authority-migration] verified")


def rollback(plan: dict, snapshot_dir: Path) -> None:
    if not (snapshot_dir / "APPLIED").exists():
        fail(f"snapshot is not an applied migration: {snapshot_dir}")
    users = {target["user"] for target in plan["targets"]}
    if not stack_is_stopped(users):
        fail("a target authority still has running containers")
    failed = snapshot_dir / "failed-current"
    failed.mkdir(exist_ok=False)
    for target in plan["targets"]:
        for root in (Path("/mnt/stack/podman"), Path("/mnt/stack/rootless")):
            current = root / target["name"]
            if current.exists():
                destination = failed / current.relative_to("/")
                destination.parent.mkdir(parents=True, exist_ok=True)
                current.rename(destination)
    for name in ("passwd", "group", "shadow", "gshadow", "subuid", "subgid"):
        saved = snapshot_dir / "etc" / name
        if saved.exists():
            shutil.copy2(saved, Path("/etc") / name)
    saved_mnt = snapshot_dir / "mnt"
    if saved_mnt.exists():
        for path in sorted(saved_mnt.rglob("*"), key=lambda item: len(item.parts)):
            relative = path.relative_to(snapshot_dir)
            destination = Path("/") / relative
            if path.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            elif path.is_symlink():
                destination.symlink_to(os.readlink(path))
            else:
                shutil.copy2(path, destination)
    (snapshot_dir / "ROLLED_BACK").write_text(f"{int(time.time())}\n")


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("check", "apply", "verify", "rollback"))
parser.add_argument("--plan", required=True, type=Path)
parser.add_argument("--snapshot-id")
args = parser.parse_args()
plan = json.loads(args.plan.read_text())
if plan.get("schemaVersion") != 1:
    fail("unsupported plan schema")
snapshot_id = args.snapshot_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
snapshot_dir = Path(plan["snapshotRoot"]) / snapshot_id
if args.mode == "check":
    for target in plan["targets"]:
        for source in target["sources"]:
            row = account(source["user"])
            print(f"{source['name']}\t{source['user']}\t{row.pw_uid if row else 'absent'}\t->\t{target['name']}")
elif os.geteuid() != 0:
    fail(f"{args.mode} requires root")
elif args.mode == "apply":
    apply(plan, snapshot_dir)
elif args.mode == "rollback":
    if not args.snapshot_id:
        fail("rollback requires --snapshot-id")
    rollback(plan, snapshot_dir)
else:
    verify(plan)
