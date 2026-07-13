#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ALLOWED_PREFIXES = (
    "global.settings/",
    "stack.compose/",
    "stack.config/",
    "stack.containers/",
    "stack.kotlin/",
    "stack.js/",
    "stack.systemd/",
    "scripts/lib/",
    "scripts/modules/",
    "docs/modules/",
    "tests/fixtures/",
)
ALLOWED_ROOTS = {prefix.rstrip("/") for prefix in ALLOWED_PREFIXES} | {"stack.runtime.yaml"}


def die(message: str) -> None:
    raise SystemExit(f"module lock error: {message}")


def run(cmd: list[str], cwd: Path | None = None, quiet: bool = False) -> str:
    kwargs = {
        "cwd": cwd,
        "text": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "check": False,
    }
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        die(f"command failed: {' '.join(cmd)}{': ' + detail if detail else ''}")
    if not quiet and result.stderr:
        sys.stderr.write(result.stderr)
    return result.stdout.strip()


def safe_cache_name(label: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in label).strip("-")
    return (safe or "module")[:80]


def validate_rel_path(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        die(f"{label} path must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        die(f"{label} path is unsafe: {value}")


def path_allowed(value: str) -> bool:
    return value in ALLOWED_ROOTS or value.startswith(ALLOWED_PREFIXES)


def clone_at_commit(cache_dir: Path, label: str, remote: str, ref: str, commit: str) -> Path:
    if not remote:
        die(f"module '{label}' is missing git remote")
    if not commit:
        die(f"module '{label}' is missing commit pin")

    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_dir / safe_cache_name(label)
    if not (repo_dir / ".git").is_dir():
        if repo_dir.exists():
            shutil.rmtree(repo_dir)
        run(["git", "clone", "--no-checkout", remote, str(repo_dir)])
    else:
        current_remote = run(["git", "-C", str(repo_dir), "remote", "get-url", "origin"], quiet=True)
        if current_remote != remote:
            shutil.rmtree(repo_dir)
            run(["git", "clone", "--no-checkout", remote, str(repo_dir)])

    if ref:
        fetch = subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--tags", "origin", ref],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if fetch.returncode != 0:
            run(["git", "-C", str(repo_dir), "fetch", "--tags", "origin"])
    else:
        run(["git", "-C", str(repo_dir), "fetch", "--tags", "origin"])

    run(["git", "-C", str(repo_dir), "cat-file", "-e", f"{commit}^{{commit}}"], quiet=True)
    run(["git", "-C", str(repo_dir), "checkout", "--detach", "--force", commit], quiet=True)
    run(["git", "-C", str(repo_dir), "clean", "-fdx"], quiet=True)
    return repo_dir


def validate_tree(root: Path) -> None:
    for link_path in root.rglob("*"):
        if not link_path.is_symlink():
            continue
        target = link_path.resolve(strict=True)
        try:
            target.relative_to(root)
        except ValueError:
            die(f"module symlink escapes module root: {link_path} -> {target}")


def load_json(path: Path, label: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        die(f"{label} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        die(f"{label} must be an object")
    return data


def validate_metadata(lock_entry: dict, metadata: dict, source_dir: Path) -> dict:
    module_id = lock_entry.get("id")
    repo = lock_entry.get("repo")
    if metadata.get("schemaVersion") != 1:
        die(f"module '{module_id}' stack.module.json schemaVersion must be 1")
    if metadata.get("id") != module_id:
        die(f"module id mismatch for '{module_id}': stack.module.json says {metadata.get('id')}")
    if metadata.get("repo") != repo:
        die(f"module repo mismatch for '{module_id}': lock says {repo}, stack.module.json says {metadata.get('repo')}")
    if metadata.get("lifecycle") == "retired":
        die(f"module '{module_id}' is retired")

    dependencies = lock_entry.get("dependencies", metadata.get("dependencies", []))
    overlays = metadata.get("overlays")
    if not isinstance(dependencies, list) or not all(isinstance(dep, str) and dep for dep in dependencies):
        die(f"module '{module_id}' dependencies must be an array of strings")
    if module_id in dependencies:
        die(f"module '{module_id}' depends on itself")
    if not isinstance(overlays, list) or not overlays:
        die(f"module '{module_id}' overlays must be a non-empty array")

    for overlay in overlays:
        validate_rel_path(overlay, f"module '{module_id}' overlay")
        if not path_allowed(overlay):
            die(f"module '{module_id}' overlay path is not allowed: {overlay}")
        if not (source_dir / overlay).exists():
            die(f"module '{module_id}' overlay path does not exist: {overlay}")

    return {
        "id": module_id,
        "repo": repo,
        "dependencies": dependencies,
        "overlays": overlays,
        "metadata": metadata,
    }


def topo_sort(modules: dict[str, dict], roots: list[str]) -> list[str]:
    selected: list[str] = []
    state: dict[str, str] = {}

    def visit(module_id: str, stack: list[str]) -> None:
        if module_id not in modules:
            die(f"missing module dependency/root: {module_id}")
        mark = state.get(module_id)
        if mark == "done":
            return
        if mark == "visiting":
            die("module dependency cycle: " + " -> ".join(stack + [module_id]))
        state[module_id] = "visiting"
        for dep in modules[module_id]["dependencies"]:
            visit(dep, stack + [module_id])
        state[module_id] = "done"
        selected.append(module_id)

    for root in roots or list(modules):
        visit(root, [])
    return selected


def iter_overlay_files(source_dir: Path, overlay: str) -> list[tuple[Path, str]]:
    path = source_dir / overlay
    if path.is_file():
        return [(path, overlay)]
    files = []
    for file_path in sorted(path.rglob("*")):
        if ".git" in file_path.parts or not file_path.is_file():
            continue
        rel = str(file_path.relative_to(source_dir))
        files.append((file_path, rel))
    return files


def dest_for(module_id: str, rel_path: str) -> str | None:
    if rel_path in {"README.md", "stack.module.json"} or rel_path.startswith("tests/"):
        return None
    if rel_path in {"stack.config/components.json", "stack.config/components.overlay.json"}:
        return f"stack.config/components.external/{module_id}.json"
    if rel_path == "stack.config/service-contracts.json":
        return f"stack.config/service-contracts.external/{module_id}.json"
    if rel_path == "stack.runtime.yaml":
        return f"stack.runtime.external/{module_id}.yaml"
    return rel_path


def materialize(
    order: list[str],
    modules: dict[str, dict],
    materialized_dir: Path,
    source_root: Path,
) -> list[dict]:
    metadata_rows = []
    seen_dest: dict[str, str] = {}
    materialized_dir.mkdir(parents=True, exist_ok=True)

    for module_id in order:
        module = modules[module_id]
        lock_entry = module["lock"]
        source_dir = module["source_dir"]
        validate_tree(source_dir)
        for overlay in module["overlays"]:
            for src_file, rel_path in iter_overlay_files(source_dir, overlay):
                if not path_allowed(rel_path):
                    die(f"module '{module_id}' has unsupported materialized path: {rel_path}")
                dest_rel = dest_for(module_id, rel_path)
                if dest_rel is None:
                    continue
                if dest_rel in seen_dest:
                    die(f"module '{module_id}' collides with module '{seen_dest[dest_rel]}' at {dest_rel}")
                if (
                    rel_path not in {"stack.config/components.json", "stack.config/components.overlay.json", "stack.config/service-contracts.json", "stack.runtime.yaml"}
                    and (source_root / rel_path).exists()
                    and rel_path not in set(lock_entry.get("overrides", []))
                ):
                    die(f"module '{module_id}' would override base file without declaring it: {rel_path}")
                seen_dest[dest_rel] = module_id
                dest_path = materialized_dir / dest_rel
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dest_path)

        metadata_rows.append(
            {
                "name": module_id,
                "id": module_id,
                "repo": module["repo"],
                "git": lock_entry["git"],
                "ref": lock_entry.get("ref", ""),
                "commit": lock_entry["commit"],
                "path": lock_entry.get("path", "."),
                "dependencies": module["dependencies"],
                "overlays": module["overlays"],
                "lifecycle": module["metadata"].get("lifecycle"),
                "sourceRepo": module["metadata"].get("sourceRepo"),
            }
        )
    return metadata_rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-file", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--materialized-dir", required=True)
    parser.add_argument("--metadata-file", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--manifest-remote", required=True)
    parser.add_argument("--manifest-ref", required=True)
    parser.add_argument("--manifest-commit", required=True)
    parser.add_argument("--manifest-path", required=True)
    args = parser.parse_args()

    lock_path = Path(args.manifest_file)
    lock = load_json(lock_path, "module lock")
    if lock.get("schemaVersion") != 2:
        die("v2 resolver requires schemaVersion: 2")
    entries = lock.get("modules")
    if not isinstance(entries, list):
        die("modules must be an array")
    roots = lock.get("roots", [])
    if roots is None:
        roots = []
    if not isinstance(roots, list) or not all(isinstance(root, str) and root for root in roots):
        die("roots must be an array of module ids")

    by_id: dict[str, dict] = {}
    by_repo: dict[str, str] = {}
    cache_dir = Path(args.cache_dir)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            die(f"module entry {index} must be an object")
        module_id = entry.get("id")
        repo = entry.get("repo")
        if not isinstance(module_id, str) or not module_id:
            die(f"module entry {index} is missing id")
        if not isinstance(repo, str) or not repo:
            die(f"module '{module_id}' is missing repo")
        if module_id in by_id:
            die(f"duplicate module id: {module_id}")
        if repo in by_repo:
            die(f"duplicate module repo: {repo} ({by_repo[repo]}, {module_id})")
        by_repo[repo] = module_id
        validate_rel_path(entry.get("path", "."), f"module '{module_id}' path")
        repo_dir = clone_at_commit(cache_dir, f"module-{module_id}", entry.get("git", ""), entry.get("ref", ""), entry.get("commit", ""))
        source_dir = (repo_dir / entry.get("path", ".")).resolve(strict=True)
        try:
            source_dir.relative_to(repo_dir)
        except ValueError:
            die(f"module '{module_id}' path escapes repo: {entry.get('path', '.')}")
        metadata_path = source_dir / "stack.module.json"
        if not metadata_path.is_file():
            die(f"module '{module_id}' is missing stack.module.json")
        metadata = load_json(metadata_path, f"module '{module_id}' stack.module.json")
        validated = validate_metadata(entry, metadata, source_dir)
        validated.update({"lock": entry, "source_dir": source_dir})
        by_id[module_id] = validated

    order = topo_sort(by_id, roots)
    materialized_dir = Path(args.materialized_dir)
    if materialized_dir.exists():
        shutil.rmtree(materialized_dir)
    rows = materialize(order, by_id, materialized_dir, Path(args.source_root))
    metadata = {
        "enabled": True,
        "schemaVersion": 2,
        "manifest": {
            "git": args.manifest_remote,
            "ref": args.manifest_ref,
            "commit": args.manifest_commit,
            "path": args.manifest_path,
        },
        "roots": roots,
        "modules": rows,
    }
    Path(args.metadata_file).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
