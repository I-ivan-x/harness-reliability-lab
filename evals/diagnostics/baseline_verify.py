"""Portable read-only SHA-256 baseline manifest generator and verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = Path("artifacts/polish-baseline-2026-11-18")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_tree(directory: Path) -> dict[str, object]:
    files: dict[str, str] = {}
    total_bytes = 0
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = path.relative_to(directory).as_posix()
            files[rel] = sha256_file(path)
            total_bytes += path.stat().st_size
    tree_hasher = hashlib.sha256()
    for rel, digest in files.items():
        tree_hasher.update(f"{rel}\0{digest}\n".encode())
    return {
        "file_count": len(files),
        "total_bytes": total_bytes,
        "tree_sha256": tree_hasher.hexdigest(),
        "files": files,
    }


def git_info(project: Path) -> dict[str, object]:
    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=project, text=True).strip()

    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--", "."], cwd=project, text=True
    ).strip()
    return {
        "branch": git("branch", "--show-current"),
        "head_commit": git("rev-parse", "HEAD"),
        "freeze_tag": "harness-replication-v2",
        "freeze_tag_commit": git("rev-parse", "harness-replication-v2^{commit}"),
        "worktree_dirty": bool(status),
    }


EXEMPT_EXTERNALIZED_PREFIXES = ("interview/",)


def _check_historical_protected(
    project: Path, hist_manifest: dict[str, str]
) -> tuple[list[str], list[str]]:
    changed: list[str] = []
    exempted: list[str] = []
    for rel, expected in hist_manifest.items():
        fpath = project / rel
        if not fpath.is_file():
            if rel.startswith(EXEMPT_EXTERNALIZED_PREFIXES):
                exempted.append(rel)
                continue
            changed.append(rel)
        elif sha256_file(fpath) != expected:
            changed.append(rel)
    return changed, exempted
def check_no_local_paths(text: str) -> None:
    lowered = text.lower()
    for forbidden in ("d:\\", "d:/", "c:\\", "c:/", "\\users\\", "/users/"):
        if forbidden in lowered:
            raise ValueError(f"Forbidden local path marker found in manifest: {forbidden}")


def generate(project: Path, out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=False)
    raw_rel = "artifacts/replication-v2-2026-11-17"
    audit_rel = "artifacts/replication-v2-2026-11-17-audit"
    zip_rel = "artifacts/harness-replication-v2-2026-11-17.zip"
    contract_rel = "specs/replication-v2.json"
    hist_rel = "artifacts/replication-v2-preparation-2026-11-17/protected-before.json"

    raw_tree = hash_tree(project / raw_rel)
    audit_tree = hash_tree(project / audit_rel)
    zip_path = project / zip_rel
    zip_sha = sha256_file(zip_path)

    contract = json.loads((project / contract_rel).read_text(encoding="utf-8"))
    expected_code_hashes: dict[str, str] = contract["replication"]["code_sha256"]
    observed_code_hashes = {
        rel: sha256_file(project / rel) for rel in sorted(expected_code_hashes)
    }
    if observed_code_hashes != expected_code_hashes:
        raise AssertionError("Frozen 31 code hashes do not match specs/replication-v2.json")

    frozen_inputs: dict[str, str] = {}
    for path in sorted((project / "tasks/frozen").glob("*")):
        if path.is_file():
            frozen_inputs[path.relative_to(project).as_posix()] = sha256_file(path)
    for spec_rel in ("specs/replication-v1.json", "specs/replication-v2.json"):
        frozen_inputs[spec_rel] = sha256_file(project / spec_rel)

    hist_manifest: dict[str, str] = json.loads((project / hist_rel).read_text(encoding="utf-8"))
    hist_changed, _ = _check_historical_protected(project, hist_manifest)
    if hist_changed:
        raise AssertionError(f"Protected historical files changed: {hist_changed[:5]}")

    manifest = {
        "schema": "polish-baseline-manifest-v1",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "git": git_info(project),
        "raw_experiment": {"root": raw_rel, **raw_tree},
        "delivered_audit": {"root": audit_rel, **audit_tree},
        "delivered_archive": {
            "path": zip_rel,
            "bytes": zip_path.stat().st_size,
            "sha256": zip_sha,
        },
        "frozen_code_and_deps": {
            "contract": contract_rel,
            "file_count": len(observed_code_hashes),
            "matches_contract": True,
            "files": observed_code_hashes,
        },
        "frozen_tasks_and_specs": {
            "file_count": len(frozen_inputs),
            "files": frozen_inputs,
        },
        "historical_protected": {
            "reference": hist_rel,
            "file_count": len(hist_manifest),
            "changed": hist_changed,
        },
    }

    manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    raw_files = raw_tree["files"]
    assert isinstance(raw_files, dict)
    sums_lines = "".join(f"{digest}  {rel}\n" for rel, digest in raw_files.items())
    check_no_local_paths(manifest_json)
    check_no_local_paths(sums_lines)

    (out_dir / "sha256-manifest.json").write_text(manifest_json, encoding="utf-8")
    (out_dir / "replication-v2-2026-11-17.SHA256SUMS").write_text(sums_lines, encoding="utf-8")
    return {
        "raw_files": raw_tree["file_count"],
        "raw_tree_sha256": raw_tree["tree_sha256"],
        "audit_files": audit_tree["file_count"],
        "audit_tree_sha256": audit_tree["tree_sha256"],
        "zip_sha256": zip_sha,
        "frozen_code_files": len(observed_code_hashes),
        "frozen_task_spec_files": len(frozen_inputs),
        "historical_protected_files": len(hist_manifest),
        "git": manifest["git"],
    }


def verify(project: Path, out_dir: Path) -> dict[str, object]:
    manifest = json.loads((out_dir / "sha256-manifest.json").read_text(encoding="utf-8"))
    raw_now = hash_tree(project / manifest["raw_experiment"]["root"])
    audit_now = hash_tree(project / manifest["delivered_audit"]["root"])
    zip_now = sha256_file(project / manifest["delivered_archive"]["path"])
    code_now = {
        rel: sha256_file(project / rel)
        for rel in sorted(manifest["frozen_code_and_deps"]["files"])
    }
    tasks_now = {
        rel: sha256_file(project / rel)
        for rel in sorted(manifest["frozen_tasks_and_specs"]["files"])
    }
    hist_manifest: dict[str, str] = json.loads(
        (project / manifest["historical_protected"]["reference"]).read_text(encoding="utf-8")
    )
    hist_changed, hist_exempted = _check_historical_protected(project, hist_manifest)

    mismatches: dict[str, object] = {}
    if raw_now != {k: manifest["raw_experiment"][k] for k in raw_now}:
        mismatches["raw_experiment"] = True
    if audit_now != {k: manifest["delivered_audit"][k] for k in audit_now}:
        mismatches["delivered_audit"] = True
    if zip_now != manifest["delivered_archive"]["sha256"]:
        mismatches["delivered_archive"] = True
    if code_now != manifest["frozen_code_and_deps"]["files"]:
        mismatches["frozen_code_and_deps"] = True
    if tasks_now != manifest["frozen_tasks_and_specs"]["files"]:
        mismatches["frozen_tasks_and_specs"] = True
    if hist_changed:
        mismatches["historical_protected"] = hist_changed

    if mismatches:
        raise AssertionError(f"Baseline verification failed: {mismatches}")

    return {
        "verified_at_utc": datetime.now(UTC).isoformat(),
        "all_intact": True,
        "raw_files": raw_now["file_count"],
        "raw_tree_sha256": raw_now["tree_sha256"],
        "audit_files": audit_now["file_count"],
        "audit_tree_sha256": audit_now["tree_sha256"],
        "zip_sha256": zip_now,
        "frozen_code_files": len(code_now),
        "frozen_task_spec_files": len(tasks_now),
        "historical_protected_files": len(hist_manifest),
        "historical_exempted_external_files": len(hist_exempted),
        "git": git_info(project),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=PROJECT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    project = args.project.resolve()
    out_dir = (project / args.out_dir) if not args.out_dir.is_absolute() else args.out_dir
    run_verify = args.verify or not args.generate
    summary = verify(project, out_dir) if run_verify else generate(project, out_dir)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
