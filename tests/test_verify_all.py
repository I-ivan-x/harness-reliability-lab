"""Offline tests for dual-mode keyless master audit (`python -m evals.verify_all`)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MAX_LEDGER_BYTES = 150 * 1024


def _compute_ledger_payload_sha256(ledger: dict[str, object]) -> str:
    body = {k: v for k, v in ledger.items() if k != "ledger_integrity"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("LAB_MODEL_")}
    env.update(extra)
    return env


def _make_clean_clone_without_artifacts(dest: Path) -> Path:
    """Create a keyless, artifacts-free repository checkout fixture."""
    dest.mkdir(parents=True, exist_ok=True)
    for rel_dir in (
        "src/harness_lab",
        "evals",
        "specs",
        "tasks/frozen",
        "docs",
        "site",
        "tests",
        ".github",
    ):
        shutil.copytree(
            PROJECT / rel_dir,
            dest / rel_dir,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for rel_file in ("pyproject.toml", "uv.lock", "AGENTS.md", "README.md", ".env.example"):
        shutil.copy2(PROJECT / rel_file, dest / rel_file)
    assert not (dest / "artifacts").exists()
    assert not (dest / "interview").exists()
    return dest


def _run_ci(
    project_dir: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "evals.verify_all", "--ci", "--project", str(project_dir)],
        cwd=PROJECT,
        env=env or _clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_verify_all_ci_mode_passes_on_repo_and_artifacts_free_clone(tmp_path: Path) -> None:
    # 1. Real repository in --ci mode exits 0 and prints aligned scorecard
    res_repo = subprocess.run(
        [sys.executable, "-m", "evals.verify_all", "--ci"],
        cwd=PROJECT,
        env=_clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert res_repo.returncode == 0, res_repo.stderr
    assert "MASTER OFFLINE AUDIT SCORECARD" in res_repo.stdout
    assert "CI-CLEAN-CLONE" in res_repo.stdout
    assert "Docs, Links & Monograph" in res_repo.stdout

    # 2. Clean clone with zero artifacts/ and zero .git/ exits 0
    clone = _make_clean_clone_without_artifacts(tmp_path / "clean-clone")
    res_clone = _run_ci(clone)
    assert res_clone.returncode == 0, res_clone.stderr
    assert "PASS" in res_clone.stdout


def test_verify_all_blocks_tampering_and_oversized_ledger(tmp_path: Path) -> None:
    clone = _make_clean_clone_without_artifacts(tmp_path / "tamper-clone")
    ledger_file = clone / "evals/evidence_ledger.json"
    orig_bytes = ledger_file.read_bytes()

    # Case 1: Unhashed metric tampering in evidence_ledger.json
    tampered = json.loads(orig_bytes.decode("utf-8"))
    tampered["replication_v2"]["model_api_failures"] = 1
    ledger_file.write_text(json.dumps(tampered, indent=2), encoding="utf-8")
    r1 = _run_ci(clone)
    assert r1.returncode != 0
    assert "payload_sha256" in r1.stderr

    # Case 2: Re-hashed ledger that violates M6 3-tier PRM return hierarchy invariant
    bad_hier = json.loads(orig_bytes.decode("utf-8"))
    bad_hier["nextgen_modules"]["m6_process_grader"]["prm_return_hierarchy"]["STRICT_CLEAN"] = 0.1
    bad_hier["ledger_integrity"]["payload_sha256"] = _compute_ledger_payload_sha256(bad_hier)
    ledger_file.write_text(json.dumps(bad_hier, indent=2), encoding="utf-8")
    r2 = _run_ci(clone)
    assert r2.returncode != 0
    assert "M6 3-tier ledger invariant" in r2.stderr

    # Case 3: Oversized ledger (> 150 KB)
    oversized = json.loads(orig_bytes.decode("utf-8"))
    oversized["padding_blob"] = "x" * (MAX_LEDGER_BYTES + 1024)
    oversized["ledger_integrity"]["payload_sha256"] = _compute_ledger_payload_sha256(oversized)
    ledger_file.write_text(json.dumps(oversized, indent=2), encoding="utf-8")
    r3 = _run_ci(clone)
    assert r3.returncode != 0
    assert "150 KB" in r3.stderr
    ledger_file.write_bytes(orig_bytes)

    # Case 4: 1-byte mutation to frozen task file
    frozen_task = clone / "tasks/frozen/acc-05.json"
    orig_task = frozen_task.read_bytes()
    frozen_task.write_bytes(orig_task + b" ")
    r4 = _run_ci(clone)
    assert r4.returncode != 0
    frozen_task.write_bytes(orig_task)


def test_verify_all_blocks_envelope_path_secret_and_env_leaks(tmp_path: Path) -> None:
    clone = _make_clean_clone_without_artifacts(tmp_path / "leak-clone")
    ledger_file = clone / "evals/evidence_ledger.json"
    orig_ledger = ledger_file.read_bytes()

    # Case 1: Host security envelope key leaked inside evidence_ledger.json
    leaked_env = json.loads(orig_ledger.decode("utf-8"))
    leaked_env["leaked_wire"] = {"idempotency_key": "forbidden-slot-token"}
    leaked_env["ledger_integrity"]["payload_sha256"] = _compute_ledger_payload_sha256(leaked_env)
    ledger_file.write_text(json.dumps(leaked_env, indent=2), encoding="utf-8")
    r1 = _run_ci(clone)
    assert r1.returncode != 0
    assert "idempotency_key" in r1.stderr
    ledger_file.write_bytes(orig_ledger)

    # Case 2: Local filesystem path leaked in tracked markdown file
    doc_leak = clone / "README.md"
    orig_readme = doc_leak.read_bytes()
    win_leak = "C:" + "/Users/" + "alice/workspace/secret.txt"
    doc_leak.write_text(f"# Leak\n{win_leak}\n", encoding="utf-8")
    r2 = _run_ci(clone)
    assert r2.returncode != 0
    doc_leak.write_bytes(orig_readme)

    # Case 3: Live-pattern API secret leaked in static site file
    site_index = clone / "site/index.html"
    orig_site_index = site_index.read_bytes()
    fake_live_key = "sk-" + "liveprod9988776655443322"
    site_index.write_text(f"<html>{fake_live_key}</html>", encoding="utf-8")
    r3 = _run_ci(clone)
    assert r3.returncode != 0
    site_index.write_bytes(orig_site_index)

    # Case 4: Forbidden .env file present in repository
    dotenv_file = clone / ".env"
    dotenv_file.write_text("PLACEHOLDER=1\n", encoding="utf-8")
    r4 = _run_ci(clone)
    assert r4.returncode != 0
    dotenv_file.unlink()

    # Case 5: Private externalized interview/ directory leaked into public checkout
    priv_dir = clone / "interview"
    priv_dir.mkdir()
    (priv_dir / "index.html").write_text("<html>private</html>", encoding="utf-8")
    r5_priv = _run_ci(clone)
    assert r5_priv.returncode != 0
    shutil.rmtree(priv_dir)

    # Case 6: LAB_MODEL_* environment variable injected into process environment
    r6 = _run_ci(clone, env=_clean_env(LAB_MODEL_API_KEY="non-empty"))
    assert r6.returncode != 0
    assert "LAB_MODEL_" in r6.stderr


def test_verify_all_stage_b_ledger_sync_dead_links_and_emoji_gates(tmp_path: Path) -> None:
    clone = _make_clean_clone_without_artifacts(tmp_path / "stage-b-clone")

    # Gate S1: site/ledger-data.js payload drift from evals/evidence_ledger.json
    site_js = clone / "site/ledger-data.js"
    orig_js = site_js.read_bytes()
    drifted = json.loads((clone / "evals/evidence_ledger.json").read_text(encoding="utf-8"))
    drifted["post_training"]["sft_samples"] = 35
    site_js.write_text(
        "window.HARNESS_LEDGER = " + json.dumps(drifted, indent=2) + ";\n",
        encoding="utf-8",
    )
    r_sync = _run_ci(clone)
    assert r_sync.returncode != 0
    assert "ledger-data.js" in r_sync.stderr
    site_js.write_bytes(orig_js)

    # Gate S2a: Dead relative Markdown link in README.md
    readme = clone / "README.md"
    orig_readme = readme.read_bytes()
    readme.write_text(
        orig_readme.decode("utf-8") + "\nSee [missing](docs/removed-legacy-note.md).\n",
        encoding="utf-8",
    )
    r_link = _run_ci(clone)
    assert r_link.returncode != 0
    assert "dead relative link" in r_link.stderr
    readme.write_bytes(orig_readme)

    # Gate S2b: Relative Markdown link pointing into gitignored artifacts/
    emp_doc = clone / "docs/empirical-evaluation.md"
    orig_emp = emp_doc.read_bytes()
    emp_doc.write_text(
        orig_emp.decode("utf-8")
        + "\nSee [raw](../artifacts/replication-v2-2026-11-17/batch.json).\n",
        encoding="utf-8",
    )
    r_art_link = _run_ci(clone)
    assert r_art_link.returncode != 0
    assert "untracked/excluded path" in r_art_link.stderr
    emp_doc.write_bytes(orig_emp)

    # Gate S3a: Emoji glyph injected into site/index.html
    site_index = clone / "site/index.html"
    orig_index = site_index.read_bytes()
    site_index.write_text(
        orig_index.decode("utf-8").replace("</body>", "\U0001f680</body>"),
        encoding="utf-8",
    )
    r_emoji = _run_ci(clone)
    assert r_emoji.returncode != 0
    assert "Emoji" in r_emoji.stderr
    site_index.write_bytes(orig_index)

    # Gate S3b: Forbidden CSS gradient injected into site/styles.css
    site_css = clone / "site/styles.css"
    orig_css = site_css.read_bytes()
    css_rule = "\n.bad { background: linear-" + "gradient(#FAF9F5, #F3F1EA); }\n"
    site_css.write_text(orig_css.decode("utf-8") + css_rule, encoding="utf-8")
    r_css = _run_ci(clone)
    assert r_css.returncode != 0
    assert "gradient" in r_css.stderr
    site_css.write_bytes(orig_css)

    # Gate S3c: .github/workflows/pages.yml upload directory mismatch
    pages_yml = clone / ".github/workflows/pages.yml"
    orig_pages = pages_yml.read_bytes()
    pages_yml.write_text(
        orig_pages.decode("utf-8").replace("path: site", "path: dist"),
        encoding="utf-8",
    )
    r_pages = _run_ci(clone)
    assert r_pages.returncode != 0
    assert "pages.yml" in r_pages.stderr
    pages_yml.write_bytes(orig_pages)

    # Gate S3d: Deprecated section symbol (§) injected into site/index.html
    site_index.write_text(
        orig_index.decode("utf-8").replace("</body>", "\u00a71</body>"),
        encoding="utf-8",
    )
    r_sec = _run_ci(clone)
    assert r_sec.returncode != 0
    assert "section symbol" in r_sec.stderr
    site_index.write_bytes(orig_index)

    # Gate S4a: Companion HTML page byte drift from Markdown source
    arch_html = clone / "site/architecture.html"
    orig_arch = arch_html.read_bytes()
    arch_html.write_text(
        orig_arch.decode("utf-8").replace("</body>", "<!-- drifted --></body>"),
        encoding="utf-8",
    )
    r_drift = _run_ci(clone)
    assert r_drift.returncode != 0
    assert "out of sync" in r_drift.stderr
    arch_html.write_bytes(orig_arch)

    # Gate S4b: Unparsed Markdown (**bold** or raw .md href) outside <pre>/<code>
    site_index.write_text(
        orig_index.decode("utf-8").replace("</body>", "<p>**unparsed**</p></body>"),
        encoding="utf-8",
    )
    r_unparsed = _run_ci(clone)
    assert r_unparsed.returncode != 0
    assert "unparsed" in r_unparsed.stderr
    site_index.write_bytes(orig_index)

    site_index.write_text(
        orig_index.decode("utf-8").replace('href="./overview.html"', 'href="../README.md"'),
        encoding="utf-8",
    )
    r_raw_jump = _run_ci(clone)
    assert r_raw_jump.returncode != 0
    assert "raw .md/.json href" in r_raw_jump.stderr
    site_index.write_bytes(orig_index)


def test_static_monograph_data_bindings_and_radius_contract() -> None:
    import re

    html = (PROJECT / "site/index.html").read_text(encoding="utf-8")
    app_js = (PROJECT / "site/app.js").read_text(encoding="utf-8")
    svg_txt = (PROJECT / "site/control-plane.svg").read_text(encoding="utf-8")
    ledger = json.loads((PROJECT / "evals/evidence_ledger.json").read_text(encoding="utf-8"))

    # Verify GitHub Dark Mode explicit warm-white canvas background rect on control-plane.svg
    first_rect = re.search(r"<svg[^>]*>\s*(<rect[^>]+>)", svg_txt)
    assert first_rect is not None and 'fill="#FAF9F5"' in first_rect.group(1)

    # Verify closed-loop companion HTML routes in masthead & presence of all 5 companion pages
    masthead_block = re.search(r'<div class="masthead-links">([\s\S]*?)</div>', html)
    assert masthead_block is not None
    masthead_hrefs = re.findall(r'href="([^"]+)"', masthead_block.group(1))
    assert masthead_hrefs == [
        "./overview.html",
        "./architecture.html",
        "./evaluation.html",
        "./ledger.html",
        "./agents.html",
    ]
    for page_name in masthead_hrefs:
        comp_path = PROJECT / "site" / page_name[2:]
        assert comp_path.is_file()
        comp_txt = comp_path.read_text(encoding="utf-8")
        assert 'href="./index.html"' in comp_txt

    html_binds = set(re.findall(r'data-bind="([^"]+)"', html))
    js_binds = set(re.findall(r"^\s{4}([a-z0-9_]+)\s*:", app_js, re.MULTILINE))
    assert len(html_binds) >= 45
    assert html_binds <= js_binds, f"Unbound HTML data-bind keys: {html_binds - js_binds}"

    slices = ledger["representative_stepper_slices"]
    assert len(slices["interactive_four_trajectories"]) == 4
    assert len(ledger["diagnostics_and_probes"]["acc15_four_way_comparison"]["variants"]) == 4
    assert set(slices["m6_three_tier_examples"]) == {
        "STRICT_CLEAN",
        "VALID_WITH_HYGIENE_WARN",
        "REWARD_HACK_BLOCKED",
    }

