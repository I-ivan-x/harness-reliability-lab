"""Deterministic pure-stdlib Markdown & JSON -> Warm-White Monograph HTML compiler."""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from evals.nextgen import enforce

COMPANION_PAGES: tuple[tuple[str, str, str | None], ...] = (
    ("overview.html", "仓库导览与速查表 (README)", "README.md"),
    ("architecture.html", "控制面与协议规范 (Architecture)", "docs/architecture-and-protocol.md"),
    ("evaluation.html", "实证评估报告 (Evaluation)", "docs/empirical-evaluation.md"),
    ("ledger.html", "公开证据账本 (Ledger)", None),
    ("agents.html", "工程纪律契约 (AGENTS)", "AGENTS.md"),
)

ROUTE_MAP: dict[str, str] = {
    "README.md": "./overview.html",
    "site/index.html": "./index.html",
    "index.html": "./index.html",
    "docs/architecture-and-protocol.md": "./architecture.html",
    "architecture-and-protocol.md": "./architecture.html",
    "docs/empirical-evaluation.md": "./evaluation.html",
    "empirical-evaluation.md": "./evaluation.html",
    "AGENTS.md": "./agents.html",
    "evals/evidence_ledger.json": "./ledger.html",
    "evidence_ledger.json": "./ledger.html",
}

FENCE_RE = re.compile(r"^```([a-zA-Z0-9_+-]*)\n([\s\S]*?)^```[ \t]*$", re.MULTILINE)
INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
INLINE_MATH_RE = re.compile(r"\$([^$\n]+)\$")
HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*$")
HR_RE = re.compile(r"^---+\s*$")
TOP_UL_RE = re.compile(r"^[-*]\s+(.+)$")
TOP_OL_RE = re.compile(r"^\d+\.\s+(.+)$")
SUB_LI_RE = re.compile(r"^[ \t]{2,}(?:[-*]|\d+\.)\s+(.+)$")
TABLE_SEP_CELL_RE = re.compile(r"^:?-{3,}:?$")

# Residual unparsed Markdown checks outside <pre>/<code>/<script>/<style>
STRIP_SAFE_TAGS_RE = re.compile(
    r"<(pre|code|script|style)\b[^>]*>[\s\S]*?</\1>",
    re.IGNORECASE,
)
RESIDUAL_MD_BOLD_RE = re.compile(r"\*\*[^*]+\*\*")
RESIDUAL_MD_HEADING_RE = re.compile(r"(?:^|\n)[ \t]*#{1,6}\s+\S")
RESIDUAL_MD_LINK_RE = re.compile(r"\[[^\]]+\]\([^)]+\.(?:md|json)[^)]*\)")
RAW_DOC_HREF_RE = re.compile(r'href="[^"]*\.(?:md|json)(?:[#?][^"]*)?"', re.IGNORECASE)


def _clean_tex(expr: str) -> str:
    """Convert lightweight LaTeX math notations into clean readable typography."""
    out = expr.strip()
    out = re.sub(r"\\text\{([^}]*)\}", r"\1", out)
    out = out.replace(r"\_", "_").replace(r"\%", "%")
    out = out.replace(r"\mathbb{Z}^+", "Z+")
    out = out.replace(r"\Delta_{adv}", "Δ_adv").replace(r"\Delta_adv", "Δ_adv")
    out = out.replace(r"\Delta_{think}", "Δ_think").replace(r"\Delta_think", "Δ_think")
    out = out.replace(r"p_{rec}", "p_rec")
    out = re.sub(r"\\frac\{([^}]*)\}\{([^}]*)\}", r"(\1) / (\2)", out)
    out = out.replace(r"\iff", "⇔").replace(r"\implies", "⇒")
    out = out.replace(r"\approx", "≈").replace(r"\in", "∈").replace(r"\cdot", "·")
    out = out.replace(r"\gamma", "γ")
    out = out.replace(r"\quad", " ")
    return html.escape(out, quote=False)


def _slugify(text: str, idx: int) -> str:
    ascii_part = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return f"sec-{idx}-{ascii_part}" if ascii_part else f"sec-{idx}"


def _rewrite_href(raw_href: str) -> str:
    target = raw_href.strip()
    if target.startswith(("http://", "https://", "mailto:", "#")):
        return target
    frag = ""
    if "#" in target:
        target, frag_part = target.split("#", 1)
        frag = "#" + frag_part
    norm = target.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    while norm.startswith("../"):
        norm = norm[3:]
    mapped = ROUTE_MAP.get(norm)
    if mapped is not None:
        return mapped + frag
    return raw_href


def _rewrite_img_src(raw_src: str) -> str:
    norm = raw_src.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    while norm.startswith("../"):
        norm = norm[3:]
    if norm.startswith("site/"):
        return "./" + norm[len("site/") :]
    return raw_src


def _protect_inline_codes(text: str, store: list[str]) -> str:
    def _repl(match: re.Match[str]) -> str:
        idx = len(store)
        escaped = html.escape(match.group(1), quote=False)
        store.append(f"<code>{escaped}</code>")
        return f"\x00ICODE_{idx}\x00"

    return INLINE_CODE_RE.sub(_repl, text)


def _restore_tokens(text: str, prefix: str, store: list[str]) -> str:
    out = text
    for idx, val in enumerate(store):
        out = out.replace(f"\x00{prefix}_{idx}\x00", val)
    return out


def _render_inline(raw_text: str) -> str:
    code_store: list[str] = []
    math_store: list[str] = []

    step = _protect_inline_codes(raw_text, code_store)

    def _math_repl(match: re.Match[str]) -> str:
        idx = len(math_store)
        math_store.append(f'<span class="mono">{_clean_tex(match.group(1))}</span>')
        return f"\x00IMATH_{idx}\x00"

    step = INLINE_MATH_RE.sub(_math_repl, step)
    step = html.escape(step, quote=False)

    def _img_repl(match: re.Match[str]) -> str:
        alt = html.escape(match.group(1), quote=True)
        src = html.escape(_rewrite_img_src(match.group(2)), quote=True)
        return f'<figure class="doc-figure"><img src="{src}" alt="{alt}"></figure>'

    step = IMAGE_RE.sub(_img_repl, step)

    def _link_repl(match: re.Match[str]) -> str:
        label = match.group(1)
        href = html.escape(_rewrite_href(match.group(2)), quote=True)
        return f'<a href="{href}">{label}</a>'

    step = LINK_RE.sub(_link_repl, step)
    step = BOLD_RE.sub(r"<strong>\1</strong>", step)

    step = _restore_tokens(step, "IMATH", math_store)
    step = _restore_tokens(step, "ICODE", code_store)
    return step


def _split_table_row(line: str) -> list[str]:
    temp_codes: list[str] = []

    def _save_raw_backtick(match: re.Match[str]) -> str:
        idx = len(temp_codes)
        temp_codes.append(match.group(0))
        return f"\x00TCODE_{idx}\x00"

    protected = INLINE_CODE_RE.sub(_save_raw_backtick, line.strip())
    if protected.startswith("|"):
        protected = protected[1:]
    if protected.endswith("|"):
        protected = protected[:-1]
    cells = [c.strip() for c in protected.split("|")]
    return [_restore_tokens(c, "TCODE", temp_codes) for c in cells]


def _is_table_separator(line: str) -> bool:
    s = line.strip()
    if "|" not in s:
        return False
    cells = _split_table_row(s)
    return bool(cells) and all(TABLE_SEP_CELL_RE.match(c) is not None for c in cells)


def _parse_alignments(sep_line: str) -> list[str]:
    aligns: list[str] = []
    for cell in _split_table_row(sep_line):
        if cell.startswith(":") and cell.endswith(":"):
            aligns.append("center")
        elif cell.endswith(":"):
            aligns.append("right")
        else:
            aligns.append("left")
    return aligns


def compile_markdown_body(md_text: str) -> str:
    """ deterministically compile GitHub-flavored Markdown subset into semantic HTML."""
    normalized = md_text.replace("\r\n", "\n")
    code_blocks: list[str] = []

    def _fence_repl(match: re.Match[str]) -> str:
        idx = len(code_blocks)
        lang = match.group(1).strip()
        body_raw = match.group(2).rstrip("\n")
        escaped = html.escape(body_raw, quote=False)
        if lang == "text" and "\n" not in body_raw.strip():
            code_blocks.append(f'<div class="equation-box">{escaped.strip()}</div>')
        else:
            cls = f' class="language-{html.escape(lang, quote=True)}"' if lang else ""
            code_blocks.append(f'<pre class="doc-code"><code{cls}>{escaped}</code></pre>')
        return f"\n\x00FENCE_{idx}\x00\n"

    staged = FENCE_RE.sub(_fence_repl, normalized)
    lines = staged.split("\n")
    blocks: list[str] = []
    heading_counter = 0
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # Fenced code placeholder
        if stripped.startswith("\x00FENCE_") and stripped.endswith("\x00"):
            blocks.append(stripped)
            i += 1
            continue

        # Standalone display math $$ ... $$
        if stripped.startswith("$$"):
            if stripped.endswith("$$") and len(stripped) > 4:
                tex_inner = stripped[2:-2]
                blocks.append(f'<div class="equation-box">{_clean_tex(tex_inner)}</div>')
                i += 1
                continue
            math_lines: list[str] = []
            i += 1
            while i < n and not lines[i].strip().endswith("$$"):
                math_lines.append(lines[i])
                i += 1
            if i < n:
                tail = lines[i].strip()[:-2]
                if tail:
                    math_lines.append(tail)
                i += 1
            blocks.append(f'<div class="equation-box">{_clean_tex(" ".join(math_lines))}</div>')
            continue

        # Horizontal rule
        if HR_RE.match(stripped):
            blocks.append('<hr class="doc-rule">')
            i += 1
            continue

        # Heading
        h_match = HEADING_RE.match(line)
        if h_match:
            heading_counter += 1
            level = len(h_match.group(1))
            raw_title = h_match.group(2)
            hid = _slugify(raw_title, heading_counter)
            blocks.append(f'<h{level} id="{hid}">{_render_inline(raw_title)}</h{level}>')
            i += 1
            continue

        # Markdown Table
        if "|" in line and (i + 1) < n and _is_table_separator(lines[i + 1]):
            headers = _split_table_row(line)
            aligns = _parse_alignments(lines[i + 1])
            i += 2
            body_rows: list[list[str]] = []
            while i < n and "|" in lines[i] and lines[i].strip():
                body_rows.append(_split_table_row(lines[i]))
                i += 1
            th_cells = []
            for c_idx, h_cell in enumerate(headers):
                al = aligns[c_idx] if c_idx < len(aligns) else "left"
                attr = (
                    ' class="num"'
                    if al == "right"
                    else (' style="text-align:center;"' if al == "center" else "")
                )
                th_cells.append(f"<th{attr}>{_render_inline(h_cell)}</th>")
            tr_html: list[str] = []
            for r_cells in body_rows:
                tds = []
                for c_idx, cell_val in enumerate(r_cells):
                    al = aligns[c_idx] if c_idx < len(aligns) else "left"
                    attr = (
                        ' class="num"'
                        if al == "right"
                        else (' style="text-align:center;"' if al == "center" else "")
                    )
                    tds.append(f"<td{attr}>{_render_inline(cell_val)}</td>")
                tr_html.append("<tr>" + "".join(tds) + "</tr>")
            blocks.append(
                '<div class="table-wrap"><table class="data-table">'
                f"<thead><tr>{''.join(th_cells)}</tr></thead>"
                f"<tbody>{''.join(tr_html)}</tbody>"
                "</table></div>"
            )
            continue

        # Blockquote
        if stripped.startswith(">"):
            q_lines: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                q_lines.append(lines[i].strip()[1:].lstrip())
                i += 1
            q_body = _render_inline(" ".join(q_lines))
            blocks.append(f'<blockquote class="doc-quote"><p>{q_body}</p></blockquote>')
            continue

        # Unordered or Ordered List (with 2-level nested sublists)
        is_ul = TOP_UL_RE.match(line) is not None
        is_ol = TOP_OL_RE.match(line) is not None
        if is_ul or is_ol:
            list_tag = "ul" if is_ul else "ol"
            top_re = TOP_UL_RE if is_ul else TOP_OL_RE
            items_html: list[str] = []
            while i < n:
                cur = lines[i]
                if not cur.strip():
                    break
                m_top = top_re.match(cur)
                if not m_top:
                    break
                main_html = _render_inline(m_top.group(1).strip())
                i += 1
                sub_items: list[str] = []
                while i < n:
                    m_sub = SUB_LI_RE.match(lines[i])
                    if not m_sub:
                        break
                    sub_items.append(f"<li>{_render_inline(m_sub.group(1).strip())}</li>")
                    i += 1
                if sub_items:
                    items_html.append(f"<li>{main_html}<ul>{''.join(sub_items)}</ul></li>")
                else:
                    items_html.append(f"<li>{main_html}</li>")
            blocks.append(f"<{list_tag}>{''.join(items_html)}</{list_tag}>")
            continue

        # Paragraph (or standalone image figure)
        para_lines: list[str] = []
        while i < n:
            cur = lines[i]
            s_cur = cur.strip()
            if (
                not s_cur
                or s_cur.startswith(("\x00FENCE_", "$$", ">"))
                or HR_RE.match(s_cur)
                or HEADING_RE.match(cur)
                or TOP_UL_RE.match(cur)
                or TOP_OL_RE.match(cur)
                or ("|" in cur and (i + 1) < n and _is_table_separator(lines[i + 1]))
            ):
                break
            para_lines.append(s_cur)
            i += 1
        rendered_para = _render_inline(" ".join(para_lines))
        if rendered_para.startswith('<figure class="doc-figure">') and rendered_para.endswith(
            "</figure>"
        ):
            blocks.append(rendered_para)
        else:
            blocks.append(f"<p>{rendered_para}</p>")

    joined = "\n".join(blocks)
    return _restore_tokens(joined, "FENCE", code_blocks)


def _wrap_companion_html(
    *,
    active_filename: str,
    page_title: str,
    source_badge: str,
    body_html: str,
    extra_scripts: str = "",
) -> str:
    tabs_html = []
    for fname, label, _ in COMPANION_PAGES:
        cls = ' class="active"' if fname == active_filename else ""
        tabs_html.append(f'<a href="./{fname}"{cls}>{html.escape(label)}</a>')

    gfont_href = (
        "https://fonts.googleapis.com/css2?"
        "family=Inter:wght@400;500;600&"
        "family=JetBrains+Mono:wght@400;500;600&"
        "family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n'
        "<head>\n"
        '  <meta charset="UTF-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"  <title>{html.escape(page_title)} — Harness Reliability Lab</title>\n"
        '  <link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        f'  <link href="{gfont_href}" rel="stylesheet" media="print" onload="this.media=\'all\'">\n'
        f'  <noscript><link href="{gfont_href}" rel="stylesheet"></noscript>\n'
        '  <link rel="stylesheet" href="./styles.css">\n'
        "</head>\n"
        "<body>\n"
        '  <nav class="companion-nav" aria-label="配套文档导航">\n'
        '    <div class="companion-nav-inner">\n'
        '      <a class="companion-return" href="./index.html">'
        "← 返回五幕交互专著</a>\n"
        f'      <div class="companion-tabs">{"".join(tabs_html)}</div>\n'
        "    </div>\n"
        "  </nav>\n"
        '  <main class="doc-shell">\n'
        f'    <div class="doc-meta-bar">{html.escape(source_badge)}</div>\n'
        f'    <article class="doc-article">\n{body_html}\n    </article>\n'
        '    <footer class="monograph-footer" '
        'style="margin-top:48px;border-top:1px solid var(--line-subtle);">\n'
        '      <a href="./index.html">← 返回五幕交互专著</a> · '
        "零外部 API 离线核验："
        "<code>uv run --frozen --no-env-file python -m evals.verify_all --ci</code>\n"
        "    </footer>\n"
        "  </main>\n"
        f"{extra_scripts}"
        "</body>\n"
        "</html>\n"
    )


def compile_ledger_inspector_html(ledger: dict[str, Any]) -> str:
    """Compile site/ledger.html structured inspector backed by ./ledger-data.js."""
    anchor = ledger["freeze_anchor"]
    integrity = ledger["ledger_integrity"]
    rv2 = ledger["replication_v2"]
    receipts = ledger["artifact_tree_receipts"]

    receipt_rows = []
    for key, item in receipts.items():
        receipt_rows.append(
            "<tr>"
            f'<td class="mono">{html.escape(key)}</td>'
            f'<td class="mono">{html.escape(item["root"])}</td>'
            f'<td class="num">{item["file_count"]}</td>'
            f'<td class="num">{item["total_bytes"]:,}</td>'
            f'<td class="mono">{html.escape(item["tree_sha256"][:24])}..</td>'
            "</tr>"
        )

    f_counts = f"{anchor['frozen_code_file_count']} + {anchor['frozen_tasks_and_specs_count']}"
    body = (
        '<h1 id="ledger-top">公开脱敏证据账本检视器 (Evidence Ledger)</h1>\n'
        "<p>本页直接加载同目录下的确定性数据脚本 <code>./ledger-data.js</code>（与版本库跟踪的 "
        "<code>evals/evidence_ledger.json</code> 逐字段严格同步，"
        "总体积严格小于 <code>150 KB</code>），"
        "展示冻结基线锚点、11 棵原始实验目录的 SHA-256 树哈希回执，"
        "以及可按模块展开检视的格式化脱敏 JSON 载荷。</p>\n"
        '<div class="summary-strip" style="margin:20px 0 28px;">'
        '<div class="summary-cell"><div class="summary-label">账本模式版本</div>'
        f'<div class="summary-value">{html.escape(ledger["schema"])}</div>'
        f'<div class="summary-sub">Grader: {html.escape(anchor["grader_version"])}</div></div>'
        '<div class="summary-cell"><div class="summary-label">冻结提交锚点</div>'
        f'<div class="summary-value">{html.escape(anchor["freeze_commit"][:12])}</div>'
        f'<div class="summary-sub">Tag: {html.escape(anchor["freeze_tag"])}</div></div>'
        '<div class="summary-cell"><div class="summary-label">冻结代码 / 题集摘要</div>'
        f'<div class="summary-value">{f_counts} 项</div>'
        '<div class="summary-sub">0 字节变更强校验</div></div>'
        '<div class="summary-cell"><div class="summary-label">主基准复核</div>'
        f'<div class="summary-value">{rv2["executed_trials"]}/{rv2["planned_trials"]} Runs</div>'
        '<div class="summary-sub">0 越权 · 0 重复写</div></div>'
        '<div class="summary-cell"><div class="summary-label">自校验载荷哈希</div>'
        f'<div class="summary-value">{html.escape(integrity["payload_sha256"][:12])}..</div>'
        '<div class="summary-sub">16 项脱敏红线全绿</div></div>'
        "</div>\n"
        '<h2 id="sec-receipts">1. 原始实验目录 SHA-256 树哈希回执（11 Trees）</h2>\n'
        '<div class="table-wrap"><table class="data-table">'
        '<thead><tr><th>账本键名</th><th>原始目录标识</th><th class="num">文件数</th>'
        '<th class="num">总字节数</th><th>SHA-256 树摘要前缀</th></tr></thead>'
        f"<tbody>{''.join(receipt_rows)}</tbody></table></div>\n"
        '<h2 id="sec-json-explorer">2. 分模块可折叠脱敏 JSON 载荷检视</h2>\n'
        '<div id="ledger-collapsible-mount"></div>'
    )

    script = (
        '  <script src="./ledger-data.js"></script>\n'
        "  <script>\n"
        "  (function() {\n"
        "    var mount = document.getElementById('ledger-collapsible-mount');\n"
        "    var data = window.HARNESS_LEDGER;\n"
        "    if (!mount || !data) return;\n"
        "    var sections = [\n"
        "      ['ledger_integrity', '账本数字签名与容量边界 (ledger_integrity)'],\n"
        "      ['freeze_anchor', '冻结代码与题集 SHA-256 字典 (freeze_anchor)'],\n"
        "      ['artifact_tree_receipts', '11 项原始实验树完整哈希 (artifact_tree_receipts)'],\n"
        "      ['replication_v2', '324 次配对主基准聚合与协议对账 (replication_v2)'],\n"
        "      ['diagnostics_and_probes', '四阶段时钟、缓存量化与探针 (diagnostics_and_probes)'],\n"
        "      ['nextgen_modules', '控制面扩展实证汇总 M1A–M6 (nextgen_modules)'],\n"
        "      ['post_training', '后训练 SFT 与偏好对导出统计 (post_training)'],\n"
        "      ['representative_stepper_slices', "
        "'交互台脱敏轨迹切片 (representative_stepper_slices)']\n"
        "    ];\n"
        "    var html = '';\n"
        "    for (var i = 0; i < sections.length; i++) {\n"
        "      var key = sections[i][0];\n"
        "      var title = sections[i][1];\n"
        "      var openAttr = i === 0 ? ' open' : '';\n"
        "      var jsonTxt = JSON.stringify(data[key], null, 2)\n"
        "        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');\n"
        "      html += '<details class=\"ledger-details\"' + openAttr + '>' +\n"
        "        '<summary>' + title + '</summary><pre>' + jsonTxt + '</pre></details>';\n"
        "    }\n"
        "    mount.innerHTML = html;\n"
        "  })();\n"
        "  </script>\n"
    )

    return _wrap_companion_html(
        active_filename="ledger.html",
        page_title="公开脱敏证据账本 (Evidence Ledger)",
        source_badge="COMPANION INSPECTOR · COMPILED FROM evals/evidence_ledger.json",
        body_html=body,
        extra_scripts=script,
    )


def build_expected_companion_pages(project: Path, ledger: dict[str, Any]) -> dict[str, str]:
    """Build all 5 deterministic companion HTML documents in memory."""
    pages: dict[str, str] = {}
    for out_name, label, src_rel in COMPANION_PAGES:
        if src_rel is None:
            pages[out_name] = compile_ledger_inspector_html(ledger)
        else:
            src_path = project / src_rel
            enforce(src_path.is_file(), f"Missing companion Markdown source: {src_rel}")
            md_raw = src_path.read_text(encoding="utf-8")
            body_html = compile_markdown_body(md_raw)
            pages[out_name] = _wrap_companion_html(
                active_filename=out_name,
                page_title=label,
                source_badge=f"STATIC MONOGRAPH COMPANION · COMPILED FROM {src_rel}",
                body_html=body_html,
            )
    return pages


def write_companion_pages(site_dir: Path, pages: dict[str, str]) -> None:
    """Atomically write all 5 compiled companion HTML files into site/."""
    site_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in sorted(pages.items()):
        dest = site_dir / fname
        tmp = dest.with_suffix(".html.tmp")
        tmp.write_text(content, encoding="utf-8", newline="\n")
        tmp.replace(dest)


def verify_companion_pages_and_no_raw_md(project: Path, ledger: dict[str, Any]) -> dict[str, Any]:
    """Verify byte-for-byte companion HTML sync and zero unparsed Markdown/raw .md links."""
    site_dir = project / "site"
    expected = build_expected_companion_pages(project, ledger)
    for fname, exp_html in sorted(expected.items()):
        fpath = site_dir / fname
        enforce(fpath.is_file(), f"Missing compiled companion HTML page: site/{fname}")
        actual_bytes = fpath.read_bytes()
        expected_bytes = exp_html.encode("utf-8")
        enforce(
            actual_bytes == expected_bytes,
            f"site/{fname} is out of sync with its Markdown/JSON source "
            "(re-run --export-ledger)",
        )

    html_files = ["index.html", *sorted(expected.keys())]
    for fname in html_files:
        raw_html = (site_dir / fname).read_text(encoding="utf-8")
        enforce(
            RAW_DOC_HREF_RE.search(raw_html) is None,
            f"site/{fname} contains raw .md/.json href jump instead of compiled .html route",
        )
        outside_code = STRIP_SAFE_TAGS_RE.sub("", raw_html)
        enforce(
            RESIDUAL_MD_BOLD_RE.search(outside_code) is None,
            f"site/{fname} contains unparsed '**bold**' Markdown outside <pre>/<code>",
        )
        enforce(
            RESIDUAL_MD_HEADING_RE.search(outside_code) is None,
            f"site/{fname} contains unparsed '## ' Markdown heading outside <pre>/<code>",
        )
        enforce(
            RESIDUAL_MD_LINK_RE.search(outside_code) is None,
            f"site/{fname} contains unparsed '[...](*.md)' syntax outside <pre>/<code>",
        )

    return {"companion_pages_verified": len(expected), "html_files_checked": len(html_files)}
