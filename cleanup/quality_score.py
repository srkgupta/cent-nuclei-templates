#!/usr/bin/env python3
"""
Quality scoring for cent-nuclei-templates.

Scores each template 0-100 (lower = worse / higher FP risk).
Critical severity is processed first within each tier.

Outputs (written to repo root by default):
  quality_scores.csv  - per-template scores and flags
  quality_report.md   - human-readable summary by tier and severity

Usage:
  python3 cleanup/quality_score.py
  python3 cleanup/quality_score.py --output-dir /some/path
"""

import argparse
import csv
import sys
import yaml
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.resolve()
TEMPLATES_DIR = REPO_ROOT / "templates"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def severity_rank(s: str) -> int:
    try:
        return SEVERITY_ORDER.index(s.lower().strip())
    except ValueError:
        return len(SEVERITY_ORDER)


def score_template(data: dict) -> tuple[int, list[str]]:
    """
    Return (score 0-100, [flags]).
    Base score is 50. Penalties push it down; bonuses push it up.
    """
    score = 50
    flags: list[str] = []

    info = data.get("info") or {}
    has_http_key = "http" in data
    http_blocks = data.get("http") or data.get("requests") or []
    if isinstance(http_blocks, dict):
        http_blocks = [http_blocks]

    # Deprecated requests: syntax
    if not has_http_key and "requests" in data:
        score -= 5
        flags.append("deprecated_requests_key")
    elif has_http_key:
        score += 5

    # CVE tag without cve-id field
    tags = str(info.get("tags") or "").lower()
    cve_id = (info.get("classification") or {}).get("cve-id")
    if "cve" in tags:
        if cve_id:
            score += 10
        else:
            score -= 5
            flags.append("cve_tagged_missing_cve_id")

    if not http_blocks:
        flags.append("no_http_block")
        return max(0, min(100, score)), _dedup(flags)

    for req in http_blocks:
        matchers = req.get("matchers") or []
        condition = (req.get("matchers-condition") or "and").lower().strip()
        paths = req.get("path") or []
        method = (req.get("method") or "GET").upper()

        # No matchers at all
        if not matchers:
            score -= 35
            flags.append("no_matchers")
            continue

        types = [m.get("type", "") for m in matchers]

        # Status-only: no body/header content validation
        if set(types) == {"status"}:
            score -= 30
            flags.append("status_only_matchers")
            continue

        # OR condition: any single weak signal fires the template
        if condition == "or":
            score -= 20
            flags.append("or_condition_matchers")
        elif condition == "and" and len(matchers) >= 3:
            score += 20
            flags.append("strong_and_matchers")

        # always-true version check: compare_versions(version, '>0')
        for dm in (m for m in matchers if m.get("type") == "dsl"):
            for expr in (dm.get("dsl") or []):
                if "'>0'" in expr or '">0"' in expr:
                    score -= 40
                    flags.append("always_true_version_check")

        # Word matcher quality
        word_matchers = [m for m in matchers if m.get("type") == "word"]
        if word_matchers:
            all_body = all((m.get("part") or "body") == "body" for m in word_matchers)
            if all_body:
                score += 10
            for wm in word_matchers:
                words = wm.get("words") or []
                if len(words) == 1 and len(words[0]) <= 6:
                    score -= 15
                    flags.append("single_weak_word_matcher")
                    break

        # Regex matchers are a quality signal (tight fingerprint)
        if any(m.get("type") == "regex" for m in matchers):
            score += 15
            flags.append("has_regex_matcher")

        # readme.txt-only paths detect presence, not exploitability
        readme_only = bool(paths) and all("readme.txt" in p for p in paths)
        if readme_only:
            score -= 10
            flags.append("readme_only_path")

        # Active probe: non-GET method or non-readme endpoint
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 25
            flags.append("active_probe_method")
        elif paths and not readme_only:
            score += 10
            flags.append("active_probe_path")

    return max(0, min(100, score)), _dedup(flags)


def _dedup(flags: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for f in flags:
        if f and f not in seen:
            seen.add(f)
            out.append(f)
    return out


def tier_label(score: int) -> str:
    if score <= 20:
        return "1-cull"
    if score <= 45:
        return "2-review"
    if score <= 70:
        return "3-acceptable"
    return "4-good"


TIER_DESCRIPTIONS = {
    "1-cull":       "score 0-20:  status-only / no matchers / always-true version check",
    "2-review":     "score 21-45: weak matchers, OR conditions, readme-only paths",
    "3-acceptable": "score 46-70: standard version-detection pattern",
    "4-good":       "score 71-100: proper matchers, active probes, tight fingerprints",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output-dir", type=Path, default=REPO_ROOT,
        help="Directory for output files (default: repo root)"
    )
    args = parser.parse_args()

    if not TEMPLATES_DIR.is_dir():
        sys.exit(f"ERROR: templates dir not found: {TEMPLATES_DIR}")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning {TEMPLATES_DIR} ...")
    rows: list[dict] = []
    errors = 0

    template_files = sorted(TEMPLATES_DIR.glob("*.yaml"))
    total = len(template_files)

    for i, fpath in enumerate(template_files, 1):
        if i % 2000 == 0:
            print(f"    {i}/{total} ...")
        try:
            data = yaml.safe_load(fpath.read_text(errors="ignore"))
            if not isinstance(data, dict):
                errors += 1
                continue
            info = data.get("info") or {}
            severity = (info.get("severity") or "unknown").lower().strip()
            sc, flags = score_template(data)
            rows.append({
                "file": fpath.name,
                "severity": severity,
                "score": sc,
                "tier": tier_label(sc),
                "flags": "|".join(flags),
            })
        except Exception:
            errors += 1

    # Sort: Critical first, then score ascending (worst quality at top)
    rows.sort(key=lambda r: (severity_rank(r["severity"]), r["score"]))

    # Write CSV
    csv_path = args.output_dir / "quality_scores.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "severity", "score", "tier", "flags"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[*] Written: {csv_path}")

    # Aggregate stats
    tier_counts: Counter = Counter(r["tier"] for r in rows)
    sev_tier: dict[str, Counter] = defaultdict(Counter)
    flag_counts: Counter = Counter()
    tier_samples: dict[str, list] = defaultdict(list)

    for r in rows:
        sev_tier[r["tier"]][r["severity"]] += 1
        for f in r["flags"].split("|"):
            if f:
                flag_counts[f] += 1
        if len(tier_samples[r["tier"]]) < 8:
            tier_samples[r["tier"]].append(r)

    # Write Markdown report
    report_path = args.output_dir / "quality_report.md"
    lines: list[str] = [
        "# Template Quality Report",
        "",
        f"Scanned **{len(rows):,}** templates ({errors} parse errors skipped).",
        "",
        "## Tier Summary",
        "",
        "| Tier | Description | Count |",
        "|------|-------------|------:|",
    ]
    for t in ["1-cull", "2-review", "3-acceptable", "4-good"]:
        lines.append(f"| **{t}** | {TIER_DESCRIPTIONS[t]} | {tier_counts.get(t, 0):,} |")

    lines += [
        "",
        "## Flag Counts",
        "",
        "| Flag | Count | Meaning |",
        "|------|------:|---------|",
    ]
    flag_meanings = {
        "no_matchers":                "Template fires on any successful HTTP response",
        "status_only_matchers":       "No body/header content checked - any 200 fires",
        "always_true_version_check":  "compare_versions('>0') matches every plugin install",
        "or_condition_matchers":      "Any single weak matcher is enough to fire",
        "single_weak_word_matcher":   "Word matcher with a single string <= 6 chars",
        "readme_only_path":           "Only fetches readme.txt - presence detection, not exploit",
        "cve_tagged_missing_cve_id":  "CVE tag present but no cve-id in classification",
        "deprecated_requests_key":    "Uses v2 'requests:' key instead of 'http:'",
        "has_regex_matcher":          "Uses regex for tighter fingerprinting (good)",
        "strong_and_matchers":        "3+ matchers all required (AND condition) - good",
        "active_probe_method":        "Uses POST/PUT/PATCH - actual exploit attempt",
        "active_probe_path":          "Non-readme.txt endpoint - targeted probe",
    }
    for flag, count in flag_counts.most_common():
        meaning = flag_meanings.get(flag, "")
        lines.append(f"| `{flag}` | {count:,} | {meaning} |")

    lines += ["", "## Breakdown by Tier and Severity", ""]
    for t in ["1-cull", "2-review", "3-acceptable", "4-good"]:
        count = tier_counts.get(t, 0)
        lines += [f"### {t} ({count:,} templates)", ""]
        if count:
            lines += ["| Severity | Count |", "|----------|------:|"]
            for sev in SEVERITY_ORDER:
                c = sev_tier[t].get(sev, 0)
                if c:
                    lines.append(f"| {sev.capitalize()} | {c:,} |")
            lines.append("")
            if tier_samples[t]:
                lines.append("<details><summary>Sample worst templates (lowest score first)</summary>")
                lines.append("")
                lines.append("| File | Severity | Score | Flags |")
                lines.append("|------|----------|------:|-------|")
                for r in tier_samples[t]:
                    lines.append(f"| `{r['file']}` | {r['severity']} | {r['score']} | {r['flags']} |")
                lines += ["", "</details>", ""]

    report_path.write_text("\n".join(lines) + "\n")
    print(f"[*] Written: {report_path}")

    print()
    print("=" * 55)
    for t in ["1-cull", "2-review", "3-acceptable", "4-good"]:
        print(f"  {t:15s}: {tier_counts.get(t, 0):>6,}")
    print(f"  {'Parse errors':15s}: {errors:>6,}")
    print(f"  {'Total':15s}: {len(rows):>6,}")
    print("=" * 55)


if __name__ == "__main__":
    main()
