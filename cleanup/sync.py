#!/usr/bin/env python3
"""
Sync new community templates via cent, apply all quality filters,
and bring only net-new passing templates into our collection.

Pipeline:
  1. Run `cent update` to pull all community repos into a staging dir
  2. Build ID sets for our collection and core nuclei-templates
  3. For each staging template not already known: run quality checks
  4. Copy passing templates into templates/, skip failures with reason
  5. Regenerate quality_scores.csv and quality_report.md

Prerequisites:
  cent installed:   go install github.com/xm1k3/cent@latest
  cent configured:  cent init   (creates ~/.cent.yaml, run once)
  core templates:   /home/chitti/nuclei-templates must exist

Usage:
  python3 cleanup/sync.py
  python3 cleanup/sync.py --dry-run
  python3 cleanup/sync.py --staging /custom/staging/path
"""

import argparse
import hashlib
import shutil
import subprocess
import sys
import yaml
import re
from collections import Counter
from pathlib import Path

REPO_ROOT   = Path(__file__).parent.parent.resolve()
TEMPLATES   = REPO_ROOT / "templates"
CORE_DIR    = Path("/home/chitti/nuclei-templates")
CENT_BIN    = Path("/home/chitti/go/bin/cent")
EMPTY_MD5   = "d41d8cd98f00b204e9800998ecf8427e"

# Authors whose templates are excluded from sync (too narrow/noisy focus).
# topscoder: ~148k WordPress-only Wordfence CVE templates, too narrow in scope.
EXCLUDED_AUTHORS = {"topscoder"}

# Tags that cause a template to be excluded from sync.
# wordpress: too plugin/theme-specific; nuclei is not the right tool for
# bulk WP scanning and these templates generate excessive noise.
EXCLUDED_TAGS = {"wordpress"}

# Regex matching CJK characters (Chinese/Japanese/Korean).
# Templates with CJK in the filename or content are excluded: they target
# region-specific software and are unmaintainable without language context.
CJK_RE = re.compile(r'[一-鿿　-〿＀-￯㐀-䶿]')

# Hardcoded researcher-controlled OOB callback domains.
# Templates must use nuclei's {{interactsh-url}} placeholder instead.
# Pattern is anchored so "notburpcollaborator.net" (SSRF negative-test) is not flagged.
_OOB_RE = re.compile(
    r'(?<![a-z])'  # not preceded by a letter — excludes "notburpcollaborator.net"
    r'(?:'
    r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.dnslog\.cn'
    r'|burpcollaborator\.net'
    r'|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.oast\.(fun|me|site|online|pro)'
    r'|webhook\.site/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    r')',
    re.IGNORECASE,
)

# Long hex runs that may be binary payloads with embedded OOB URLs.
_HEX_PAYLOAD_RE = re.compile(r'[0-9a-fA-F]{80,}')

# Words that appear routinely in any web/API response and provide no discriminating
# signal when used as the sole content check in a word matcher.
# Applied in two ways:
#   1. Single-word check (original): one word from this set -> reject
#   2. All-generic check (new): ALL words in a word matcher from this set + no
#      regex/dsl/header matcher providing a tighter signal -> reject
# Keep in sync with GENERIC_BODY_WORDS in quality_score.py.
GENERIC_BODY_WORDS = {
    # Common JSON API field names - appear in virtually any API response
    "code", "count", "data", "result", "results", "value", "values",
    "name", "names", "type", "types", "id", "ids", "key", "keys",
    "list", "items", "item", "total", "page", "size", "limit", "offset",
    "status", "message", "msg", "error", "errors", "success", "ok",
    "response", "info", "detail", "details", "content", "body", "payload",
    "text", "title", "url", "path", "link", "href", "src",
    "time", "date", "created", "updated",
    "user", "users", "role", "roles", "group", "groups",
    # Common HTML/DOM words
    "html", "head", "script", "style", "meta", "form", "input",
    "class", "div", "span", "table",
    # Common system/server words
    "root", "home", "server", "host", "system", "config", "version",
    "api", "true", "false", "null", "none",
    # Original narrow set kept for backward compat
    "http", "dns", "backup", "player", "stream", "evil",
    "team", "canvas", "erp", "bridge",
}
# Alias for the original single-word path (kept for clarity at call site)
GENERIC_WORDS = GENERIC_BODY_WORDS


def get_author(fpath: Path) -> str:
    try:
        with open(fpath, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if line.strip().startswith("author:"):
                    return line.split(":", 1)[1].strip()
                if i > 30:
                    break
    except OSError:
        pass
    return ""


def get_tags(fpath: Path) -> set[str]:
    try:
        with open(fpath, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if line.strip().startswith("tags:"):
                    raw = line.split(":", 1)[1].strip()
                    return {t.strip().lower() for t in raw.split(",") if t.strip()}
                if i > 30:
                    break
    except OSError:
        pass
    return set()


def get_id(fpath: Path) -> str | None:
    try:
        with open(fpath, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if line.startswith("id:"):
                    return line[3:].strip()
                if i > 20:
                    break
    except OSError:
        pass
    return None


def file_md5(fpath: Path) -> str:
    h = hashlib.md5()
    with open(fpath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _oob_check(content: str) -> str | None:
    """Return a reason string if hardcoded OOB callback domains are found, else None.

    Scans non-comment lines for known researcher-controlled OOB domains, then
    decodes any long hex strings and repeats the check inside them (catches
    ysoserial URLDNS payloads and similar binary blobs with embedded URLs).
    """
    import binascii

    for line in content.splitlines():
        if line.lstrip().startswith('#'):
            continue
        if _OOB_RE.search(line):
            return "hardcoded_oob_domain"

    for hex_match in _HEX_PAYLOAD_RE.finditer(content):
        try:
            decoded = binascii.unhexlify(hex_match.group()).decode('latin-1')
            if _OOB_RE.search(decoded):
                return "hardcoded_oob_domain_in_hex"
        except Exception:
            pass

    return None


def quality_check(fpath: Path) -> tuple[bool, str]:
    """Return (passes, reason). Mirrors all removal decisions made to date."""
    try:
        raw = fpath.read_text(errors="ignore")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return False, "invalid_yaml"
    except Exception:
        return False, "parse_error"

    oob_reason = _oob_check(raw)
    if oob_reason:
        return False, oob_reason

    http = data.get("http") or data.get("requests") or []
    if isinstance(http, dict):
        http = [http]

    # Must have at least one HTTP/network block
    if not http and not data.get("dns") and not data.get("network") and not data.get("file"):
        return False, "no_http_block"

    for req in (http if isinstance(http, list) else [http]):
        matchers = req.get("matchers") or []

        # No matchers
        if not matchers:
            return False, "no_matchers"

        matchers = [m for m in matchers if isinstance(m, dict)]
        if not matchers:
            return False, "no_matchers"
        types = {m.get("type", "") for m in matchers}

        # Status-only
        if types == {"status"}:
            return False, "status_only_matchers"

        # Always-true version check
        for dm in (m for m in matchers if m.get("type") == "dsl"):
            for expr in (dm.get("dsl") or []):
                if isinstance(expr, str) and ("'>0'" in expr or '">0"' in expr):
                    return False, "always_true_version_check"

        # Generic word matchers: reject when no word matcher provides a real signal.
        # Only applies to BODY word matchers (part=body or unset); non-body parts
        # (interactsh_protocol, header, cookie) have different semantics and are
        # counted as strong signals that exempt the template from this check.
        word_matchers = [m for m in matchers if m.get("type") == "word"]
        body_word_matchers = [
            m for m in word_matchers
            if (m.get("part") or "body") == "body"
        ]
        has_strong_matcher = any(
            m.get("type") in ("regex", "dsl") or
            (m.get("type") == "word" and (m.get("part") or "body") != "body")
            for m in matchers
        )
        if body_word_matchers and not has_strong_matcher:
            for wm in body_word_matchers:
                words = [str(w) for w in (wm.get("words") or [])]
                # Case 1: single generic word
                if len(words) == 1 and words[0].lower() in GENERIC_BODY_WORDS:
                    return False, f"generic_word:{words[0].lower()}"
            # Case 2: every word across every body word matcher is generic
            all_words = [
                str(w).lower()
                for wm in body_word_matchers
                for w in (wm.get("words") or [])
            ]
            if all_words and all(w in GENERIC_BODY_WORDS for w in all_words):
                sample = ",".join(all_words[:4])
                return False, f"all_generic_words:{sample}"

    return True, "ok"


def build_id_set(directory: Path) -> set[str]:
    ids: set[str] = set()
    for fpath in directory.rglob("*.yaml"):
        tid = get_id(fpath)
        if tid:
            ids.add(tid)
    return ids


def run_cent(staging: Path) -> bool:
    if not CENT_BIN.exists():
        print(f"ERROR: cent not found at {CENT_BIN}")
        print("Install with: go install github.com/xm1k3/cent@latest")
        return False
    staging.mkdir(parents=True, exist_ok=True)

    # Use `cent update` if staging already has templates (subsequent syncs),
    # otherwise use the base `cent` command for the initial clone.
    existing = list(staging.rglob("*.yaml"))
    if existing:
        cmd = [str(CENT_BIN), "update", "-p", str(staging), "-d", "-f",
               "-t", "20", "-T", "30"]
        label = "cent update (refresh)"
    else:
        cmd = [str(CENT_BIN), "-p", str(staging), "-C",
               "-t", "20", "-T", "30"]
        label = "cent (initial clone)"

    print(f"[sync] Running: {label} -> {staging}")
    print("[sync] This clones 130+ repos — may take 10-30 minutes ...")
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be added without copying files")
    parser.add_argument("--staging", type=Path, default=Path("/tmp/cent-sync-staging"),
                        help="Staging dir for cent output (default: /tmp/cent-sync-staging)")
    parser.add_argument("--skip-cent", action="store_true",
                        help="Skip cent update step (use existing staging dir)")
    args = parser.parse_args()

    if args.dry_run:
        print("DRY RUN — no files will be copied\n")

    # Step 1: Run cent update
    if not args.skip_cent:
        if not run_cent(args.staging):
            print("WARNING: cent update exited non-zero, continuing with whatever was fetched")
    else:
        print(f"[sync] Skipping cent update, using existing staging: {args.staging}")

    staging_yamls = list(args.staging.rglob("*.yaml"))
    print(f"[sync] Staging templates found: {len(staging_yamls)}")

    # Step 2: Build known ID sets
    print("[sync] Indexing our collection ...")
    our_ids = build_id_set(TEMPLATES)
    our_hashes = {file_md5(f) for f in TEMPLATES.glob("*.yaml")}
    print(f"       Our collection IDs: {len(our_ids)}")

    print("[sync] Indexing core nuclei-templates ...")
    core_ids = build_id_set(CORE_DIR) if CORE_DIR.exists() else set()
    print(f"       Core template IDs:  {len(core_ids)}")

    known_ids = our_ids | core_ids

    # Step 3 & 4: Filter and copy
    stats = Counter()
    tag_counts: Counter = Counter()
    added: list[str] = []
    skipped: list[tuple[str, str]] = []

    for fpath in sorted(staging_yamls):
        stats["total"] += 1
        try:
            # Empty-MD5 stub filter
            if EMPTY_MD5 in fpath.name:
                stats["skip_empty_md5_stub"] += 1
                continue

            # Author exclusion
            author = get_author(fpath)
            if any(ex in author for ex in EXCLUDED_AUTHORS):
                stats["skip_excluded_author"] += 1
                continue

            # CJK filename or content exclusion
            if CJK_RE.search(fpath.name) or CJK_RE.search(fpath.read_text(errors="ignore")):
                stats["skip_cjk"] += 1
                continue

            # Tag exclusion (e.g. wordpress)
            tags = get_tags(fpath)
            if tags & EXCLUDED_TAGS:
                stats["skip_excluded_tag"] += 1
                continue

            tid = get_id(fpath)
            if not tid:
                stats["skip_no_id"] += 1
                continue

            if tid in known_ids:
                stats["skip_duplicate_id"] += 1
                continue

            h = file_md5(fpath)
            if h in our_hashes:
                stats["skip_duplicate_content"] += 1
                continue

            passes, reason = quality_check(fpath)
            if not passes:
                stats[f"skip_{reason}"] += 1
                continue

            # Fix deprecated syntax inline before copying
            content = fpath.read_text(errors="ignore")
            content = re.sub(r'^requests:', 'http:', content, flags=re.MULTILINE)

            dest = TEMPLATES / fpath.name
            if dest.exists():
                dest = TEMPLATES / f"{fpath.stem}_new{fpath.suffix}"

            if not args.dry_run:
                dest.write_text(content)

            # Always track seen IDs and hashes so staging duplicates
            # don't inflate the count in dry-run mode either
            our_hashes.add(h)
            known_ids.add(tid)

            # Count tags for the summary breakdown
            try:
                data = yaml.safe_load(fpath.read_text(errors="ignore"))
                tags_str = str((data.get("info") or {}).get("tags") or "")
                for tag in tags_str.split(","):
                    tag = tag.strip()
                    if tag:
                        tag_counts[tag] += 1
            except Exception:
                pass

            added.append(fpath.name)
            stats["added"] += 1

        except Exception:
            stats["skip_error"] += 1

    # Step 5: Regenerate quality report
    if not args.dry_run and stats["added"] > 0:
        print("\n[sync] Regenerating quality report ...")
        subprocess.run(
            [sys.executable, str(REPO_ROOT / "cleanup" / "quality_score.py")],
            check=False,
        )

    # Summary
    print()
    quality_skipped = sum(v for k, v in stats.items()
                         if k.startswith('skip_') and k not in
                         ('skip_duplicate_id', 'skip_duplicate_content',
                          'skip_no_id', 'skip_empty_md5_stub',
                          'skip_error', 'skip_excluded_author',
                          'skip_excluded_tag', 'skip_cjk'))
    print("=" * 55)
    print(f"  Staging templates scanned:  {stats['total']:>6,}")
    print(f"  Skipped (known ID):         {stats['skip_duplicate_id']:>6,}")
    print(f"  Skipped (empty-MD5 stubs):  {stats['skip_empty_md5_stub']:>6,}")
    print(f"  Skipped (excluded authors): {stats['skip_excluded_author']:>6,}")
    print(f"  Skipped (CJK content):      {stats['skip_cjk']:>6,}")
    print(f"  Skipped (excluded tags):    {stats['skip_excluded_tag']:>6,}")
    print(f"  Skipped (content dup):      {stats['skip_duplicate_content']:>6,}")
    print(f"  Skipped (no id field):      {stats['skip_no_id']:>6,}")
    print(f"  Skipped (quality filters):  {quality_skipped:>6,}")
    print(f"  Skipped (errors/malformed): {stats['skip_error']:>6,}")
    print(f"  {'[DRY RUN] Would add' if args.dry_run else 'Added to collection'}:{stats['added']:>6,}")
    print("=" * 55)

    if tag_counts:
        print(f"\nTag distribution of {'would-be additions' if args.dry_run else 'added templates'} (top 20):")
        print(f"  {'Tag':<25} {'Count':>6}")
        print(f"  {'-'*25} {'-'*6}")
        for tag, count in tag_counts.most_common(20):
            print(f"  {tag:<25} {count:>6,}")

    if added and args.dry_run:
        print(f"\nSample new templates:")
        for name in added[:10]:
            print(f"  {name}")
        if len(added) > 10:
            print(f"  ... and {len(added)-10} more")


if __name__ == "__main__":
    main()
