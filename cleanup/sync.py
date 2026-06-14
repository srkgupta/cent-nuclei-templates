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

# Identical to quality_score.py — keep in sync if scoring changes
GENERIC_WORDS = {
    "http", "dns", "backup", "player", "stream", "evil",
    "team", "canvas", "erp", "bridge",
}


def get_id(fpath: Path) -> str | None:
    try:
        with open(fpath, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("id:"):
                    return line[3:].strip()
                if f.tell() > 512:
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


def quality_check(fpath: Path) -> tuple[bool, str]:
    """Return (passes, reason). Mirrors all removal decisions made to date."""
    try:
        data = yaml.safe_load(fpath.read_text(errors="ignore"))
        if not isinstance(data, dict):
            return False, "invalid_yaml"
    except Exception:
        return False, "parse_error"

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
                if "'>0'" in expr or '">0"' in expr:
                    return False, "always_true_version_check"

        # Generic sole-word matcher
        for wm in (m for m in matchers if m.get("type") == "word"):
            words = wm.get("words") or []
            if len(words) == 1 and words[0].lower() in GENERIC_WORDS:
                return False, f"generic_word:{words[0].lower()}"

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
    added: list[str] = []
    skipped: list[tuple[str, str]] = []

    for fpath in sorted(staging_yamls):
        stats["total"] += 1

        tid = get_id(fpath)
        if not tid:
            stats["skip_no_id"] += 1
            skipped.append((fpath.name, "no_id"))
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
            skipped.append((fpath.name, reason))
            continue

        # Fix deprecated syntax inline before copying
        content = fpath.read_text(errors="ignore")
        content = re.sub(r'^requests:', 'http:', content, flags=re.MULTILINE)

        dest = TEMPLATES / fpath.name
        # Avoid filename collision — append a suffix if needed
        if dest.exists():
            dest = TEMPLATES / f"{fpath.stem}_new{fpath.suffix}"

        if not args.dry_run:
            dest.write_text(content)
            our_hashes.add(h)
            known_ids.add(tid)

        added.append(fpath.name)
        stats["added"] += 1

    # Step 5: Regenerate quality report
    if not args.dry_run and stats["added"] > 0:
        print("\n[sync] Regenerating quality report ...")
        subprocess.run(
            [sys.executable, str(REPO_ROOT / "cleanup" / "quality_score.py")],
            check=False,
        )

    # Summary
    print()
    print("=" * 55)
    print(f"  Staging templates scanned:  {stats['total']:>6,}")
    print(f"  Skipped (known ID):         {stats['skip_duplicate_id']:>6,}")
    print(f"  Skipped (content dup):      {stats['skip_duplicate_content']:>6,}")
    print(f"  Skipped (quality filters):  {sum(v for k,v in stats.items() if k.startswith('skip_') and 'dup' not in k and k != 'skip_no_id'):>6,}")
    print(f"  Skipped (no id field):      {stats['skip_no_id']:>6,}")
    print(f"  {'[DRY RUN] Would add' if args.dry_run else 'Added to collection'}:{stats['added']:>6,}")
    print("=" * 55)

    if added:
        print(f"\nNew templates {'(dry run)' if args.dry_run else 'added'}:")
        for name in added[:20]:
            print(f"  {name}")
        if len(added) > 20:
            print(f"  ... and {len(added)-20} more")

    if skipped and not args.dry_run:
        print(f"\nTop quality filter rejections:")
        reject_counts = Counter(r for _, r in skipped)
        for reason, count in reject_counts.most_common(10):
            print(f"  {reason}: {count}")


if __name__ == "__main__":
    main()
