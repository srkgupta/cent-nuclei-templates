#!/usr/bin/env python3
"""
Deduplicates cent-nuclei-templates against core nuclei-templates.

Phases:
  1. Remove any template whose `id:` field matches a core template ID.
  2. Remove stub templates with the empty-MD5 hash suffix (d41d8cd9...).
  3. Remove internal content duplicates (same file hash, keep first alphabetically).

Run from anywhere:
  python3 /home/chitti/pentest/cent-nuclei-templates/dedup.py

Dry-run (no deletions):
  python3 /home/chitti/pentest/cent-nuclei-templates/dedup.py --dry-run
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
CUSTOM_DIR = SCRIPT_DIR / "templates"
CORE_DIR = Path("/home/chitti/nuclei-templates")
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def get_template_id(filepath: Path) -> str | None:
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("id:"):
                    return line[3:].strip()
                # IDs always appear near the top; stop after 10 lines
                if f.tell() > 512:
                    break
    except OSError:
        pass
    return None


def file_md5(filepath: Path) -> str:
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def remove(path: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"  [dry] would remove: {path.name}")
    else:
        path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print what would be deleted without deleting")
    args = parser.parse_args()
    dry_run = args.dry_run

    if not CUSTOM_DIR.is_dir():
        sys.exit(f"ERROR: templates dir not found: {CUSTOM_DIR}")
    if not CORE_DIR.is_dir():
        sys.exit(f"ERROR: core nuclei-templates not found: {CORE_DIR}")

    if dry_run:
        print("DRY RUN mode - nothing will be deleted\n")

    # ── Phase 1: Remove templates whose id: matches a core template ──────────
    print("[Phase 1] Building core template ID index...")
    core_ids: set[str] = set()
    for root, _, files in os.walk(CORE_DIR):
        for fname in files:
            if fname.endswith(".yaml"):
                tid = get_template_id(Path(root) / fname)
                if tid:
                    core_ids.add(tid)
    print(f"          Core IDs indexed: {len(core_ids)}")

    print("[Phase 1] Scanning custom templates for IDs already in core...")
    p1 = 0
    all_custom = sorted(CUSTOM_DIR.glob("*.yaml"))
    for fpath in all_custom:
        tid = get_template_id(fpath)
        if tid and tid in core_ids:
            remove(fpath, dry_run)
            p1 += 1
    print(f"          Removed: {p1}\n")

    # ── Phase 2: Remove stub templates with empty-MD5 hash suffix ────────────
    print("[Phase 2] Removing empty-MD5 stub templates...")
    p2 = 0
    for fpath in CUSTOM_DIR.glob(f"*{EMPTY_MD5}.yaml"):
        remove(fpath, dry_run)
        p2 += 1
    print(f"          Removed: {p2}\n")

    # ── Phase 3: Remove internal content duplicates ───────────────────────────
    print("[Phase 3] Hashing remaining templates and removing content duplicates...")
    p3 = 0
    seen: dict[str, Path] = {}
    for fpath in sorted(CUSTOM_DIR.glob("*.yaml")):
        h = file_md5(fpath)
        if h in seen:
            remove(fpath, dry_run)
            p3 += 1
        else:
            seen[h] = fpath
    print(f"          Removed: {p3}\n")

    remaining = len(list(CUSTOM_DIR.glob("*.yaml")))
    total_removed = p1 + p2 + p3
    print("=" * 45)
    print(f"  Phase 1 (core ID duplicates):   {p1:>6}")
    print(f"  Phase 2 (empty-MD5 stubs):       {p2:>6}")
    print(f"  Phase 3 (internal content dups): {p3:>6}")
    print(f"  {'(dry run - nothing deleted)' if dry_run else 'Total removed':30} {total_removed:>6}")
    print(f"  Remaining templates:             {remaining:>6}")
    print("=" * 45)


if __name__ == "__main__":
    main()
