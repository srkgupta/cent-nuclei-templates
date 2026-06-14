# cent-nuclei-templates
Cent Nuclei Templates generated through the [cent tool](https://github.com/xm1k3/cent)

This repo contains **10,997 quality-filtered nuclei templates** sourced from the cent tool and curated against the [core nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).

### What was done to clean this up

The collection was built in two phases:

**Phase 1: Clean up the original ~23,000 custom templates (culled to ~12,000)**
- **Deduplication** - templates whose `id:` field matched core nuclei-templates removed; empty-MD5 stub templates (auto-generated placeholders) removed
- **No-signal culls** - templates with no matchers block, status-200-only matchers, and `compare_versions('>0')` always-true version checks removed
- **Syntax modernisation** - 1,400 templates updated from deprecated nuclei v2 `requests:` key to `http:`
- **Generic matcher culls** - templates whose sole word matcher was a common English word (`http`, `dns`, `backup`, `player`, `stream`, `evil`, `team`, `canvas`, `erp`, `bridge`) removed

**Phase 2: Community sync via cent (+9,630 templates)**
- Pulled templates from 130+ community repos using the `cent` tool
- Applied all quality filters from Phase 1 during import
- Excluded topscoder author (148k WordPress-only Wordfence CVE templates, too narrow in scope)
- Excluded all templates tagged `wordpress` (nuclei is not the right tool for bulk WP scanning; these generate excessive noise)

### Template Stats

| Severity | Count |
|----------|------:|
| Critical | 1,908 |
| High     | 2,863 |
| Medium   | 2,192 |
| Low      |   708 |
| Info     | 3,251 |
| Unknown  |    75 |
| **Total**| **10,997** |

### What is excluded

The following categories are explicitly excluded from this collection and from future syncs:

| Exclusion | Reason |
|-----------|--------|
| `author: topscoder` | ~148k WordPress-only Wordfence CVE templates; too narrow in scope |
| `tags: wordpress` | WordPress plugin/theme templates generate excessive noise; nuclei is not the right tool for bulk WP scanning |
| Empty-MD5 stubs | Auto-generated placeholder files with no real content |
| Status-200-only matchers | No body/header check; high false-positive rate |
| `compare_versions('>0')` | Always-true version check; matches everything |
| Generic sole-word matchers | Single common word (`http`, `dns`, `backup`, etc.) as the only signal |

### Maintenance

The `cleanup/` folder contains scripts for ongoing maintenance:

- `cleanup/dedup.py` - re-deduplicates against core nuclei-templates
- `cleanup/quality_score.py` - scores all templates 0-100 and outputs `quality_scores.csv` + `quality_report.md`
- `cleanup/sync.py` - pulls new community templates via cent, applies all quality filters, and adds passing templates

```
python3 cleanup/sync.py --dry-run    # preview what would be added
python3 cleanup/sync.py              # run full sync + quality report
python3 cleanup/dedup.py --dry-run   # preview dedup removals
python3 cleanup/dedup.py             # run dedup
python3 cleanup/quality_score.py     # regenerate quality report only
```

### How to run these templates

- Clone the repository:
```
git clone https://github.com/srkgupta/cent-nuclei-templates.git
```

- Run the nuclei templates:
```
nuclei -u https://example.com -t ./cent-nuclei-templates/templates -tags cve
nuclei -l urls.txt -t ./cent-nuclei-templates/templates -tags cve
```
