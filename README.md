# cent-nuclei-templates
Cent Nuclei Templates generated through the [cent tool](https://github.com/xm1k3/cent)

This repo contains **21,772 quality-filtered nuclei templates** sourced from the cent tool and curated against the [core nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).

### What was done to clean this up

Starting from ~23,000 raw templates, the following passes were applied:

- **Deduplication** - templates whose `id:` field matched core nuclei-templates removed; empty-MD5 stub templates (auto-generated placeholders) removed
- **No-signal culls** - templates with no matchers block, status-200-only matchers, and `compare_versions('>0')` always-true version checks removed
- **Syntax modernisation** - 1,400 templates updated from deprecated nuclei v2 `requests:` key to `http:`
- **Generic matcher culls** - templates whose sole word matcher was a common English word (`http`, `dns`, `backup`, `player`, `stream`, `evil`, `team`, `canvas`, `erp`, `bridge`) removed
- **Community sync** - 9,630 net-new templates added from 130+ community repos via `cent`, with all quality filters applied during import; topscoder (WordPress-only Wordfence CVE templates) excluded

### Template Stats

| Severity | Count |
|----------|------:|
| Critical | 2,926 |
| High     | 5,797 |
| Medium   | 8,847 |
| Low      |   821 |
| Info     | 3,291 |
| Unknown  |    52 |
| **Total**| **21,772** |

### Quality Tiers

Templates are scored 0-100 based on matcher quality, severity specificity, and false-positive signals:

| Tier | Score | Count |
|------|-------|------:|
| 4-good | 71-100 | 13,652 |
| 3-acceptable | 46-70 | 7,963 |
| 2-review | 21-45 | 150 |
| 1-cull | 0-20 | 2 |

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
