# cent-nuclei-templates
Cent Nuclei Templates generated through the [cent tool](https://github.com/xm1k3/cent)

This repo contains **12,142 quality-filtered nuclei templates** sourced from the cent tool and curated against the [core nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).

### What was done to clean this up

Starting from ~23,000 raw templates, the following passes were applied:

- **Deduplication** - templates whose `id:` field matched core nuclei-templates removed; empty-MD5 stub templates (auto-generated placeholders) removed
- **No-signal culls** - templates with no matchers block, status-200-only matchers, and `compare_versions('>0')` always-true version checks removed
- **Syntax modernisation** - 1,400 templates updated from deprecated nuclei v2 `requests:` key to `http:`
- **Generic matcher culls** - templates whose sole word matcher was a common English word (`http`, `dns`, `backup`, `player`, `stream`, `evil`, `team`, `canvas`, `erp`, `bridge`) removed

### Template Stats

| Severity | Count |
|----------|------:|
| Critical | 1,314 |
| High     | 3,245 |
| Medium   | 6,826 |
| Low      |   198 |
| Info     |   543 |
| Unknown  |    15 |
| **Total**| **12,142** |

### Maintenance

The `cleanup/` folder contains two scripts for ongoing maintenance:

- `cleanup/dedup.py` - re-deduplicates against core nuclei-templates (run after pulling new templates)
- `cleanup/quality_score.py` - scores all templates 0-100 and outputs `quality_scores.csv` + `quality_report.md`

```
python3 cleanup/dedup.py --dry-run   # preview what would be removed
python3 cleanup/dedup.py             # run dedup
python3 cleanup/quality_score.py     # regenerate quality report
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
