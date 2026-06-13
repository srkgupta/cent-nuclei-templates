# cent-nuclei-templates
Cent Nuclei Templates generated through the [cent tool](https://github.com/xm1k3/cent)

This repo contains 12,401 unique custom nuclei templates generated from the [cent tool](https://github.com/xm1k3/cent), deduplicated against the [core nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).

Note:
- All the invalid templates which are not compatible with the latest nuclei are removed.
- All the duplicate templates are removed
- All the workflows are removed
- Templates already present in the core nuclei-templates are removed (deduped by template `id:`)
- Empty/stub auto-generated templates (empty-MD5 hash suffix) are removed

### Template Stats

| Severity | Count |
|----------|------:|
| Critical | 1,386 |
| High     | 3,310 |
| Medium   | 6,911 |
| Low      |   204 |
| Info     |   574 |
| Unknown  |    15 |
| **Total**| **12,401** |

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
