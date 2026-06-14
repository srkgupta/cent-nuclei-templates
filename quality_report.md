# Template Quality Report

Scanned **12,205** templates (4 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 0 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 29 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 3,552 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 8,624 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `strong_and_matchers` | 10,460 | 3+ matchers all required (AND condition) - good |
| `readme_only_path` | 9,798 | Only fetches readme.txt - presence detection, not exploit |
| `cve_tagged_missing_cve_id` | 3,027 | CVE tag present but no cve-id in classification |
| `active_probe_path` | 1,756 | Non-readme.txt endpoint - targeted probe |
| `single_weak_word_matcher` | 605 | Word matcher with a single string <= 6 chars |
| `has_regex_matcher` | 270 | Uses regex for tighter fingerprinting (good) |
| `no_http_block` | 237 |  |
| `active_probe_method` | 55 | Uses POST/PUT/PATCH - actual exploit attempt |
| `or_condition_matchers` | 28 | Any single weak matcher is enough to fire |

## Breakdown by Tier and Severity

### 1-cull (0 templates)

### 2-review (29 templates)

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 9 |
| Medium | 3 |
| Info | 7 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `cve-2017-12629-2909.yaml` | critical | 35 | cve_tagged_missing_cve_id|single_weak_word_matcher |
| `log4shell.yaml` | critical | 35 | cve_tagged_missing_cve_id|single_weak_word_matcher |
| `netgear-wnap320-rce.yaml` | critical | 40 | single_weak_word_matcher |
| `seeyon_fastjson.yaml` | critical | 40 | single_weak_word_matcher |
| `seeyon_log4j.yaml` | critical | 40 | single_weak_word_matcher |
| `tableau-log4j-rce.yaml` | critical | 40 | single_weak_word_matcher |
| `ueditor-uploadVul.yaml` | critical | 40 | single_weak_word_matcher |
| `vmware-workspace-one-log4j-rce.yaml` | critical | 40 | single_weak_word_matcher |

</details>

### 3-acceptable (3,552 templates)

| Severity | Count |
|----------|------:|
| Critical | 637 |
| High | 995 |
| Medium | 1,637 |
| Low | 40 |
| Info | 235 |
| Unknown | 8 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `CVE-2018-0101.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `apache-solr-log4j-CVE-2021-44228.yaml` | critical | 50 | single_weak_word_matcher|active_probe_path |
| `cisco-rv-series-rce.yaml` | critical | 50 | single_weak_word_matcher |
| `cve-2017-1000486-2847.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2017-12149-2883.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2017-5638-3032.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2020-15505-4613.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2021-26855-5890.yaml` | critical | 50 | cve_tagged_missing_cve_id |

</details>

### 4-good (8,624 templates)

| Severity | Count |
|----------|------:|
| Critical | 685 |
| High | 2,266 |
| Medium | 5,203 |
| Low | 162 |
| Info | 300 |
| Unknown | 8 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `AVTECH-login-bypass.yaml` | critical | 75 | active_probe_path |
| `CNVD-2019-17294.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-01627.yaml` | critical | 75 | strong_and_matchers |
| `CVE-2003-1599.yaml` | critical | 75 | active_probe_path |
| `CVE-2006-4028.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-0107.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-1277.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-3544.yaml` | critical | 75 | active_probe_path |

</details>

