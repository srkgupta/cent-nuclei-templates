# Template Quality Report

Scanned **12,138** templates (4 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 0 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 15 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 3,510 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 8,613 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `strong_and_matchers` | 10,422 | 3+ matchers all required (AND condition) - good |
| `readme_only_path` | 9,772 | Only fetches readme.txt - presence detection, not exploit |
| `cve_tagged_missing_cve_id` | 3,008 | CVE tag present but no cve-id in classification |
| `active_probe_path` | 1,736 | Non-readme.txt endpoint - targeted probe |
| `single_weak_word_matcher` | 538 | Word matcher with a single string <= 6 chars |
| `has_regex_matcher` | 263 | Uses regex for tighter fingerprinting (good) |
| `no_http_block` | 237 |  |
| `active_probe_method` | 54 | Uses POST/PUT/PATCH - actual exploit attempt |
| `or_condition_matchers` | 27 | Any single weak matcher is enough to fire |

## Breakdown by Tier and Severity

### 1-cull (0 templates)

### 2-review (15 templates)

| Severity | Count |
|----------|------:|
| Critical | 2 |
| High | 4 |
| Medium | 2 |
| Info | 7 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `cve-2017-3881-3017.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |
| `cve-2020-7247-5247.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |
| `CVE-2020-7048.yaml` | high | 45 | or_condition_matchers|active_probe_path |
| `cve-2015-3306-2506.yaml` | high | 45 | cve_tagged_missing_cve_id|no_http_block |
| `symfony-debugmode-10623.yaml` | high | 45 | or_condition_matchers|active_probe_path |
| `time-sqlinjection-uri-finder.yaml` | high | 45 | or_condition_matchers|active_probe_path |
| `cve-2018-8006-3631.yaml` | medium | 45 | cve_tagged_missing_cve_id|single_weak_word_matcher|active_probe_path |
| `express-lfr-post.yaml` | medium | 45 | or_condition_matchers|active_probe_path |

</details>

### 3-acceptable (3,510 templates)

| Severity | Count |
|----------|------:|
| Critical | 632 |
| High | 980 |
| Medium | 1,621 |
| Low | 34 |
| Info | 235 |
| Unknown | 8 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `CVE-2018-0101.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2017-1000486-2847.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2017-12149-2883.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2017-5638-3032.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2020-15505-4613.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `cve-2021-26855-5890.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `exposed-adb-7281.yaml` | critical | 50 | no_http_block |
| `ftp-default-creds.yaml` | critical | 50 | no_http_block |

</details>

### 4-good (8,613 templates)

| Severity | Count |
|----------|------:|
| Critical | 680 |
| High | 2,261 |
| Medium | 5,202 |
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

