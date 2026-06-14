# Template Quality Report

Scanned **21,767** templates (5 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 2 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 150 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 7,963 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 13,652 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `strong_and_matchers` | 11,623 | 3+ matchers all required (AND condition) - good |
| `readme_only_path` | 9,784 | Only fetches readme.txt - presence detection, not exploit |
| `active_probe_path` | 6,221 | Non-readme.txt endpoint - targeted probe |
| `cve_tagged_missing_cve_id` | 3,377 | CVE tag present but no cve-id in classification |
| `has_regex_matcher` | 1,990 | Uses regex for tighter fingerprinting (good) |
| `active_probe_method` | 1,108 | Uses POST/PUT/PATCH - actual exploit attempt |
| `single_weak_word_matcher` | 972 | Word matcher with a single string <= 6 chars |
| `no_http_block` | 462 |  |
| `or_condition_matchers` | 239 | Any single weak matcher is enough to fire |

## Breakdown by Tier and Severity

### 1-cull (2 templates)

| Severity | Count |
|----------|------:|
| Critical | 1 |
| Info | 1 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `origin-wildcard-check.yaml` | critical | 15 | or_condition_matchers |
| `tomcat-found.yaml` | info | 20 | or_condition_matchers|single_weak_word_matcher |

</details>

### 2-review (150 templates)

| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 39 |
| Medium | 15 |
| Low | 18 |
| Info | 64 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `dahua-icc-rce.yaml` | critical | 30 | cve_tagged_missing_cve_id|or_condition_matchers |
| `CVE-2021-42183_1.yaml` | critical | 35 | or_condition_matchers |
| `weed-fs.yaml` | critical | 35 | or_condition_matchers |
| `fanwei_eoffice_json_common_sqli.yaml` | critical | 40 | single_weak_word_matcher |
| `yunanbao_config_fastjson_rce.yaml` | critical | 40 | single_weak_word_matcher |
| `CVE-2022-40684_1.yaml` | critical | 45 | or_condition_matchers |
| `CVE-2024-0507-rce.yaml` | critical | 45 | cve_tagged_missing_cve_id|single_weak_word_matcher |
| `cve-2017-3881-3017.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |

</details>

### 3-acceptable (7,963 templates)

| Severity | Count |
|----------|------:|
| Critical | 1,297 |
| High | 2,353 |
| Medium | 2,260 |
| Low | 414 |
| Info | 1,610 |
| Unknown | 24 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `CVE-2015-2208.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `CVE-2017-12149-2.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `CVE-2017-12149_1.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `CVE-2018-0101.yaml` | critical | 50 | cve_tagged_missing_cve_id |
| `CVE-2018-21246.yaml` | critical | 50 | single_weak_word_matcher|active_probe_path |
| `CVE-2018-6789.yaml` | critical | 50 | no_http_block |
| `CVE-2019-10149.yaml` | critical | 50 | no_http_block |
| `CVE-2019-17571.yaml` | critical | 50 | no_http_block |

</details>

### 4-good (13,652 templates)

| Severity | Count |
|----------|------:|
| Critical | 1,614 |
| High | 3,405 |
| Medium | 6,572 |
| Low | 389 |
| Info | 1,616 |
| Unknown | 28 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `AVTECH-login-bypass.yaml` | critical | 75 | active_probe_path |
| `AssetNote-RCE.yaml` | critical | 75 | active_probe_path |
| `CNVD-2019-17294.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-01627.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-30167.yaml.yaml` | critical | 75 | active_probe_path |
| `CVE-2003-1599.yaml` | critical | 75 | active_probe_path |
| `CVE-2006-4028.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-0107.yaml` | critical | 75 | active_probe_path |

</details>

