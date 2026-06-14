# Template Quality Report

Scanned **9,327** templates (4 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 2 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 134 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 3,997 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 5,194 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `active_probe_path` | 4,498 | Non-readme.txt endpoint - targeted probe |
| `has_regex_matcher` | 1,865 | Uses regex for tighter fingerprinting (good) |
| `strong_and_matchers` | 1,313 | 3+ matchers all required (AND condition) - good |
| `active_probe_method` | 1,008 | Uses POST/PUT/PATCH - actual exploit attempt |
| `cve_tagged_missing_cve_id` | 621 | CVE tag present but no cve-id in classification |
| `no_http_block` | 459 |  |
| `single_weak_word_matcher` | 393 | Word matcher with a single string <= 6 chars |
| `or_condition_matchers` | 225 | Any single weak matcher is enough to fire |
| `readme_only_path` | 20 | Only fetches readme.txt - presence detection, not exploit |

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

### 2-review (134 templates)

| Severity | Count |
|----------|------:|
| Critical | 13 |
| High | 28 |
| Medium | 12 |
| Low | 18 |
| Info | 63 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `dahua-icc-rce.yaml` | critical | 30 | cve_tagged_missing_cve_id|or_condition_matchers |
| `CVE-2021-42183_1.yaml` | critical | 35 | or_condition_matchers |
| `weed-fs.yaml` | critical | 35 | or_condition_matchers |
| `fanwei_eoffice_json_common_sqli.yaml` | critical | 40 | single_weak_word_matcher |
| `CVE-2022-40684_1.yaml` | critical | 45 | or_condition_matchers |
| `CVE-2024-0507-rce.yaml` | critical | 45 | cve_tagged_missing_cve_id|single_weak_word_matcher |
| `cve-2017-3881-3017.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |
| `cve-2020-7247-5247.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |

</details>

### 3-acceptable (3,997 templates)

| Severity | Count |
|----------|------:|
| Critical | 583 |
| High | 864 |
| Medium | 588 |
| Low | 391 |
| Info | 1,550 |
| Unknown | 16 |

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
| `CVE-2019-3925.yaml` | critical | 50 | no_http_block |

</details>

### 4-good (5,194 templates)

| Severity | Count |
|----------|------:|
| Critical | 905 |
| High | 1,153 |
| Medium | 1,395 |
| Low | 275 |
| Info | 1,417 |
| Unknown | 21 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `AssetNote-RCE.yaml` | critical | 75 | active_probe_path |
| `CNVD-2019-17294.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-01627.yaml` | critical | 75 | strong_and_matchers |
| `CVE-2013-6225.yaml` | critical | 75 | active_probe_path |
| `CVE-2013-6295.yaml` | critical | 75 | active_probe_path |
| `CVE-2014-1924.yaml` | critical | 75 | active_probe_path |
| `CVE-2014-9612.yaml` | critical | 75 | active_probe_path |
| `CVE-2014-9613.yaml` | critical | 75 | active_probe_path |

</details>

