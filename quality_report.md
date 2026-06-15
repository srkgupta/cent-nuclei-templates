# Template Quality Report

Scanned **9,284** templates (4 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 2 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 136 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 3,998 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 5,148 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `active_probe_path` | 4,476 | Non-readme.txt endpoint - targeted probe |
| `has_regex_matcher` | 1,865 | Uses regex for tighter fingerprinting (good) |
| `strong_and_matchers` | 1,313 | 3+ matchers all required (AND condition) - good |
| `active_probe_method` | 987 | Uses POST/PUT/PATCH - actual exploit attempt |
| `cve_tagged_missing_cve_id` | 618 | CVE tag present but no cve-id in classification |
| `no_http_block` | 459 |  |
| `single_weak_word_matcher` | 376 | Word matcher with a single string <= 6 chars |
| `or_condition_matchers` | 224 | Any single weak matcher is enough to fire |
| `readme_only_path` | 20 | Only fetches readme.txt - presence detection, not exploit |
| `excessive_path_sweep` | 19 | 20+ paths with only status+word checks - weak match fires across many unrelated URLs |

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

### 2-review (136 templates)

| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 28 |
| Medium | 13 |
| Low | 18 |
| Info | 63 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `dahua-icc-rce.yaml` | critical | 30 | cve_tagged_missing_cve_id|or_condition_matchers |
| `CVE-2021-42183_1.yaml` | critical | 35 | or_condition_matchers |
| `weed-fs.yaml` | critical | 35 | or_condition_matchers |
| `CVE-2022-46169_2.yaml` | critical | 40 | single_weak_word_matcher |
| `fanwei_eoffice_json_common_sqli.yaml` | critical | 40 | single_weak_word_matcher |
| `CVE-2019-18394-4012.yaml` | critical | 45 | cve_tagged_missing_cve_id|single_weak_word_matcher|active_probe_path |
| `CVE-2022-40684_1.yaml` | critical | 45 | or_condition_matchers |
| `cve-2017-3881-3017.yaml` | critical | 45 | cve_tagged_missing_cve_id|no_http_block |

</details>

### 3-acceptable (3,998 templates)

| Severity | Count |
|----------|------:|
| Critical | 580 |
| High | 866 |
| Medium | 592 |
| Low | 390 |
| Info | 1,550 |
| Unknown | 15 |

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

### 4-good (5,148 templates)

| Severity | Count |
|----------|------:|
| Critical | 891 |
| High | 1,142 |
| Medium | 1,382 |
| Low | 273 |
| Info | 1,411 |
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

