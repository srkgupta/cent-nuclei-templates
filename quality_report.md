# Template Quality Report

Scanned **10,992** templates (5 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 2 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 150 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 5,091 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 5,749 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `active_probe_path` | 5,344 | Non-readme.txt endpoint - targeted probe |
| `has_regex_matcher` | 1,929 | Uses regex for tighter fingerprinting (good) |
| `strong_and_matchers` | 1,373 | 3+ matchers all required (AND condition) - good |
| `active_probe_method` | 1,105 | Uses POST/PUT/PATCH - actual exploit attempt |
| `cve_tagged_missing_cve_id` | 634 | CVE tag present but no cve-id in classification |
| `single_weak_word_matcher` | 464 | Word matcher with a single string <= 6 chars |
| `no_http_block` | 462 |  |
| `or_condition_matchers` | 237 | Any single weak matcher is enough to fire |
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

### 3-acceptable (5,091 templates)

| Severity | Count |
|----------|------:|
| Critical | 898 |
| High | 1,474 |
| Medium | 716 |
| Low | 401 |
| Info | 1,580 |
| Unknown | 17 |

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

### 4-good (5,749 templates)

| Severity | Count |
|----------|------:|
| Critical | 995 |
| High | 1,353 |
| Medium | 1,460 |
| Low | 287 |
| Info | 1,605 |
| Unknown | 21 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `AVTECH-login-bypass.yaml` | critical | 75 | active_probe_path |
| `AssetNote-RCE.yaml` | critical | 75 | active_probe_path |
| `CNVD-2019-17294.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-01627.yaml` | critical | 75 | strong_and_matchers |
| `CNVD-2021-30167.yaml.yaml` | critical | 75 | active_probe_path |
| `CVE-2013-3738.yaml` | critical | 75 | active_probe_path |
| `CVE-2013-6225.yaml` | critical | 75 | active_probe_path |
| `CVE-2013-6295.yaml` | critical | 75 | active_probe_path |

</details>

