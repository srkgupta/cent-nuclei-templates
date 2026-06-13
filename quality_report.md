# Template Quality Report

Scanned **12,397** templates (4 parse errors skipped).

## Tier Summary

| Tier | Description | Count |
|------|-------------|------:|
| **1-cull** | score 0-20:  status-only / no matchers / always-true version check | 48 |
| **2-review** | score 21-45: weak matchers, OR conditions, readme-only paths | 159 |
| **3-acceptable** | score 46-70: standard version-detection pattern | 4,205 |
| **4-good** | score 71-100: proper matchers, active probes, tight fingerprints | 7,985 |

## Flag Counts

| Flag | Count | Meaning |
|------|------:|---------|
| `strong_and_matchers` | 10,603 | 3+ matchers all required (AND condition) - good |
| `readme_only_path` | 9,843 | Only fetches readme.txt - presence detection, not exploit |
| `cve_tagged_missing_cve_id` | 3,153 | CVE tag present but no cve-id in classification |
| `active_probe_path` | 1,859 | Non-readme.txt endpoint - targeted probe |
| `deprecated_requests_key` | 1,448 | Uses v2 'requests:' key instead of 'http:' |
| `single_weak_word_matcher` | 635 | Word matcher with a single string <= 6 chars |
| `has_regex_matcher` | 271 | Uses regex for tighter fingerprinting (good) |
| `no_http_block` | 237 |  |
| `always_true_version_check` | 140 | compare_versions('>0') matches every plugin install |
| `active_probe_method` | 56 | Uses POST/PUT/PATCH - actual exploit attempt |
| `no_matchers` | 43 | Template fires on any successful HTTP response |
| `or_condition_matchers` | 32 | Any single weak matcher is enough to fire |
| `status_only_matchers` | 6 | No body/header content checked - any 200 fires |

## Breakdown by Tier and Severity

### 1-cull (48 templates)

| Severity | Count |
|----------|------:|
| Critical | 3 |
| High | 10 |
| Medium | 4 |
| Info | 31 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `log4j-code42-rce.yaml` | critical | 5 | deprecated_requests_key|no_matchers|single_weak_word_matcher|active_probe_path |
| `log4j-fuzz-head-poc-v1.yaml` | critical | 10 | deprecated_requests_key|or_condition_matchers|single_weak_word_matcher |
| `cve-2020-17518-4688.yaml` | critical | 15 | deprecated_requests_key|cve_tagged_missing_cve_id|no_matchers|active_probe_path |
| `Header-Injection.yaml` | high | 0 | deprecated_requests_key|no_matchers|or_condition_matchers |
| `cve-2020-23972-4786.yaml` | high | 5 | deprecated_requests_key|cve_tagged_missing_cve_id|no_matchers |
| `ScanMySQLiErrorBased.yaml` | high | 10 | deprecated_requests_key|no_matchers |
| `bxss.yaml` | high | 10 | deprecated_requests_key|no_matchers |
| `sqli2.yaml` | high | 10 | deprecated_requests_key|no_matchers |

</details>

### 2-review (159 templates)

| Severity | Count |
|----------|------:|
| Critical | 52 |
| High | 45 |
| Medium | 42 |
| Low | 3 |
| Info | 17 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `cve-2017-12629-2909.yaml` | critical | 25 | deprecated_requests_key|cve_tagged_missing_cve_id|single_weak_word_matcher |
| `log4shell.yaml` | critical | 25 | deprecated_requests_key|cve_tagged_missing_cve_id|single_weak_word_matcher |
| `Premium_Gallery_Manager-61abe32e52b571909ad72a03fd796dc2.yaml` | critical | 30 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|readme_only_path |
| `RLSWordPressSearch-dd2697de3a8d5988afaf1e8d3ac8e37b.yaml` | critical | 30 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|readme_only_path |
| `accordion-6f8f1d3e4e1383d7e226c6b2b11ea4a4.yaml` | critical | 30 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|readme_only_path |
| `amerisale-re-0bcd5e6f648c26dbe80dedf2a6385eae.yaml` | critical | 30 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|readme_only_path |
| `barclaycart-e2c7747732780cbb22ac5c28c3c4ac71.yaml` | critical | 30 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|readme_only_path |
| `cve-2017-12615-2899.yaml` | critical | 30 | deprecated_requests_key|cve_tagged_missing_cve_id|no_matchers|has_regex_matcher|active_probe_path |

</details>

### 3-acceptable (4,205 templates)

| Severity | Count |
|----------|------:|
| Critical | 685 |
| High | 1,203 |
| Medium | 1,743 |
| Low | 100 |
| Info | 466 |
| Unknown | 8 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `CVE-2022-4298.yaml` | critical | 50 | deprecated_requests_key|single_weak_word_matcher |
| `apache-httpd-rce-362.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id |
| `colormix-081a0818ee59b395f6acc445324bdeb8.yaml` | critical | 50 | cve_tagged_missing_cve_id|strong_and_matchers|always_true_version_check|active_probe_path |
| `cve-2018-1207-3230.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id|active_probe_path |
| `cve-2018-17431-3424.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id |
| `cve-2019-9733-4312.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id |
| `cve-2020-12720-4479.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id |
| `cve-2020-24186-4795.yaml` | critical | 50 | deprecated_requests_key|cve_tagged_missing_cve_id |

</details>

### 4-good (7,985 templates)

| Severity | Count |
|----------|------:|
| Critical | 646 |
| High | 2,052 |
| Medium | 5,121 |
| Low | 99 |
| Info | 59 |
| Unknown | 8 |

<details><summary>Sample worst templates (lowest score first)</summary>

| File | Severity | Score | Flags |
|------|----------|------:|-------|
| `CVE-2003-1599.yaml` | critical | 75 | active_probe_path |
| `CVE-2006-4028.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-0107.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-1277.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-3544.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-6013.yaml` | critical | 75 | active_probe_path |
| `CVE-2007-6318.yaml` | critical | 75 | active_probe_path |
| `CVE-2008-5695.yaml` | critical | 75 | active_probe_path |

</details>

