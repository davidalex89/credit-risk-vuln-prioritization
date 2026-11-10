# Bond Desk Risk Models for Vulnerability Prioritization

Survival analysis applied to CVE exploitation — borrowing Cox Proportional Hazards models from financial credit risk to produce a time-based vulnerability prioritization queue.

Published analysis: [apophenialabs.ai/posts/2026/vuln-survival-analysis/](https://apophenialabs.ai/posts/2026/vuln-survival-analysis/)  
Interactive dashboard: [apophenialabs.ai/2026/vuln-survival-analysis/](https://apophenialabs.ai/2026/vuln-survival-analysis/)

---

## What this does

Banks have been predicting time-to-default on loan portfolios for decades using Cox Proportional Hazards models under Basel II/III regulatory frameworks. The same model applies almost directly to CVEs: replace "borrower" with "vulnerability," replace "default" with "exploitation in the wild," and replace financial ratios with CVSS subscores and exploit metadata.

This script:
1. Fetches CVE data from the NVD API (2019–2023, ~108k CVEs)
2. Joins against CISA KEV for confirmed exploitation dates (event timestamps)
3. Retrieves EPSS scores from FIRST.org
4. Fits Kaplan-Meier curves stratified by CVSS severity tier and PoC signal
5. Fits a Cox PH model with 14 covariates; outputs hazard ratios with 95% CIs
6. Runs an ablation study (model with and without EPSS) to test coefficient stability
7. Builds a synthetic 500-asset inventory ranked by partial hazard score
8. Outputs `chart_data.json` for the interactive dashboard

## Key results

| Model | Concordance |
|---|---|
| Cox PH (full) | **0.938** |
| EPSS alone | 0.918 |
| CVSS alone | 0.728 |

Top hazard ratios (full model):
- EPSS Score (+0.10): **148.5×** — dominant predictor; absorbs most structural signal
- Vendor: Enterprise SW vs Niche: **1.82×**
- Vendor: Hyperscaler / Major OS vs Niche: **1.73×**
- CWE: Memory Corruption vs Other: **1.23×**

CVEs with high early-risk signal at publication exploit **18.3× faster** than those with no signal — visible directly in the Kaplan-Meier curves without any modeling.

## Data sources (all public)

| Source | Use |
|---|---|
| [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE metadata, CVSS v3.1 scores/subscores, CWE, CPE vendor |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation dates (event timestamps). CC0 license. |
| [EPSS — FIRST.org](https://www.first.org/epss) | 30-day exploitation probability scores |

## Usage

```bash
pip install lifelines pandas numpy requests scipy tqdm
python3 vuln_survival.py
```

On first run, fetches NVD data (takes ~5–10 minutes across 2019–2023 with 119-day API windows). Subsequent runs load from `_cache.csv` and complete in under 30 seconds.

Outputs:
- `chart_data.json` — all model results for the interactive dashboard
- `results.txt` — plain-text summary

## Files

| File | Description |
|---|---|
| `vuln_survival.py` | Main script: data fetch, feature engineering, KM curves, Cox model, inventory |
| `chart_data.json` | Dashboard data output (KM curves, hazard ratios, priority queue, inversions) |
| `results.txt` | Plain-text model summary |

`_cache.csv` (NVD dataset cache) is gitignored — regenerate with a fresh run.

## Limitations

The ~0.7% exploitation rate reflects CISA KEV's scope, not actual exploitation rates. KEV is conservative by design — it requires public confirmation of active exploitation and skews toward mass exploitation events. A V2 using VulnCheck KEV, Exploit-DB, and Metasploit module availability would expand the event pool and likely sharpen hazard ratio differentiation across attack vector and CWE.

## License

Data is public domain (NVD/NIST, CISA CC0, EPSS/FIRST.org). Code is MIT.
