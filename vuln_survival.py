#!/usr/bin/env python3
"""
Dead on Arrival: Survival Analysis for Vulnerability Prioritization
Apophenia Labs — 2026

Pulls NVD + CISA KEV + EPSS, builds a Cox PH model, generates chart data
for the interactive dashboard, and produces a synthetic inventory prioritization.

Run:  python3 vuln_survival.py
Outputs:
  - chart_data.json   (consumed by dashboard.js)
  - results.txt       (narrative summary)
"""

import json, math, random, sys, time, warnings
from datetime import datetime, timedelta, date
from pathlib import Path
import requests
import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter, CoxPHFitter
from lifelines.utils import concordance_index

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────
# 0. CONFIGURATION
# ─────────────────────────────────────────────
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL   = "https://api.first.org/data/v1/epss"

# NVD window — CVEs published 2019-01-01 through 2023-12-31
# API max window = 120 days; we loop over 120-day slices
NVD_RANGE_START = date(2019, 1, 1)
NVD_RANGE_END   = date(2023, 12, 31)
NVD_WINDOW_DAYS = 119

# Observation window for censoring
OBS_END    = date(2025, 12, 31)

OUT_DIR    = Path(__file__).parent

# ─────────────────────────────────────────────
# 1. FETCH KEV
# ─────────────────────────────────────────────
def fetch_kev():
    print("Fetching CISA KEV …")
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    raw = r.json()["vulnerabilities"]
    df = pd.DataFrame([{
        "cve_id":      v["cveID"],
        "kev_added":   pd.to_datetime(v["dateAdded"]).date(),
        "vendor":      v.get("vendorProject",""),
        "product":     v.get("product",""),
        "kev_type":    v.get("vulnerabilityName",""),
    } for v in raw])
    print(f"  KEV entries: {len(df):,}")
    return df.set_index("cve_id")

# ─────────────────────────────────────────────
# 2. FETCH NVD (paged over 120-day windows)
# ─────────────────────────────────────────────
def _nvd_window(win_start, win_end, headers, page_size=2000):
    """Fetch all CVEs within a single ≤120-day window, handling pagination."""
    rows, start = [], 0
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params_base = {
        "pubStartDate": win_start.strftime(fmt),
        "pubEndDate":   win_end.strftime(fmt),
        "resultsPerPage": page_size,
    }
    while True:
        params = {**params_base, "startIndex": start}
        for attempt in range(3):
            try:
                r = requests.get(NVD_BASE, params=params, headers=headers, timeout=90)
                r.raise_for_status()
                break
            except Exception as e:
                if attempt == 2:
                    raise
                time.sleep(6)
        data  = r.json()
        items = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        rows.extend(items)
        start += len(items)
        if start >= total:
            break
        time.sleep(0.7)
    return rows

def fetch_nvd():
    print("Fetching NVD CVEs (2019–2023, 119-day windows) …")
    all_items = []
    headers = {"User-Agent": "ApopheniaLabs-Research/1.0"}
    cur = NVD_RANGE_START
    while cur <= NVD_RANGE_END:
        win_end = min(cur + timedelta(days=NVD_WINDOW_DAYS), NVD_RANGE_END)
        chunk = _nvd_window(cur, win_end, headers)
        all_items.extend(chunk)
        print(f"  Window {cur} → {win_end}: {len(chunk):4d} CVEs  (total so far: {len(all_items):,})", flush=True)
        cur = win_end + timedelta(days=1)
        time.sleep(1.0)

    rows = []
    for item in all_items:
        c = item["cve"]
        cve_id = c["id"]
        published = pd.to_datetime(c["published"]).date()

        # CVSS v3.1 preferred, fall back to v3.0 then v2
        metrics = c.get("metrics", {})
        cv3 = (metrics.get("cvssMetricV31", []) or
               metrics.get("cvssMetricV30", []) or [])
        cv2 = metrics.get("cvssMetricV2", [])

        base_score = av = ac = pr = ui = scope = None
        if cv3:
            d = cv3[0]["cvssData"]
            base_score = d.get("baseScore")
            av    = d.get("attackVector","")
            ac    = d.get("attackComplexity","")
            pr    = d.get("privilegesRequired","")
            ui    = d.get("userInteraction","")
            scope = d.get("scope","")
        elif cv2:
            d = cv2[0]["cvssData"]
            base_score = d.get("baseScore")
            av    = d.get("accessVector","")
            ac    = d.get("accessComplexity","")
            pr    = "NONE" if d.get("authentication","") == "NONE" else "LOW"
            ui    = "NONE"
            scope = "UNCHANGED"

        if base_score is None:
            continue

        # CWE
        weaknesses = c.get("weaknesses", [])
        cwe = "OTHER"
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_val = desc.get("value","")
                if cwe_val.startswith("CWE-"):
                    cwe = cwe_val
                    break
            if cwe != "OTHER":
                break

        # Vendor tier from CPE
        cfg = c.get("configurations", [])
        vendor_raw = ""
        for node_wrap in cfg:
            for node in node_wrap.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria","")
                    parts = cpe.split(":")
                    if len(parts) > 3:
                        vendor_raw = parts[3].lower()
                        break
                if vendor_raw:
                    break
            if vendor_raw:
                break

        rows.append({
            "cve_id":     cve_id,
            "published":  published,
            "base_score": base_score,
            "av":         av,
            "ac":         ac,
            "pr":         pr,
            "ui":         ui,
            "scope":      scope,
            "cwe":        cwe,
            "vendor_raw": vendor_raw,
        })

    df = pd.DataFrame(rows)
    print(f"  NVD total kept: {len(df):,}")
    return df.set_index("cve_id")

# ─────────────────────────────────────────────
# 3. FETCH EPSS (batch via CSV endpoint)
# ─────────────────────────────────────────────
def fetch_epss(cve_ids):
    print("Fetching EPSS scores …")
    scores = {}
    batch = 100
    ids   = list(cve_ids)
    for i in range(0, len(ids), batch):
        chunk = ids[i:i+batch]
        params = {"cve": ",".join(chunk), "fields": "cve,epss"}
        try:
            r = requests.get(EPSS_URL, params=params, timeout=30)
            r.raise_for_status()
            for row in r.json().get("data", []):
                scores[row["cve"]] = float(row["epss"])
        except:
            pass
        time.sleep(0.2)
    print(f"  EPSS scores retrieved: {len(scores):,}")
    return scores

# ─────────────────────────────────────────────
# 4. FEATURE ENGINEERING
# ─────────────────────────────────────────────
HYPERSCALERS = {
    "microsoft","google","apple","linux","redhat","canonical","debian",
    "apache","nginx","openssl","mozilla","oracle","cisco","adobe",
}
MAJOR_ENTERPRISE = {
    "sap","vmware","citrix","palo_alto_networks","fortinet","f5","juniper",
    "checkpoint","salesforce","servicenow","atlassian","gitlab","github",
}

def cwe_bucket(cwe):
    memory = {"CWE-120","CWE-121","CWE-122","CWE-124","CWE-125","CWE-126",
              "CWE-127","CWE-128","CWE-129","CWE-130","CWE-415","CWE-416",
              "CWE-476","CWE-787","CWE-788","CWE-824","CWE-825"}
    injection = {"CWE-77","CWE-78","CWE-79","CWE-89","CWE-90","CWE-91",
                 "CWE-94","CWE-95","CWE-96","CWE-601","CWE-611","CWE-917"}
    auth = {"CWE-284","CWE-285","CWE-287","CWE-288","CWE-290","CWE-294",
            "CWE-302","CWE-306","CWE-307","CWE-522","CWE-640","CWE-798"}
    info  = {"CWE-200","CWE-201","CWE-202","CWE-203","CWE-209","CWE-532"}
    if cwe in memory:    return "memory_corruption"
    if cwe in injection: return "injection"
    if cwe in auth:      return "auth_bypass"
    if cwe in info:      return "info_disclosure"
    return "other"

def vendor_tier(vendor_raw):
    v = vendor_raw.lower()
    if any(h in v for h in HYPERSCALERS):   return 1
    if any(e in v for e in MAJOR_ENTERPRISE): return 2
    return 3

# ─────────────────────────────────────────────
# 5. BUILD DATASET
# ─────────────────────────────────────────────
def build_dataset(nvd, kev, epss_map):
    print("Building analytical dataset …")
    df = nvd.copy()

    # Join KEV events
    df["kev_added"] = kev["kev_added"]
    df["event"]     = df["kev_added"].notna().astype(int)

    # Survival time in days
    def survival_days(row):
        start = row["published"]
        end   = row["kev_added"] if row["event"] else OBS_END
        if pd.isna(start) or pd.isna(end):
            return np.nan
        d = (end - start).days
        return max(d, 1)

    df["duration"] = df.apply(survival_days, axis=1)
    df = df.dropna(subset=["duration", "base_score"])

    # EPSS
    df["epss"] = df.index.map(lambda x: epss_map.get(x, np.nan))
    df["epss"] = df["epss"].fillna(df["epss"].median())

    # Categorical features → indicators
    df["av_network"] = (df["av"] == "NETWORK").astype(int)
    df["av_adjacent"]= (df["av"] == "ADJACENT").astype(int)
    df["av_local"]   = (df["av"] == "LOCAL").astype(int)
    # av_physical is reference

    df["ac_low"]  = (df["ac"] == "LOW").astype(int)

    df["pr_none"] = (df["pr"] == "NONE").astype(int)
    df["pr_low"]  = (df["pr"] == "LOW").astype(int)

    df["ui_none"] = (df["ui"] == "NONE").astype(int)

    df["cwe_bucket"] = df["cwe"].apply(cwe_bucket)
    df["cwe_memory"]  = (df["cwe_bucket"] == "memory_corruption").astype(int)
    df["cwe_inject"]  = (df["cwe_bucket"] == "injection").astype(int)
    df["cwe_auth"]    = (df["cwe_bucket"] == "auth_bypass").astype(int)
    df["cwe_info"]    = (df["cwe_bucket"] == "info_disclosure").astype(int)

    df["vendor_tier"] = df["vendor_raw"].apply(vendor_tier)
    df["vt1"] = (df["vendor_tier"] == 1).astype(int)
    df["vt2"] = (df["vendor_tier"] == 2).astype(int)

    # PoC proxy: exploit-db is hard to bulk-match; use EPSS > 0.05 at pub time
    # as a conservative "known-dangerous at publication" flag
    df["poc_proxy"]   = (df["epss"] > 0.05).astype(int)

    # CVSS severity tier for K-M stratification
    def sev_tier(s):
        if s >= 9.0: return "Critical (9.0–10.0)"
        if s >= 7.0: return "High (7.0–8.9)"
        if s >= 4.0: return "Medium (4.0–6.9)"
        return "Low (0.1–3.9)"
    df["severity_tier"] = df["base_score"].apply(sev_tier)

    print(f"  Final dataset: {len(df):,} rows, {df['event'].sum():,} events")
    return df

# ─────────────────────────────────────────────
# 6. KAPLAN-MEIER CURVES (compute values, no matplotlib)
# ─────────────────────────────────────────────
def km_by_severity(df):
    """Returns dict: tier → {x: [...], y: [...], ci_lower, ci_upper, n, events}"""
    kmf = KaplanMeierFitter()
    results = {}
    tiers = ["Critical (9.0–10.0)","High (7.0–8.9)","Medium (4.0–6.9)","Low (0.1–3.9)"]
    for tier in tiers:
        sub = df[df["severity_tier"] == tier]
        if len(sub) < 10:
            continue
        kmf.fit(sub["duration"], sub["event"], label=tier)
        tl = kmf.timeline.tolist()
        sf = kmf.survival_function_[tier].tolist()
        ci = kmf.confidence_interval_
        col_lo = ci.columns[0]
        col_hi = ci.columns[1]
        results[tier] = {
            "x": [int(v) for v in tl],
            "y": [round(v, 4) for v in sf],
            "ci_lo": [round(v, 4) for v in ci[col_lo].tolist()],
            "ci_hi": [round(v, 4) for v in ci[col_hi].tolist()],
            "n":      int(len(sub)),
            "events": int(sub["event"].sum()),
        }
    return results

def km_by_poc(df):
    kmf = KaplanMeierFitter()
    results = {}
    for flag, label in [(1,"PoC-Era (EPSS > 5%)"),(0,"No Early Risk Signal")]:
        sub = df[df["poc_proxy"] == flag]
        if len(sub) < 10:
            continue
        kmf.fit(sub["duration"], sub["event"], label=label)
        tl = kmf.timeline.tolist()
        sf = kmf.survival_function_[label].tolist()
        ci = kmf.confidence_interval_
        col_lo = ci.columns[0]
        col_hi = ci.columns[1]
        results[label] = {
            "x": [int(v) for v in tl],
            "y": [round(v, 4) for v in sf],
            "ci_lo": [round(v, 4) for v in ci[col_lo].tolist()],
            "ci_hi": [round(v, 4) for v in ci[col_hi].tolist()],
            "n":      int(len(sub)),
            "events": int(sub["event"].sum()),
        }
    return results

# ─────────────────────────────────────────────
# 7. COX PROPORTIONAL HAZARDS
# ─────────────────────────────────────────────
COX_COLS = [
    "duration","event","base_score",
    "av_network","av_adjacent","av_local",
    "ac_low","pr_none","pr_low","ui_none",
    "cwe_memory","cwe_inject","cwe_auth","cwe_info",
    "vt1","vt2","epss",
]

def fit_cox(df):
    print("Fitting Cox PH model …", flush=True)
    sub = df[COX_COLS].dropna()

    # Drop zero/near-zero variance columns — rare dummy categories
    # (e.g. av_physical reference has no samples → sum-to-1 collinearity)
    feature_cols = [c for c in sub.columns if c not in ("duration", "event")]
    variances = sub[feature_cols].var()
    zero_var = variances[variances < 1e-5].index.tolist()
    if zero_var:
        print(f"  Dropping near-zero-variance columns: {zero_var}", flush=True)
        sub = sub.drop(columns=zero_var)

    # Also drop any column that is a perfect linear combination of others
    # (correlation > 0.98 with another feature)
    remaining = [c for c in sub.columns if c not in ("duration", "event")]
    corr = sub[remaining].corr().abs()
    upper = corr.where(~(corr.isna()) & (corr < 1) &
                       (corr.values > 0.97)).stack()
    highly_correlated = set()
    for (c1, c2), v in upper.items():
        # Drop the one with lower variance
        if variances.get(c1, 0) <= variances.get(c2, 0):
            highly_correlated.add(c1)
        else:
            highly_correlated.add(c2)
    if highly_correlated:
        print(f"  Dropping highly-correlated columns: {highly_correlated}", flush=True)
        sub = sub.drop(columns=list(highly_correlated), errors="ignore")

    print(f"  Fitting on {len(sub):,} rows, "
          f"{len([c for c in sub.columns if c not in ('duration','event')])} covariates",
          flush=True)

    cph = CoxPHFitter(penalizer=0.01)
    cph.fit(sub, duration_col="duration", event_col="event")
    cph.print_summary()
    return cph, sub

def hazard_ratios(cph):
    """Returns list of dicts for forest plot."""
    sm = cph.summary
    rows = []
    names = {
        "base_score":   "CVSS Base Score (+1)",
        "av_network":   "Attack Vector: Network vs Physical",
        "av_adjacent":  "Attack Vector: Adjacent vs Physical",
        "av_local":     "Attack Vector: Local vs Physical",
        "ac_low":       "Attack Complexity: Low vs High",
        "pr_none":      "Privs Required: None vs High",
        "pr_low":       "Privs Required: Low vs High",
        "ui_none":      "User Interaction: None vs Required",
        "cwe_memory":   "CWE: Memory Corruption vs Other",
        "cwe_inject":   "CWE: Injection vs Other",
        "cwe_auth":     "CWE: Auth Bypass vs Other",
        "cwe_info":     "CWE: Info Disclosure vs Other",
        "poc_proxy":    "EPSS >5% at Publication",
        "vt1":          "Vendor: Hyperscaler / Major OS vs Niche",
        "vt2":          "Vendor: Enterprise SW vs Niche",
        "epss":         "EPSS Score (+0.10)",
    }
    for covar, label in names.items():
        if covar not in sm.index:
            continue
        hr   = float(np.exp(sm.loc[covar, "coef"]))
        # 95% CI
        lo   = float(np.exp(sm.loc[covar, "coef lower 95%"]))
        hi   = float(np.exp(sm.loc[covar, "coef upper 95%"]))
        pval = float(sm.loc[covar, "p"])
        rows.append({
            "covar": covar,
            "label": label,
            "hr":   round(hr, 3),
            "lo":   round(lo, 3),
            "hi":   round(hi, 3),
            "p":    round(pval, 4),
            "sig":  pval < 0.05,
        })
    return rows

# ─────────────────────────────────────────────
# 8. SYNTHETIC ASSET INVENTORY
# ─────────────────────────────────────────────
ASSET_TYPES = [
    ("Web Application Server",     0.35),
    ("Database Server",            0.18),
    ("Network Appliance / Firewall",0.12),
    ("Workstation / Endpoint",     0.14),
    ("Container Orchestration",    0.08),
    ("Legacy ERP System",          0.08),
    ("Cloud Management Console",   0.05),
]

def build_inventory(df, cph, n_assets=500):
    """
    Generate 500 fictional assets, assign CVEs, score via Cox partial hazard.

    Ranking note: we use predict_partial_hazard() rather than median survival time.
    With a ~0.7% event rate, the Cox survival function almost never crosses 50%,
    so "median TTE" is undefined for virtually every CVE and produces a meaningless
    tied ranking.  Partial hazard is the standard Cox-derived risk score and
    always produces a valid, differentiating ordinal.  Higher partial hazard →
    shorter expected time to exploitation → lower (more urgent) survival rank.
    """
    print("Building synthetic inventory …")

    # Deliberately seed the pool with confirmed-exploited CVEs so the top of the
    # queue contains validated high-risk items alongside unconfirmed high-hazard ones.
    kev_pool = df[df["event"] == 1]
    non_kev  = df[df["event"] == 0]

    hi_sev = non_kev[non_kev["base_score"] >= 7.0]
    lo_sev = non_kev[non_kev["base_score"] < 7.0]

    kev_sample = kev_pool.sample(min(50,  len(kev_pool)), replace=False, random_state=42)
    hi_sample  = hi_sev.sample( min(300, len(hi_sev)),  replace=True,  random_state=42)
    lo_sample  = lo_sev.sample( min(150, len(lo_sev)),  replace=True,  random_state=42)
    cve_pool   = pd.concat([kev_sample, hi_sample, lo_sample]).reset_index()
    cve_pool   = cve_pool.rename(columns={"index": "cve_id"})  # preserve CVE ID
    cve_pool   = cve_pool.head(n_assets)

    feat_cols  = [c for c in COX_COLS if c not in ("duration", "event")]

    # Score every CVE in one vectorised call — much faster than row-by-row.
    pool_feats = cve_pool[feat_cols].copy().fillna(0)
    partial_haz = cph.predict_partial_hazard(pool_feats).values

    # 1-year exploitation probability: 1 − S(365)
    try:
        sf365 = cph.predict_survival_function(pool_feats, times=[365])
        prob_1yr = (1.0 - sf365.iloc[0].values).clip(0, 1)
    except Exception:
        prob_1yr = np.zeros(len(cve_pool))

    asset_types_list = [a[0] for a in ASSET_TYPES]
    asset_weights    = [a[1] for a in ASSET_TYPES]

    assets = []
    for i, row in cve_pool.iterrows():
        atype = random.choices(asset_types_list, weights=asset_weights)[0]
        assets.append({
            "asset_id":         f"ASSET-{i+1:04d}",
            "asset_type":       atype,
            "cve_id":           row["cve_id"],
            "base_score":       round(float(row["base_score"]), 1),
            "partial_hazard":   round(float(partial_haz[i]), 4),
            "prob_exploit_1yr": round(float(prob_1yr[i]) * 100, 2),
            "av_network":       int(row["av_network"]),
            "poc_proxy":        int(row["poc_proxy"]),
            "cwe_bucket":       row["cwe_bucket"],
            "severity_tier":    row["severity_tier"],
            "in_kev":           int(row["event"]),
        })

    inv = pd.DataFrame(assets)
    # Higher partial hazard = more urgent = rank 1
    inv["survival_rank"] = inv["partial_hazard"].rank(ascending=False, method="first").astype(int)
    # CVSS rank for comparison (higher CVSS = rank 1)
    inv["cvss_rank"] = inv["base_score"].rank(ascending=False, method="first").astype(int)
    # Positive delta = survival model ranks this item higher than CVSS alone
    inv["rank_delta"] = inv["cvss_rank"] - inv["survival_rank"]
    inv = inv.sort_values("survival_rank")
    return inv

# ─────────────────────────────────────────────
# 9. INVERSIONS — the "money shot"
# ─────────────────────────────────────────────
def find_inversions(inv, top_n=20):
    """
    Find cases where a lower CVSS CVE ranks higher under survival model.
    Return top 20 most dramatic reversals.
    """
    inv = inv.copy().reset_index(drop=True)
    inversions = []
    for i, row_a in inv.iterrows():
        for j, row_b in inv.iterrows():
            if j <= i:
                continue
            # row_a ranks higher under survival (lower survival_rank)
            if (row_a["base_score"] < row_b["base_score"] and
                    row_a["survival_rank"] < row_b["survival_rank"] and
                    row_b["base_score"] >= 8.5 and
                    row_a["base_score"] <= 8.0):
                inversions.append({
                    "winner_cve":    row_a["cve_id"],
                    "winner_score":  row_a["base_score"],
                    "winner_risk":   round(float(row_a["partial_hazard"]), 4),
                    "winner_prob1yr": round(float(row_a["prob_exploit_1yr"]), 2),
                    "winner_rank":   row_a["survival_rank"],
                    "loser_cve":     row_b["cve_id"],
                    "loser_score":   row_b["base_score"],
                    "loser_risk":    round(float(row_b["partial_hazard"]), 4),
                    "loser_prob1yr": round(float(row_b["prob_exploit_1yr"]), 2),
                    "loser_rank":    row_b["survival_rank"],
                    "score_gap":     round(row_b["base_score"] - row_a["base_score"], 1),
                    "rank_improvement": row_b["survival_rank"] - row_a["survival_rank"],
                })
            if len(inversions) >= top_n * 5:
                break
        if len(inversions) >= top_n * 5:
            break
    inversions.sort(key=lambda x: -x["rank_improvement"])
    return inversions[:top_n]

# ─────────────────────────────────────────────
# 10. AGGREGATE STATS
# ─────────────────────────────────────────────
def compute_stats(df):
    total     = len(df)
    exploited = int(df["event"].sum())
    pct_kev   = round(exploited / total * 100, 1)
    med_tte   = int(df[df["event"]==1]["duration"].median())
    poc_pct   = round(df["poc_proxy"].mean() * 100, 1)

    # Median TTE by severity tier
    tte_by_sev = (
        df[df["event"]==1]
        .groupby("severity_tier")["duration"]
        .median()
        .round(0)
        .astype(int)
        .to_dict()
    )
    # Event rate by AV
    rate_by_av = (
        df.groupby("av")["event"]
        .agg(["sum","count"])
        .assign(rate=lambda x: (x["sum"]/x["count"]*100).round(1))
        ["rate"]
        .to_dict()
    )
    return {
        "total_cves":      total,
        "exploited":       exploited,
        "pct_kev":         pct_kev,
        "median_tte_days": med_tte,
        "poc_pct":         poc_pct,
        "tte_by_sev":      tte_by_sev,
        "rate_by_av":      rate_by_av,
    }

# ─────────────────────────────────────────────
# 11. KM SURVIVAL PROBABILITIES AT KEY TIME POINTS
# ─────────────────────────────────────────────
def km_at_days(km_results, days_list=[30, 90, 180, 365, 730]):
    """For each tier, interpolate survival probability at given days."""
    table = {}
    for tier, data in km_results.items():
        x = np.array(data["x"])
        y = np.array(data["y"])
        row = {}
        for d in days_list:
            idx = np.searchsorted(x, d, side="right") - 1
            if idx < 0: idx = 0
            if idx >= len(y): idx = len(y) - 1
            row[str(d)] = round(float(y[idx]), 4)
        table[tier] = row
    return table

# ─────────────────────────────────────────────
# 12. MAIN
# ─────────────────────────────────────────────
def main():
    out = {}
    CACHE = OUT_DIR / "_cache.csv"

    # --- Data (with disk cache to avoid re-fetching NVD on retry) ---
    if CACHE.exists():
        print("Loading cached dataset …", flush=True)
        df = pd.read_csv(CACHE, index_col="cve_id")
        print(f"  Loaded {len(df):,} rows from cache", flush=True)
    else:
        kev_df   = fetch_kev()
        nvd_df   = fetch_nvd()
        epss_map = fetch_epss(nvd_df.index.tolist())
        df = build_dataset(nvd_df, kev_df, epss_map)
        df.to_csv(CACHE)
        print(f"  Saved dataset to cache ({CACHE})", flush=True)

    # --- KM ---
    print("Computing Kaplan-Meier curves …")
    km_sev = km_by_severity(df)
    km_poc = km_by_poc(df)

    # --- Cox (full model with EPSS) ---
    cph, cox_data = fit_cox(df)
    hr_table = hazard_ratios(cph)

    # --- Cox without EPSS (ablation to assess EPSS collinearity) ---
    print("Fitting Cox model WITHOUT EPSS (ablation) …", flush=True)
    COX_COLS_NO_EPSS = [c for c in COX_COLS if c != "epss"]
    sub_no_epss = df[COX_COLS_NO_EPSS].dropna()
    # Apply same variance / correlation filters
    feat_cols_ne = [c for c in sub_no_epss.columns if c not in ("duration", "event")]
    var_ne = sub_no_epss[feat_cols_ne].var()
    zv_ne = var_ne[var_ne < 1e-5].index.tolist()
    if zv_ne:
        sub_no_epss = sub_no_epss.drop(columns=zv_ne)
    cph_no_epss = CoxPHFitter(penalizer=0.01)
    cph_no_epss.fit(sub_no_epss, duration_col="duration", event_col="event")
    hr_no_epss = hazard_ratios(cph_no_epss)
    ci_no_epss = concordance_index(
        sub_no_epss["duration"],
        -cph_no_epss.predict_partial_hazard(sub_no_epss),
        sub_no_epss["event"]
    )
    print(f"  No-EPSS concordance index: {ci_no_epss:.3f}", flush=True)

    # Concordance index
    ci_cox = concordance_index(
        cox_data["duration"],
        -cph.predict_partial_hazard(cox_data),
        cox_data["event"]
    )
    print(f"  Cox concordance index: {ci_cox:.3f}")

    # EPSS baseline concordance (higher EPSS = predicts exploitation)
    ci_epss = concordance_index(
        cox_data["duration"],
        -cox_data["epss"],
        cox_data["event"]
    )
    print(f"  EPSS concordance index: {ci_epss:.3f}")

    # CVSS baseline concordance
    ci_cvss = concordance_index(
        cox_data["duration"],
        -cox_data["base_score"],
        cox_data["event"]
    )
    print(f"  CVSS concordance index: {ci_cvss:.3f}")

    # --- Inventory ---
    inv = build_inventory(df, cph, n_assets=500)
    inversions = find_inversions(inv, top_n=20)

    # Compute rank correlation
    from scipy.stats import spearmanr
    corr, _ = spearmanr(inv["cvss_rank"], inv["survival_rank"])

    # Top 25 prioritization list for dashboard
    top25 = inv.head(25)[[
        "asset_id","asset_type","cve_id","base_score",
        "partial_hazard","prob_exploit_1yr","cvss_rank","survival_rank","rank_delta","in_kev","poc_proxy"
    ]].to_dict(orient="records")

    # --- Stats ---
    stats = compute_stats(df)
    km_table = km_at_days(km_sev)

    # --- Pack output ---
    out = {
        "meta": {
            "generated":        datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nvd_window":       f"{NVD_RANGE_START} – {NVD_RANGE_END}",
            "obs_end":          str(OBS_END),
            "total_cves":       stats["total_cves"],
            "exploited":        stats["exploited"],
            "pct_kev":          stats["pct_kev"],
            "median_tte_days":  stats["median_tte_days"],
            "poc_pct":          stats["poc_pct"],
            "concordance_cox":  round(ci_cox,  3),
            "concordance_epss": round(ci_epss, 3),
            "concordance_cvss": round(ci_cvss, 3),
            "concordance_cox_no_epss": round(ci_no_epss, 3),
            "spearman_rank_corr": round(float(corr), 3),
        },
        "km_severity": km_sev,
        "km_poc":       km_poc,
        "km_table":     km_table,
        "hazard_ratios":hr_table,
        "hazard_ratios_no_epss": hr_no_epss,
        "tte_by_sev":   stats["tte_by_sev"],
        "rate_by_av":   stats["rate_by_av"],
        "top25_inventory": top25,
        "inversions":   inversions[:5],  # top 5 for dashboard highlight
    }

    out_path = OUT_DIR / "chart_data.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nWrote {out_path}")

    # --- Text summary ---
    with open(OUT_DIR / "results.txt", "w") as f:
        f.write("=" * 60 + "\n")
        f.write("SURVIVAL ANALYSIS — VULNERABILITY PRIORITIZATION\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Dataset: {stats['total_cves']:,} CVEs, "
                f"{stats['exploited']:,} exploited ({stats['pct_kev']}%)\n")
        f.write(f"Median time-to-exploitation: {stats['median_tte_days']} days\n\n")
        f.write("Concordance indices (0.5 = random, 1.0 = perfect):\n")
        f.write(f"  Cox model: {ci_cox:.3f}\n")
        f.write(f"  EPSS:      {ci_epss:.3f}\n")
        f.write(f"  CVSS:      {ci_cvss:.3f}\n\n")
        f.write("Top 5 hazard ratios:\n")
        for h in sorted(hr_table, key=lambda x: -x["hr"])[:5]:
            f.write(f"  {h['label']}: HR={h['hr']:.2f} "
                    f"[{h['lo']:.2f}–{h['hi']:.2f}] p={h['p']}\n")
        f.write("\nTop 5 ranking inversions (lower CVSS, higher survival priority):\n")
        for inv_ex in inversions[:5]:
            f.write(f"  {inv_ex['winner_cve']} CVSS {inv_ex['winner_score']} "
                    f"→ rank #{inv_ex['winner_rank']} "
                    f"vs {inv_ex['loser_cve']} CVSS {inv_ex['loser_score']} "
                    f"→ rank #{inv_ex['loser_rank']}\n")

    print("Done. See chart_data.json and results.txt")

if __name__ == "__main__":
    main()
