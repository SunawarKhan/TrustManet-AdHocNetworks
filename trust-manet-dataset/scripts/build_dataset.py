#!/usr/bin/env python3
"""
build_dataset.py
----------------
Turn raw ns-3 run logs (from run_matrix.py) into the TRUST-MANET dataset:
one row per (observer i, observed neighbour j, time window t), with the five
feature groups from the proposal plus targets, written to Parquet.

For each run we:
  1. load per-window node measurements and 1-hop adjacency,
  2. build directed observer->neighbour pairs (i watches j),
  3. compute mobility / link / forwarding features,
  4. simulate honest + corrupt observer reports (bad-mouthing / ballot-stuffing)
     for every corrupt_reporter_frac in the matrix (NO re-simulation),
  5. aggregate other observers' reports about j,
  6. assign targets, and write one Parquet file per run into --out.

Only simulator-provided ground truth is used for LABELS; the watchdog
forward-ratio the observer "sees" is noised and is a FEATURE. Link RSSI is a
distance-based proxy and is named rssi_proxy_dbm accordingly (see the proposal:
mark approximations instead of inventing sensor access).

Usage:
  python scripts/build_dataset.py --raw raw/ --out dataset/ --matrix scenario_matrix.yaml
"""
import argparse
import glob
import json
import os
import sys
from collections import defaultdict

import numpy as np
import pandas as pd

try:
    import yaml
except ImportError:
    sys.exit("PyYAML missing. Run: pip install -r requirements.txt")

# ---- distance -> RSSI proxy (log-distance path loss; documented approximation)
PT_DBM = 16.0206   # ns-3 default Wi-Fi tx power
PL0_DB = 40.0      # reference path loss at d0
PL_EXP = 3.0       # path-loss exponent
D0 = 1.0
RSSI_MIN, RSSI_MAX = -95.0, -40.0


def rssi_proxy(dist):
    d = np.maximum(dist, D0)
    pl = PL0_DB + 10.0 * PL_EXP * np.log10(d / D0)
    return PT_DBM - pl


def link_quality(rssi):
    return np.clip((rssi - RSSI_MIN) / (RSSI_MAX - RSSI_MIN), 0.0, 1.0)


def neighbour_sets(edges):
    """window_idx -> {node: set(neighbours)} (undirected)."""
    adj = defaultdict(lambda: defaultdict(set))
    for w, i, j in edges[["window_idx", "i", "j"]].itertuples(index=False):
        adj[w][i].add(j)
        adj[w][j].add(i)
    return adj


def neighbour_churn(adj, windows):
    """(window_idx, node) -> churn = 1 - Jaccard(N_t, N_{t-1})."""
    churn = {}
    wsorted = sorted(windows)
    allnodes = set()
    for w in wsorted:
        allnodes |= set(adj[w].keys())
    for node in allnodes:
        prev = None
        for w in wsorted:
            cur = adj[w].get(node, set())
            if prev is None:
                churn[(w, node)] = 0.0
            else:
                union = prev | cur
                inter = prev & cur
                churn[(w, node)] = 0.0 if not union else 1.0 - len(inter) / len(union)
            prev = cur
    return churn


def process_run(meta_path, out_dir, post_fracs, rmodel):
    prefix = meta_path[: -len("_meta.json")]
    run_id = os.path.basename(prefix)
    with open(meta_path) as fh:
        meta = json.load(fh)

    nodes = pd.read_csv(prefix + "_nodes.csv")
    edges = pd.read_csv(prefix + "_edges.csv")
    if nodes.empty or edges.empty:
        print(f"  skip {run_id}: empty logs")
        return

    mal_set = set(meta.get("malicious_nodes", []))
    attack_type = meta["attack_type"]
    attack_start = float(meta["attack_start"])
    window_sec = float(meta["window_sec"])
    n_nodes = int(meta["n_nodes"])

    # --- per-node per-window derived quantities ------------------------------
    nodes["fwd_ratio_true"] = np.where(
        nodes["recv_forward"] > 0, nodes["fwd_ok"] / nodes["recv_forward"], np.nan
    )
    nodes["attack_active"] = (attack_type != "clean") & (nodes["time_s"] >= attack_start)
    nodes["is_mal_active"] = nodes["node"].isin(mal_set) & nodes["attack_active"]

    # window-level reachability (global PDR in the window)
    win_tot = nodes.groupby("window_idx").agg(
        app_tx_sum=("app_tx", "sum"), app_rx_sum=("app_rx", "sum")
    )
    win_tot["route_reachability"] = np.where(
        win_tot["app_tx_sum"] > 0, win_tot["app_rx_sum"] / win_tot["app_tx_sum"], np.nan
    ).clip(0, 1)

    windows = nodes["window_idx"].unique()
    adj = neighbour_sets(edges)
    churn = neighbour_churn(adj, windows)

    # --- directed observer->neighbour pairs ----------------------------------
    d1 = edges.rename(columns={"i": "obs", "j": "tgt"})
    d2 = edges.rename(columns={"i": "tgt", "j": "obs"})
    pairs = pd.concat([d1, d2], ignore_index=True)[["window_idx", "obs", "tgt", "dist"]]

    nf = nodes[
        ["window_idx", "node", "time_s", "vel_x", "vel_y", "speed",
         "fwd_ratio_true", "recv_forward", "fwd_drop_attack", "no_route",
         "is_mal_active"]
    ]
    pairs = pairs.merge(
        nf.add_suffix("_obs").rename(columns={"window_idx_obs": "window_idx", "node_obs": "obs"}),
        on=["window_idx", "obs"], how="left",
    )
    pairs = pairs.merge(
        nf.add_suffix("_tgt").rename(columns={"window_idx_tgt": "window_idx", "node_tgt": "tgt"}),
        on=["window_idx", "tgt"], how="left",
    )

    # ---- mobility features ----
    pairs["rel_speed"] = np.hypot(pairs["vel_x_obs"] - pairs["vel_x_tgt"],
                                  pairs["vel_y_obs"] - pairs["vel_y_tgt"])
    pairs["neighbor_churn"] = [churn.get((w, o), 0.0)
                               for w, o in zip(pairs["window_idx"], pairs["obs"])]

    # contact lifetime (consecutive windows the pair stays adjacent)
    pairs = pairs.sort_values(["obs", "tgt", "window_idx"]).reset_index(drop=True)
    wdiff = pairs.groupby(["obs", "tgt"])["window_idx"].diff()
    isnew = wdiff.ne(1.0)  # NaN (first in group) -> True
    runid = isnew.groupby([pairs["obs"], pairs["tgt"]]).cumsum()
    pairs["contact_lifetime_win"] = pairs.groupby(["obs", "tgt", runid]).cumcount() + 1
    pairs["contact_lifetime_s"] = pairs["contact_lifetime_win"] * window_sec

    # ---- link features (distance-based proxies) ----
    pairs["rssi_proxy_dbm"] = rssi_proxy(pairs["dist"].to_numpy())
    pairs["link_quality_proxy"] = link_quality(pairs["rssi_proxy_dbm"].to_numpy())

    # ---- forwarding features (watchdog view of the TARGET's behaviour) ----
    rng = np.random.default_rng(abs(hash(run_id)) % (2**32))
    base_ratio = pairs["fwd_ratio_true_tgt"].to_numpy()
    noise = rng.normal(0.0, rmodel["observation_sigma"], size=len(pairs))
    observed = np.clip(base_ratio + noise, 0.0, 1.0)
    enough = pairs["recv_forward_tgt"].to_numpy() >= rmodel["min_transit_for_obs"]
    observed = np.where(enough & ~np.isnan(base_ratio), observed, np.nan)
    pairs["observed_fwd_ratio"] = observed
    pairs["obs_confidence"] = np.where(enough & ~np.isnan(base_ratio),
                                       np.clip(pairs["recv_forward_tgt"] / 20.0, 0, 1), 0.0)
    pairs["missing_ack_ratio"] = np.where(np.isnan(observed), np.nan, 1.0 - observed)
    pairs["tgt_transit_load"] = pairs["recv_forward_tgt"]
    pairs["tgt_no_route"] = pairs["no_route_tgt"]

    # ---- targets ----
    pairs["tgt_malicious"] = pairs["is_mal_active_tgt"].fillna(False).astype(int)
    pairs["attack_type"] = attack_type
    pairs["tgt_drop_attack_true"] = pairs["fwd_drop_attack_tgt"].fillna(0)
    pairs = pairs.merge(win_tot[["route_reachability"]], on="window_idx", how="left")

    # scenario / key metadata
    pairs["run_id"] = run_id
    pairs["scenario_id"] = f"n{n_nodes}_s{meta['speed']}_{attack_type}_c{meta['compromised_frac']:.2f}"
    pairs["seed"] = meta["seed"]
    pairs["n_nodes"] = n_nodes
    pairs["speed"] = meta["speed"]
    pairs["compromised_frac"] = meta["compromised_frac"]
    pairs["time_s"] = pairs["time_s_obs"]

    frames = []
    for frac in post_fracs:
        frames.append(apply_reports(pairs.copy(), frac, n_nodes, meta["seed"], rmodel))
    out = pd.concat(frames, ignore_index=True)

    # drop intermediate suffix columns the consumer doesn't need
    drop = [c for c in out.columns if c.endswith("_obs") or c.endswith("_tgt")]
    keep_tgt = {"tgt"}  # keep the id
    drop = [c for c in drop if c not in keep_tgt]
    out = out.drop(columns=[c for c in drop if c in out.columns], errors="ignore")
    out = out.rename(columns={"obs": "observer_id", "tgt": "neighbor_id"})

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"part-{run_id}.parquet")
    out.to_parquet(out_path, index=False)
    print(f"  wrote {out_path}  rows={len(out)}")


def apply_reports(df, corrupt_frac, n_nodes, seed, rmodel):
    """Generate honest + corrupt observer reports for one corrupt_reporter_frac."""
    rng = np.random.default_rng((int(seed) * 1000003 + int(corrupt_frac * 1000)) % (2**32))

    n_corrupt = int(np.floor(corrupt_frac * n_nodes))
    corrupt_nodes = set(rng.choice(np.arange(n_nodes), size=n_corrupt, replace=False).tolist()) \
        if n_corrupt > 0 else set()

    obs = df["obs"].to_numpy()
    tgt_mal = df["tgt_malicious"].to_numpy().astype(bool)
    observed = df["observed_fwd_ratio"].to_numpy()

    # honest risk: high when the target appears to drop packets
    honest = np.where(np.isnan(observed), np.nan, np.clip(1.0 - observed, 0.0, 1.0))

    obs_corrupt = np.array([o in corrupt_nodes for o in obs])
    badmouth = rng.uniform(rmodel["badmouth_risk_min"], 1.0, size=len(df))
    ballot = rng.uniform(0.0, rmodel["ballotstuff_risk_max"], size=len(df))

    risk = honest.copy()
    # corrupt reporter bad-mouths benign targets (inflate risk)
    m_bad = obs_corrupt & ~tgt_mal
    risk = np.where(m_bad, np.maximum(np.nan_to_num(honest, nan=0.0), badmouth), risk)
    # corrupt reporter ballot-stuffs for malicious (colluding) targets (deflate)
    m_ball = obs_corrupt & tgt_mal
    risk = np.where(m_ball, np.minimum(np.nan_to_num(honest, nan=1.0), ballot), risk)

    df["corrupt_reporter_frac"] = corrupt_frac
    df["observer_is_corrupt"] = obs_corrupt.astype(int)
    df["reported_risk"] = risk
    # report freshness within the window (synthetic; models staleness jitter)
    df["report_age_s"] = rng.uniform(0.0, 5.0, size=len(df))
    df["has_report"] = (~np.isnan(risk)).astype(int)

    # ---- causal observer consistency: running agreement with ground truth ----
    df["agree"] = np.where(
        np.isnan(risk), np.nan, ((risk > 0.5).astype(float) == tgt_mal.astype(float)).astype(float)
    )
    df = df.sort_values(["obs", "window_idx"]).reset_index(drop=True)
    # mean agreement per (obs, window), then expanding mean over strictly-earlier windows
    ow = df.groupby(["obs", "window_idx"])["agree"].mean().reset_index(name="win_agree")
    ow = ow.sort_values(["obs", "window_idx"])
    ow["cum"] = ow.groupby("obs")["win_agree"].transform(
        lambda s: s.shift(1).expanding().mean()
    )
    ow["observer_consistency"] = ow["cum"].fillna(0.5)
    df = df.merge(ow[["obs", "window_idx", "observer_consistency"]],
                  on=["obs", "window_idx"], how="left")

    # ---- aggregate OTHER observers' reports about the target ----
    rep = df[df["has_report"] == 1]
    grp = rep.groupby(["window_idx", "tgt"]).agg(
        sum_risk=("reported_risk", "sum"),
        cnt=("reported_risk", "size"),
        sum_age=("report_age_s", "sum"),
        sum_cons=("observer_consistency", "sum"),
    ).reset_index()
    df = df.merge(grp, on=["window_idx", "tgt"], how="left")

    own_risk = np.where(df["has_report"] == 1, df["reported_risk"], 0.0)
    own_age = np.where(df["has_report"] == 1, df["report_age_s"], 0.0)
    own_cons = np.where(df["has_report"] == 1, df["observer_consistency"], 0.0)
    own_in = (df["has_report"] == 1).astype(float)

    others_cnt = (df["cnt"].fillna(0) - own_in).clip(lower=0)
    with np.errstate(invalid="ignore", divide="ignore"):
        df["rep_count_others"] = others_cnt
        df["mean_reported_risk_others"] = np.where(
            others_cnt > 0, (df["sum_risk"].fillna(0) - own_risk) / others_cnt, np.nan)
        df["mean_report_age_others"] = np.where(
            others_cnt > 0, (df["sum_age"].fillna(0) - own_age) / others_cnt, np.nan)
        df["mean_observer_consistency_others"] = np.where(
            others_cnt > 0, (df["sum_cons"].fillna(0) - own_cons) / others_cnt, np.nan)
        # all-observer mean risk about the target (incl. self) for false-accusation label
        mean_all = np.where(df["cnt"].fillna(0) > 0, df["sum_risk"].fillna(0) / df["cnt"], np.nan)

    # false accusation: benign target that the neighbourhood collectively flags
    df["is_false_accusation"] = (
        (df["tgt_malicious"] == 0) & (pd.Series(mean_all) > 0.5)
    ).astype(int)

    df = df.drop(columns=["sum_risk", "cnt", "sum_age", "sum_cons", "agree"], errors="ignore")
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", default="raw", help="Dir with raw ns-3 run files")
    ap.add_argument("--out", default="dataset", help="Output Parquet dir")
    ap.add_argument("--matrix", default="scenario_matrix.yaml")
    ap.add_argument("--which", default="screening", choices=["full", "screening"])
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    with open(args.matrix) as fh:
        cfg = yaml.safe_load(fh)
    post_fracs = cfg[args.which]["post_factors"]["corrupt_reporter_frac"]
    rmodel = cfg["report_model"]

    metas = sorted(glob.glob(os.path.join(args.raw, "*_meta.json")))
    if args.limit:
        metas = metas[: args.limit]
    if not metas:
        sys.exit(f"No *_meta.json found in {args.raw}. Run run_matrix.py first.")

    print(f"Building dataset from {len(metas)} runs x {len(post_fracs)} corrupt fracs")
    for mp in metas:
        process_run(mp, args.out, post_fracs, rmodel)

    print(f"\nDone. Parquet parts in {args.out}/  "
          f"(read with pandas.read_parquet or pyarrow.dataset)")


if __name__ == "__main__":
    main()
