# TrustManet-AdHocNetworks

**Trust-aware intrusion detection for Mobile Ad Hoc Networks (MANETs), built on an ns-3 simulated dataset.**

**Author:** Sunawar Khan

---

## Overview

Mobile ad hoc networks have no fixed infrastructure, so every node must rely on its neighbours to forward packets. This makes them vulnerable to *packet-dropping* insiders (blackhole and grayhole nodes) and to *dishonest reporters* that poison cooperative trust schemes through bad-mouthing and ballot-stuffing.

This repository provides an end-to-end pipeline that:

1. **Simulates** AODV-based MANETs in ns-3 with configurable blackhole / grayhole attackers.
2. **Builds a dataset** where each row is an *(observer, observed neighbour, time window)* triple, with mobility, link, forwarding and trust-report features.
3. **Trains an IDS** (LightGBM) using only local evidence, then adds neighbour-reported trust evidence.
4. **Hardens trust fusion** against colluding false reporters with an iterative, sensing-anchored reputation layer.

Everything is runnable end-to-end from the notebook `adhoc-trustmanet.ipynb` (Kaggle / Colab / local Linux).

## Key ideas

- **Watchdog-style observation** (monitoring whether a neighbour forwards packets), with Gaussian observation noise to model imperfect overhearing.
- **Reputation / trust reports** exchanged between observers, in the spirit of CONFIDANT and CORE.
- **Adversarial reporters:** a configurable fraction of observers lie (bad-mouthing benign nodes, ballot-stuffing malicious nodes).
- **Leakage-safe evaluation:** whole simulation runs / scenario configurations are assigned to a single split; cross-validation is grouped by scenario.
- **Honest anchor:** the iterative trust layer anchors consensus on pure sensing features (which a dishonest *reporter* does not fabricate), in a truth-discovery style.

## Repository structure

```
TrustManet-AdHocNetworks/
├── adhoc-trustmanet.ipynb          # full pipeline notebook (writes all sources below)
├── trust-manet-dataset/
│   ├── ns3/
│   │   ├── trust-manet-sim.cc      # main ns-3 scenario (AODV, mobility, traffic)
│   │   ├── malicious-routing.h     # blackhole / grayhole routing extension
│   │   └── malicious-routing.cc
│   ├── scripts/
│   │   ├── build_ns3.sh            # fetch + build pinned ns-3 (default ns-3.42)
│   │   ├── run_matrix.py           # run the scenario matrix in ns-3
│   │   ├── build_dataset.py        # raw logs -> Parquet dataset
│   │   ├── split_dataset.py        # leakage-safe train/val/test split
│   │   ├── train_ids.py            # LightGBM IDS + evaluation + plots
│   │   └── trust_iterative.py      # iterative anchored trust fusion
│   ├── scenario_matrix.yaml        # full (450 runs) and screening (36 runs) matrices
│   └── requirements.txt
├── dataset/                        # part-*.parquet + trust_manet_dataset.parquet
├── dataset_split/                  # same parts with an added `split` column
└── ids_results/
    ├── metrics.json
    ├── tables/                     # CSV / JSON result tables
    └── figures/                    # ROC, PR, confusion matrices, etc.
```

## Dataset

The bundled dataset was generated with the **screening matrix**.

| Item | Value |
|---|---|
| Rows | 182,064 |
| Columns | 38 |
| Simulation runs | 36 (12 scenarios × 3 seeds) |
| Node counts | 25, 50 |
| Node speed | 0 m/s (static), 15 m/s |
| Attacks | clean (0 %), blackhole (20 %), grayhole (20 %) |
| Corrupt-reporter fraction | 0.00, 0.40 (applied in post-processing, no re-simulation) |
| Simulation length / window | 200 s / 5 s |
| Malicious-target rate | ≈ 12.96 % |
| Split (rows) | train 121,376 / val 35,728 / test 24,960 |

The **full matrix** (`which: full`) covers 3 node counts × 3 speeds × 5 attack settings × 10 seeds = 450 ns-3 runs (1,350 logical scenarios with the three corrupt-reporter fractions).

### Feature groups

| Group | Columns |
|---|---|
| Mobility | `dist`, `rel_speed`, `neighbor_churn`, `contact_lifetime_win`, `contact_lifetime_s` |
| Link | `rssi_proxy_dbm`, `link_quality_proxy` |
| Forwarding / routing | `observed_fwd_ratio`, `obs_confidence`, `missing_ack_ratio`, `tgt_transit_load`, `tgt_no_route`, `route_reachability` |
| Reports | `reported_risk`, `report_age_s`, `has_report`, `observer_consistency` |
| Trust aggregates (other observers) | `rep_count_others`, `mean_reported_risk_others`, `mean_report_age_others`, `mean_observer_consistency_others` |
| Targets / metadata | `tgt_malicious`, `attack_type`, `tgt_drop_attack_true`, `is_false_accusation`, `scenario_id`, `run_id`, `seed`, `split` |

> **Note:** `rssi_proxy_dbm` is a *distance-based log-distance path-loss proxy*, not a measured RSSI. Labels come only from simulator ground truth; the watchdog forward-ratio seen by an observer is noised and used as a feature.

## Installation

```bash
git clone https://github.com/SunawarKhan/TrustManet-AdHocNetworks.git
cd TrustManet-AdHocNetworks/trust-manet-dataset

pip install -r requirements.txt
pip install lightgbm scikit-learn        # needed for the IDS
```

To regenerate the data you also need a C++ toolchain:

```bash
sudo apt-get update && sudo apt-get install -y git g++ cmake python3 make
```

## Usage

```bash
# 1) Build ns-3 (pinned tag, default ns-3.42) and install the scratch program
bash scripts/build_ns3.sh ./ns-3-dev ns-3.42

# 2) Run simulations
python scripts/run_matrix.py --ns3-dir ./ns-3-dev --which screening --out raw/
#    full matrix (long): add  --which full --resume

# 3) Build the Parquet dataset
python scripts/build_dataset.py --raw raw/ --out dataset/ --matrix scenario_matrix.yaml

# 4) Leakage-safe split ('run' or 'config' mode)
python scripts/split_dataset.py --dataset dataset/ --out dataset_split/ --mode config

# 5) Train and evaluate the IDS (5-fold, grouped by scenario)
python scripts/train_ids.py --dataset dataset/ --out ids_results/

# 6) Iterative anchored trust fusion
python scripts/trust_iterative.py --dataset dataset/ --out ids_results/ --alpha 0.5
```

Prefer a single entry point? Open `adhoc-trustmanet.ipynb` on Kaggle, Colab or a local Linux machine; it auto-detects the environment and runs all steps.

## Method

**Local detector.** A LightGBM classifier (400 trees, 63 leaves, class-balanced) is trained on local features only, with `GroupKFold` over scenarios to produce out-of-fold predictions.

**Local + trust detector.** The same model additionally receives the neighbour-report aggregates (`rep_count_others`, `mean_reported_risk_others`, …).

**Iterative anchored trust.** For each neighbour *j*, consensus is

`consensus_j = α · anchor_j + (1 − α) · WeightedMedian{ r_kj ; w_k }`

where `anchor_j` is the median of honest local-detector readings (built only from sensing features) and `r_kj` are reports from other observers *k*. Reporter weights are updated as `w_k ← exp(−γ · median_j |r_kj − consensus_j|)` and iterated to convergence, driving systematic colluders toward zero weight.

## Results

All numbers below are read from `ids_results/` (out-of-fold, grouped by scenario).

### Detector comparison

| Model / view | ROC-AUC | PR-AUC | Precision | Recall | F1 | False-accusation rate |
|---|---|---|---|---|---|---|
| Local (window) | 0.725 | 0.447 | 0.381 | 0.488 | 0.428 | 0.118 |
| Local + trust (window) | 0.832 | 0.623 | 0.937 | 0.398 | 0.558 | 0.0040 |
| Local + trust (observable windows) | 0.977 | 0.943 | 0.975 | 0.861 | 0.914 | 0.0037 |
| Local + trust (node level, q90) | 0.884 | 0.874 | 0.925 | 0.850 | 0.886 | 0.0108 |
| Local + trust (node level, max) | 0.882 | 0.873 | 0.861 | 0.850 | 0.855 | 0.0217 |

Adding trust evidence cuts the false-accusation rate from about 11.8 % to 0.4 %, at the cost of lower window-level recall. Aggregating to node level recovers recall (≈ 0.85).

### Per attack type (local + trust, window level)

| Attack | ROC-AUC | Precision | Recall | F1 |
|---|---|---|---|---|
| Blackhole | 0.860 | 0.9996 | 0.400 | 0.571 |
| Grayhole | 0.857 | 1.000 | 0.396 | 0.567 |

### Trust fusion under corrupt reporters

| Method | Corrupt fraction | ROC-AUC | F1 | False-accusation rate |
|---|---|---|---|---|
| Naive mean | 0.00 | 0.974 | 0.789 | 0.000 |
| Weighted median (one-shot) | 0.00 | 0.976 | 0.805 | 0.000 |
| Weighted median (one-shot) | 0.40 | 0.016 | 0.002 | 0.988 |
| Naive mean | 0.40 | – | 0.001 | 0.991 |

(from `tables/trust_fusion.csv`, 348 targets). With 40 % colluding reporters, plain aggregation collapses.

A separate evaluation of the iterative layer (`tables/trust_iterative.json`, 41,019 targets) shows the anchored variant stays stable as corruption rises, while one-shot and mean fusion degrade:

| Method | ROC-AUC @ 0.00 | ROC-AUC @ 0.40 | F1 @ 0.40 |
|---|---|---|---|
| Iterative anchored | 0.554 | 0.552 | 0.289 |
| One-shot weighted median | 0.553 | 0.245 | 0.045 |
| Naive mean | 0.553 | 0.241 | 0.045 |

## Limitations and notes

- The shipped dataset is the **screening subset** (2 node counts, 2 speeds, 3 seeds); the full 450-run matrix has not been bundled.
- Static (`speed = 0`) scenarios give noticeably lower node-level recall (≈ 0.50–0.74) than mobile ones (1.00), likely because attackers in static topologies carry less transit traffic.
- The iterative anchored layer is robust to corruption but its absolute ROC-AUC in the 41k-target evaluation is modest (≈ 0.55); the anchor quality is the bottleneck.
- Results in `by_corrupt.csv` (window-level detector) show higher metrics at corrupt fraction 0.40 than at 0.00, which is counter-intuitive and merits further investigation before drawing conclusions.
- RSSI is a proxy computed from distance, not a real radio measurement.

## Roadmap

- [ ] Run and publish the full 450-run matrix (100-node, 5 m/s scenarios)
- [ ] Add more attacks (e.g. wormhole, on-off, Sybil)
- [ ] Compare against deep sequence models (GRU / Transformer)
- [ ] Real-trace validation

## Citation

If you use this repository, please cite:

```bibtex
@software{khan2026trustmanet,
  author = {Khan, Sunawar},
  title  = {{TrustManet-AdHocNetworks}: Trust-Aware Intrusion Detection for MANETs with ns-3},
  year   = {2026},
  url    = {https://github.com/SunawarKhan/TrustManet-AdHocNetworks}
}
```

## License

No license has been specified yet. Add a `LICENSE` file (e.g. MIT or Apache-2.0) before public reuse.

## Contact

**Sunawar Khan** — GitHub: [@SunawarKhan](https://github.com/SunawarKhan)
