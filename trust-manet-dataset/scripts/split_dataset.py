#!/usr/bin/env python3
"""
split_dataset.py
----------------
Assign a leakage-safe train/val/test split to the Parquet parts produced by
build_dataset.py. A whole simulation run (and, in 'config' mode, a whole
scenario configuration) is assigned to exactly ONE split, so no window from a
test scenario can appear in training/tuning -- as required by the proposal.

Modes:
  run     : split at the (scenario, seed) run level (default).
  config  : split at the scenario-config level -> test contains UNSEEN
            configurations (strictest cross-scenario generalization test).

Each input part is rewritten to --out with an added 'split' column.

Usage:
  python scripts/split_dataset.py --dataset dataset/ --out dataset_split/ --mode config
"""
import argparse
import glob
import os
import sys

import pandas as pd
import numpy as np


def key_of(part, mode):
    cols = ["run_id", "scenario_id"]
    head = pd.read_parquet(part, columns=cols)
    if head.empty:
        return None, None
    run_id = head["run_id"].iloc[0]
    scenario_id = head["scenario_id"].iloc[0]
    return run_id, scenario_id


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="dataset", help="Dir with part-*.parquet")
    ap.add_argument("--out", default="dataset_split")
    ap.add_argument("--mode", default="run", choices=["run", "config"])
    ap.add_argument("--ratios", type=float, nargs=3, default=[0.7, 0.15, 0.15],
                    metavar=("TRAIN", "VAL", "TEST"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    parts = sorted(glob.glob(os.path.join(args.dataset, "part-*.parquet")))
    if not parts:
        sys.exit(f"No part-*.parquet in {args.dataset}. Run build_dataset.py first.")

    # map each part to its grouping key
    part_keys = {}
    keyset = set()
    for p in parts:
        run_id, scenario_id = key_of(p, args.mode)
        if run_id is None:
            continue
        key = scenario_id if args.mode == "config" else run_id
        part_keys[p] = key
        keyset.add(key)

    keys = sorted(keyset)
    rng = np.random.default_rng(args.seed)
    rng.shuffle(keys)
    n = len(keys)
    n_tr = int(round(args.ratios[0] * n))
    n_va = int(round(args.ratios[1] * n))
    split_map = {}
    for i, k in enumerate(keys):
        split_map[k] = "train" if i < n_tr else ("val" if i < n_tr + n_va else "test")

    counts = {"train": 0, "val": 0, "test": 0}
    os.makedirs(args.out, exist_ok=True)
    for p, key in part_keys.items():
        split = split_map[key]
        counts[split] += 1
        df = pd.read_parquet(p)
        df["split"] = split
        df.to_parquet(os.path.join(args.out, os.path.basename(p)), index=False)

    print(f"Split by {args.mode}: {n} groups -> "
          f"train={n_tr} val={n_va} test={n - n_tr - n_va}")
    print(f"Part files per split: {counts}")
    print(f"Wrote split parts to {args.out}/ (added 'split' column)")


if __name__ == "__main__":
    main()
