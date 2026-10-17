#!/usr/bin/env python3
"""
run_matrix.py
-------------
Enumerate the TRUST-MANET scenario matrix and run the compiled ns-3 program
once per (sim-factor combination x seed). Raw outputs (<run_id>_nodes.csv,
<run_id>_edges.csv, <run_id>_meta.json) are written into --out.

Prereq: build the simulator first with scripts/build_ns3.sh.

Examples
--------
# fast screening pass (36 runs) to validate the pipeline:
python scripts/run_matrix.py --ns3-dir ./ns-3-dev --which screening --out raw/

# full matrix (450 runs) -- long; use --resume to restart safely:
python scripts/run_matrix.py --ns3-dir ./ns-3-dev --which full --out raw/ --resume
"""
import argparse
import math
import os
import subprocess
import sys
import csv

try:
    import yaml
except ImportError:
    sys.exit("PyYAML missing. Run: pip install -r requirements.txt")


def enumerate_runs(cfg, which):
    m = cfg[which]
    fixed = cfg["fixed"]
    runs = []
    for n in m["sim_factors"]["n_nodes"]:
        for speed in m["sim_factors"]["speed"]:
            for atk in m["sim_factors"]["attack"]:
                for seed in m["seeds"]:
                    attack_type = atk["attack_type"]
                    cfrac = float(atk["compromised_frac"])
                    scenario_id = f"n{n}_s{speed}_{attack_type}_c{cfrac:.2f}"
                    run_id = f"{scenario_id}_seed{seed}"
                    # derived
                    area = n * float(fixed["density_m2_per_node"])
                    side = round(math.sqrt(area), 1)
                    n_flows = max(1, round(fixed["n_flows_per_25_nodes"] * n / 25.0))
                    runs.append(
                        dict(
                            run_id=run_id,
                            scenario_id=scenario_id,
                            n_nodes=n,
                            speed=speed,
                            attack_type=attack_type,
                            compromised_frac=cfrac,
                            seed=seed,
                            area_x=side,
                            area_y=side,
                            n_flows=n_flows,
                        )
                    )
    return runs, fixed


def build_cmd(run, fixed, out_dir):
    prefix = os.path.join(os.path.abspath(out_dir), run["run_id"])
    args = [
        f"--nNodes={run['n_nodes']}",
        f"--speed={run['speed']}",
        f"--attackType={run['attack_type']}",
        f"--compromisedFrac={run['compromised_frac']}",
        f"--grayholeDropProb={fixed['grayhole_drop_prob']}",
        f"--nFlows={run['n_flows']}",
        f"--simTime={fixed['sim_time']}",
        f"--windowSec={fixed['window_sec']}",
        f"--attackStart={fixed['attack_start']}",
        f"--appStart={fixed['app_start']}",
        f"--areaX={run['area_x']}",
        f"--areaY={run['area_y']}",
        f"--rangeM={fixed['range_m']}",
        f"--seed={run['seed']}",
        f"--outPrefix={prefix}",
    ]
    return prefix, "trust-manet " + " ".join(args)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ns3-dir", required=True, help="Path to the built ns-3 tree")
    ap.add_argument("--matrix", default="scenario_matrix.yaml")
    ap.add_argument("--which", default="screening", choices=["full", "screening"])
    ap.add_argument("--out", default="raw", help="Output dir for raw run files")
    ap.add_argument("--limit", type=int, default=0, help="Run only the first N (0 = all)")
    ap.add_argument("--resume", action="store_true", help="Skip runs whose _meta.json exists")
    ap.add_argument("--dry-run", action="store_true", help="Print commands, do not execute")
    args = ap.parse_args()

    with open(args.matrix) as fh:
        cfg = yaml.safe_load(fh)

    os.makedirs(args.out, exist_ok=True)
    runs, fixed = enumerate_runs(cfg, args.which)
    if args.limit:
        runs = runs[: args.limit]

    # write the run index
    idx_path = os.path.join(args.out, "run_index.csv")
    with open(idx_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(runs[0].keys()))
        w.writeheader()
        w.writerows(runs)
    print(f"{len(runs)} runs enumerated -> {idx_path}")

    ns3 = os.path.abspath(args.ns3_dir)
    ok, skipped, failed = 0, 0, 0
    for i, run in enumerate(runs, 1):
        prefix, program = build_cmd(run, fixed, args.out)
        meta = prefix + "_meta.json"
        if args.resume and os.path.exists(meta):
            skipped += 1
            continue
        cmd = ["./ns3", "run", "--no-build", program]
        print(f"[{i}/{len(runs)}] {run['run_id']}")
        if args.dry_run:
            print("   ", " ".join(cmd))
            continue
        r = subprocess.run(cmd, cwd=ns3)
        if r.returncode == 0 and os.path.exists(meta):
            ok += 1
        else:
            failed += 1
            print(f"   !! run failed (rc={r.returncode})")

    print(f"\nDone. ok={ok} skipped={skipped} failed={failed}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
