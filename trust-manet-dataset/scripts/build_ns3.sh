#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build_ns3.sh : fetch a pinned ns-3, install the TRUST-MANET scratch program,
#                and build only the modules we need (fast even on 1 core).
#
# Usage:
#   bash scripts/build_ns3.sh [NS3_DIR] [NS3_VERSION]
#
#   NS3_DIR      where to clone ns-3   (default: ./ns-3-dev)
#   NS3_VERSION  git tag to check out  (default: ns-3.42)
#
# After this finishes, run the matrix with scripts/run_matrix.py.
# ---------------------------------------------------------------------------
set -euo pipefail

NS3_DIR="${1:-$(pwd)/ns-3-dev}"
NS3_VERSION="${2:-ns-3.42}"
REPO="https://github.com/nsnam/ns-3-dev-git.git"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # project root

echo "==> Checking build prerequisites"
missing=()
for t in git g++ cmake python3 make; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: missing tools: ${missing[*]}"
  echo "On Ubuntu/Debian:  sudo apt-get update && sudo apt-get install -y git g++ cmake python3 make"
  exit 1
fi

# Clone when there's no real git checkout yet. Checking for .git (not just the
# directory) means a pre-created empty dir or a half-finished clone won't block it.
if [ ! -d "$NS3_DIR/.git" ]; then
  echo "==> Cloning ns-3 ($NS3_VERSION) into $NS3_DIR"
  rm -rf "$NS3_DIR"
  git clone "$REPO" "$NS3_DIR"
fi

cd "$NS3_DIR"
echo "==> Checking out $NS3_VERSION"
git fetch --tags --quiet || true
git checkout "$NS3_VERSION"

echo "==> Installing TRUST-MANET scratch program"
mkdir -p scratch/trust-manet
# Name the main file after the directory so the run target is simply 'trust-manet'.
cp "$HERE/ns3/trust-manet-sim.cc"   scratch/trust-manet/trust-manet.cc
cp "$HERE/ns3/malicious-routing.cc" scratch/trust-manet/
cp "$HERE/ns3/malicious-routing.h"  scratch/trust-manet/
rm -f scratch/trust-manet/trust-manet-sim.cc   # drop any stale duplicate main

echo "==> Configuring (optimized, minimal module set)"
# NOTE: ns-3 expects a SEMICOLON-separated, quoted module list; dependencies are
# resolved automatically. Limiting modules cuts build time/memory. Add modules
# here if you extend the simulation (e.g. flow-monitor, energy).
./ns3 clean || true
./ns3 configure -d optimized \
  --enable-modules='core;network;internet;wifi;mobility;aodv;applications;propagation' \
  --disable-examples --disable-tests

echo "==> Building"
# Builds the enabled libraries + the scratch program. (Building by explicit
# target name is avoided because the short name is not accepted on every version.)
./ns3 build

echo
echo "==> Done. ns-3 is at: $NS3_DIR"
echo "    Smoke test:"
echo "    (cd \"$NS3_DIR\" && ./ns3 run \"trust-manet --nNodes=25 --attackType=blackhole --simTime=60 --outPrefix=/tmp/smoke\")"
