"""Out-of-sample check of the triage step: build an allowlist from some captures, test it on others.

In production, the pairs a beacon hunt flags are triaged and the benign periodic services that come up
(vendor telemetry, update services, chat keep-alives) are allowlisted. Measuring the false-positive rate
after that step on the same captures would be in-sample. Here the allowlist is built from the false
positives of a TRAIN set of captures (exact DNS names only, no wildcard widening) and applied unchanged to
a TEST set.

Usage:
    python tools/beacon_triage_split.py _private/zeek_published --out results/beaconing
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from beacon_score import score_capture  # noqa: E402
from evaluate_beacons import beacon_pairs, dns_names, in_scope, summarise  # noqa: E402

TRAIN = ["delay_var_d10_j25", "delay_var_d30_j25", "delay_var_d300_j25", "jit_var_d30_j0"]
TEST = ["jit_var_d30_j10", "jit_var_d30_j99", "random_d30_j0", "random_d30_j25", "round_rob_d30_j25"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument("--mode", choices=("pair", "channel"), default="channel")
    ap.add_argument("--out", type=Path, default=Path("results/beaconing"))
    args = ap.parse_args()

    learned: set[str] = set()
    for name in TRAIN:
        cap = args.root / name
        truth, names = beacon_pairs(cap), dns_names(cap)
        ranked = score_capture(cap, mode=args.mode, keep=lambda k: in_scope(k, names))
        for u in ranked:
            beacon = any((u["src"], d, u["port"]) in truth for d in u["members"])
            if u["flagged"] and not beacon:
                for d in u["members"]:
                    learned |= names.get(d, set())

    report = {"mode": args.mode, "train": TRAIN, "test": TEST, "learned_allowlist": sorted(learned), "test_results": []}
    print(f"allowlist learned from {len(TRAIN)} train captures ({args.mode} mode): {len(learned)} names")
    for n in sorted(learned):
        print("   ", n)
    print(f"\n{'test capture':22} {'beacon flagged':>14} {'best rank':>9} {'FP before':>9} {'FP after':>8} {'negatives':>9}")
    for name in TEST:
        cap = args.root / name
        truth, names = beacon_pairs(cap), dns_names(cap)
        base = lambda k: in_scope(k, names)
        triaged = lambda k: in_scope(k, names) and not (names.get(k[1], set()) & learned)
        before = summarise(score_capture(cap, mode=args.mode, keep=base), truth, names)
        after = summarise(score_capture(cap, mode=args.mode, keep=triaged), truth, names)
        report["test_results"].append({"capture": name, "before": before, "after": after})
        print(f"{name:22} {after['beacon_flagged']:14} {str(min(after['beacon_ranks'], default='-')):>9} "
              f"{before['false_positives']:9} {after['false_positives']:8} {after['negatives']:9}")
        for fp in after["top_fp"]:
            print(f"      remaining FP: {fp['dst']}:{fp['port']} score {fp['score']} names {fp['names']}")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"triage_split_{args.mode}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
