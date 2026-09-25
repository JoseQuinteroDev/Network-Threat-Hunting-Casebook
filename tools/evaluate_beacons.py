"""Evaluate tools/beacon_score.py on the nine Cobalt Strike captures with known configuration.

Ground truth comes from content the detector never sees: the Cobalt Strike check-ins are the HTTP requests
with a fixed /image/<id> URI and a spoofed Internet Explorer 8 user agent (Zeek http.log). Every
(client, server, port) pair that carries them is a beacon pair; every other pair is a negative.

Each capture is scored twice:
  raw         every pair the detector scores
  allowlist   operational scoping fixed before the evaluation (docs/methodology.md):
              - outbound only: private client to public server (this hunt is about internet C2)
              - NTP (udp/123) excluded
              - servers whose DNS name (from Zeek dns.log answers) is an OS connectivity-check or
                time-sync endpoint excluded (list below)

Usage:
    python tools/evaluate_beacons.py _private/zeek_published --out results/beaconing
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from beacon_score import THRESHOLD, score_capture  # noqa: E402
from zeeklog import read_zeek  # noqa: E402

CS_URI = re.compile(r"^/image/[a-p]{30,}")  # e.g. /image/bbelaichgojcbaeb...kok-.jpg
CS_UA = "MSIE 8.0; Windows NT 6.1"
KNOWN_PERIODIC = re.compile(
    r"(^|\.)(connectivity-check\.ubuntu\.com|ntp\.ubuntu\.com|msftconnecttest\.com|msftncsi\.com|"
    r"time\.windows\.com|pool\.ntp\.org|captive\.apple\.com|time\.apple\.com|connectivitycheck\.gstatic\.com|"
    r"clients3\.google\.com|time\.google\.com)$", re.I)
CONFIG = re.compile(r"(?P<kind>delay_var|jit_var|random|round_rob)(?:_r2)?_d(?P<d>\d+)_j(?P<j>\d+)")
HOURS = (1, 2, 6, 12, 24)


def beacon_pairs(capture: Path) -> set[tuple]:
    pairs = set()
    for r in read_zeek(capture, "http"):
        if CS_URI.match(r.get("uri") or "") and CS_UA in (r.get("user_agent") or ""):
            pairs.add((r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p")))
    return pairs


def dns_names(capture: Path) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for r in read_zeek(capture, "dns"):
        q = (r.get("query") or "").lower()
        for a in r.get("answers") or []:
            try:
                ipaddress.ip_address(a)
            except ValueError:
                continue
            names.setdefault(a, set()).add(q)
    return names


def in_scope(key: tuple, names: dict[str, set[str]]) -> bool:
    """True if a (client, server, port, protocol) key stays in scope after the operational allowlist."""
    src_ip, dst_ip, port, proto = key
    try:
        src, dst = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    if not (src.is_private and dst.is_global):
        return False
    if proto == "udp" and port == 123:
        return False
    return not any(KNOWN_PERIODIC.search(n) for n in names.get(dst_ip, ()))


def is_beacon(unit: dict, truth: set[tuple]) -> bool:
    return any((unit["src"], d, unit["port"]) in truth for d in unit["members"])


def summarise(ranked: list[dict], truth: set[tuple], names: dict[str, set[str]]) -> dict:
    flags = [is_beacon(u, truth) for u in ranked]
    b_scores = [u["score"] for u, b in zip(ranked, flags) if b]
    negatives = [u for u, b in zip(ranked, flags) if not b]
    describe = lambda u: ({k: u[k] for k in ("src", "dst", "port", "proto", "score", "median_gap_s")}
                          | {"names": sorted({n for d in u["members"] for n in names.get(d, ())})[:3]})
    return {"units": len(ranked),
            "beacon_ranks": [i + 1 for i, b in enumerate(flags) if b],
            "beacon_scores": b_scores,
            "beacon_flagged": sum(1 for s in b_scores if s >= THRESHOLD),
            "negatives": len(negatives),
            "false_positives": sum(1 for u in negatives if u["flagged"]),
            "top_negative": describe(negatives[0]) if negatives else None,
            "top_fp": [describe(u) for u in negatives if u["flagged"]][:6]}


def evaluate(capture: Path) -> dict:
    m = CONFIG.search(capture.name)
    truth = beacon_pairs(capture)
    names = dns_names(capture)
    keep = lambda key: in_scope(key, names)
    result = {"capture": capture.name,
              "rotation": {"delay_var": "none", "jit_var": "none", "random": "random, 2 redirectors",
                           "round_rob": "round robin, 2 redirectors"}[m["kind"]],
              "delay_s": int(m["d"]), "jitter_pct": int(m["j"]), "beacon_pairs": len(truth)}
    for mode in ("pair", "channel"):
        result[mode] = {"raw": summarise(score_capture(capture, mode=mode), truth, names),
                        "allowlist": summarise(score_capture(capture, mode=mode, keep=keep), truth, names)}
        early = {}
        for h in HOURS:
            s = summarise(score_capture(capture, max_hours=h, mode=mode, keep=keep), truth, names)
            early[h] = {k: s[k] for k in ("beacon_flagged", "beacon_scores", "false_positives", "negatives")}
        result[mode]["first_hours"] = early
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path, help="directory with one sub-directory of Zeek logs per capture")
    ap.add_argument("--out", type=Path, default=Path("results/beaconing"))
    ap.add_argument("--only", default="", help="regular expression the capture directory name must match")
    args = ap.parse_args()
    has_logs = lambda d: any(p.name.split(".")[0] == "conn" for p in d.iterdir())
    wanted = re.compile(args.only)
    captures = sorted((d for d in args.root.iterdir()
                       if d.is_dir() and CONFIG.search(d.name) and wanted.search(d.name) and has_logs(d)),
                      key=lambda d: (d.name.split("_d")[0], int(CONFIG.search(d.name)["d"]),
                                     int(CONFIG.search(d.name)["j"])))
    results = [evaluate(c) for c in captures]
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "evaluation.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    with open(args.out / "evaluation.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["capture", "rotation", "delay_s", "jitter_pct", "mode", "scope", "units", "beacon_best_rank",
                    "beacon_best_score", "beacon_flagged", "negatives", "false_positives"]
                   + [f"flagged_first_{h}h" for h in HOURS])
        for r in results:
            for mode in ("pair", "channel"):
                for scope in ("raw", "allowlist"):
                    s = r[mode][scope]
                    early = [r[mode]["first_hours"][h]["beacon_flagged"] if scope == "allowlist" else ""
                             for h in HOURS]
                    w.writerow([r["capture"], r["rotation"], r["delay_s"], r["jitter_pct"], mode, scope, s["units"],
                                min(s["beacon_ranks"], default=""), max(s["beacon_scores"], default=""),
                                s["beacon_flagged"], s["negatives"], s["false_positives"]] + early)
    for mode in ("pair", "channel"):
        print(f"\n== mode: {mode}")
        print(f"{'capture':22} {'rotation':26} {'D':>4} {'j%':>3} | {'raw rank':>8} {'FP':>3} | "
              f"{'allow rank':>10} {'score':>6} {'flag':>4} {'FP':>3} {'neg':>4} | flagged in first 1/2/6/12/24 h")
        for r in results:
            a, s = r[mode]["raw"], r[mode]["allowlist"]
            fh = "/".join(str(r[mode]["first_hours"][h]["beacon_flagged"]) for h in HOURS)
            print(f"{r['capture']:22} {r['rotation']:26} {r['delay_s']:4} {r['jitter_pct']:3} | "
                  f"{str(a['beacon_ranks'][:2]):>8} {a['false_positives']:3} | {str(s['beacon_ranks'][:2]):>10} "
                  f"{max(s['beacon_scores'], default=0):6} {s['beacon_flagged']:4} {s['false_positives']:3} "
                  f"{s['negatives']:4} | {fh}")


if __name__ == "__main__":
    main()
