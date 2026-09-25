"""Summarise Suricata alerts per capture and separate the ones that touch a known malicious flow.

Reads alerts.json (or eve.json) from each _private/suricata/<capture>/ directory. An alert "touches the beacon"
when one side is the victim and the other is a C2 server or redirector of that capture (ground truth from
tools/evaluate_beacons.py, i.e. from the Cobalt Strike HTTP check-ins in Zeek's http.log).

Usage:
    python tools/suricata_summary.py --out results/beaconing/et_open_alerts.json
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from evaluate_beacons import beacon_pairs  # noqa: E402

ZEEK_FOR = {  # Suricata output directory -> published Zeek logs used as ground truth
    "delay_var_d10_j25_24h": "delay_var_d10_j25", "delay_var_d30_j25_24h": "delay_var_d30_j25",
    "delay_var_d300_j25_24h": "delay_var_d300_j25", "jit_var_d30_j0_24h": "jit_var_d30_j0",
    "jit_var_d30_j10_24h": "jit_var_d30_j10", "jit_var_d30_j99_24h": "jit_var_d30_j99",
    "random_d30_j0_24h": "random_d30_j0", "random_d30_j25_24h": "random_d30_j25",
    "round_rob_r2_d30_j25_24h": "round_rob_d30_j25",
}


def alerts(directory: Path):
    """Alert events, de-duplicated: Suricata appends to an existing eve.json, so a capture processed twice
    would otherwise count every alert twice."""
    f = directory / "alerts.json"
    if not f.exists():
        f = directory / "eve.json"
    seen = set()
    with open(f, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            a = json.loads(line)
            # flow_id is random per run, so it cannot identify a duplicate; the packet number can.
            key = (a.get("timestamp"), a.get("pcap_cnt"), a["alert"].get("signature_id"), a.get("src_ip"),
                   a.get("src_port"), a.get("dest_ip"), a.get("dest_port"))
            if key in seen:
                continue
            seen.add(key)
            yield a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "results/beaconing/et_open_alerts.json")
    args = ap.parse_args()
    report = []
    for sdir, zdir in ZEEK_FOR.items():
        d = ROOT / "_private/suricata" / sdir
        if not d.exists() or not any((d / n).exists() for n in ("alerts.json", "eve.json")):
            print(f"{sdir}: not processed yet")
            continue
        truth = beacon_pairs(ROOT / "_private/zeek_published" / zdir)
        victims = {p[0] for p in truth}
        servers = {p[1] for p in truth}
        total, on_beacon = collections.Counter(), collections.Counter()
        for a in alerts(d):
            sig = a["alert"]["signature"]
            total[sig] += 1
            ends = {a.get("src_ip"), a.get("dest_ip")}
            if ends & victims and ends & servers:
                on_beacon[sig] += 1
        report.append({"capture": sdir, "alerts": sum(total.values()), "signatures": len(total),
                       "top": total.most_common(6), "beacon_alerts": sum(on_beacon.values()),
                       "beacon_signatures": on_beacon.most_common()})
        print(f"{sdir:26} alerts {sum(total.values()):7}  on the beacon flow {sum(on_beacon.values()):6}  "
              f"{on_beacon.most_common(3)}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
