"""Profile DNS behaviour per client and base domain from a Zeek dns.log (JSON), and flag likely tunnels.

A DNS tunnel has to encode data in the query names, so it produces many unique, long, high-entropy
subdomains under a single base domain. Normal traffic reuses a small set of names. The detector looks
at each (client, base domain) pair hour by hour.

Thresholds were fixed before looking at any capture (see methodology), and are deliberately generic:
    unique subdomains in one hour  >= 50
    mean subdomain length          >= 20 characters
    mean Shannon entropy           >= 3.0 bits per character

Usage:
    python tools/dns_profile.py _private/zeek/<capture>/dns.log [--top 15] [--json out.json]
    python tools/dns_profile.py <directory of hourly Zeek logs>
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import re
import statistics
import sys
from pathlib import Path

import tldextract

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zeeklog import read_zeek  # noqa: E402

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # bundled public suffix list: offline, reproducible
THRESHOLDS = {"unique_subdomains_per_hour": 50, "mean_subdomain_len": 20.0, "mean_entropy": 3.0}
HEX = re.compile(r"^[0-9a-f.]+$", re.I)
SKIP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".local")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def split_name(query: str) -> tuple[str, str]:
    """(base domain, subdomain part) using the public suffix list."""
    query = query.rstrip(".").lower()
    r = EXTRACT(query)
    base = r.top_domain_under_public_suffix or query
    sub = query[: -len(base)].rstrip(".") if query.endswith(base) else ""
    return base, sub


def load(path: Path):
    return read_zeek(path, "dns")


def profile(rows) -> dict:
    groups = collections.defaultdict(lambda: {"ts": [], "subs": [], "qtypes": collections.Counter(),
                                              "rcodes": collections.Counter(), "answer_chars": 0})
    for r in rows:
        q = r.get("query")
        if not q or q.lower().endswith(SKIP_SUFFIXES):
            continue
        base, sub = split_name(q)
        g = groups[(r.get("id.orig_h", "?"), base)]
        g["ts"].append(float(r["ts"]))
        g["subs"].append(sub)
        g["qtypes"][r.get("qtype_name") or "-"] += 1
        g["rcodes"][r.get("rcode_name") or "-"] += 1
        g["answer_chars"] += sum(len(a) for a in (r.get("answers") or []))
    out = {}
    for (client, base), g in groups.items():
        subs = [s for s in g["subs"] if s]
        uniq = set(subs)
        hours = collections.defaultdict(set)
        for t, s in zip(g["ts"], g["subs"]):
            if s:
                hours[int(t // 3600)].add(s)
        peak_hour_unique = max((len(v) for v in hours.values()), default=0)
        mean_len = statistics.fmean(len(s) for s in uniq) if uniq else 0.0
        mean_ent = statistics.fmean(entropy(s.replace(".", "")) for s in uniq) if uniq else 0.0
        ts = sorted(g["ts"])
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        flagged = (peak_hour_unique >= THRESHOLDS["unique_subdomains_per_hour"]
                   and mean_len >= THRESHOLDS["mean_subdomain_len"]
                   and mean_ent >= THRESHOLDS["mean_entropy"])
        out[f"{client} {base}"] = {
            "client": client, "base_domain": base, "queries": len(g["ts"]), "unique_subdomains": len(uniq),
            "peak_hour_unique_subdomains": peak_hour_unique, "mean_subdomain_len": round(mean_len, 1),
            "max_subdomain_len": max((len(s) for s in uniq), default=0), "mean_entropy": round(mean_ent, 2),
            "hex_only_share": round(sum(1 for s in uniq if HEX.match(s)) / len(uniq), 3) if uniq else 0.0,
            "qtypes": dict(g["qtypes"].most_common()), "rcodes": dict(g["rcodes"].most_common()),
            # Hex encoding carries 1 byte per 2 characters: an upper bound of the data sent upstream.
            "upstream_bytes_est": sum(len(s.replace(".", "")) for s in subs) // 2,
            "answer_chars": g["answer_chars"],
            "first_ts": ts[0], "last_ts": ts[-1],
            "median_gap_s": round(statistics.median(gaps), 3) if gaps else None,
            "flagged": flagged,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dns_log", type=Path)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    prof = profile(load(args.dns_log))
    ranked = sorted(prof.values(), key=lambda p: (p["flagged"], p["peak_hour_unique_subdomains"]), reverse=True)
    print(f"(client, base domain) pairs: {len(prof)}   flagged: {sum(p['flagged'] for p in prof.values())}")
    print(f"{'client':15} {'base domain':30} {'queries':>8} {'uniq sub':>8} {'peak/h':>7} {'len':>5} {'ent':>5} "
          f"{'hex':>5} {'gap s':>6}  flag  qtypes")
    for p in ranked[: args.top]:
        print(f"{p['client'][:15]:15} {p['base_domain'][:30]:30} {p['queries']:8} {p['unique_subdomains']:8} "
              f"{p['peak_hour_unique_subdomains']:7} {p['mean_subdomain_len']:5} {p['mean_entropy']:5} "
              f"{p['hex_only_share']:5} {str(p['median_gap_s']):>6}  {'YES ' if p['flagged'] else '    '}  "
              f"{dict(list(p['qtypes'].items())[:3])}")
    if args.json:
        args.json.write_text(json.dumps({"thresholds": THRESHOLDS, "pairs": ranked}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
