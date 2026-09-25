"""Score every connection pair in a Zeek conn.log for beacon-like behaviour.

A C2 implant that "checks in" produces connections from one client to one server at a steady rhythm,
with near-constant sizes, all day long. Each (client, server, port, protocol) pair gets four sub-scores
in [0, 1] and their mean:

    S_disp   timing regularity   1 - MAD(gaps) / median(gaps)        (robust coefficient of dispersion)
    S_skew   timing symmetry     1 - |Bowley skewness of the gaps|   (jitter is usually symmetric)
    S_size   size regularity     1 - MAD(bytes) / median(bytes)      (idle check-ins repeat the same size)
    S_cov    persistence         share of the capture's hours with at least one connection

A pair is flagged when it has at least MIN_CONNECTIONS connections and the mean score reaches
THRESHOLD. Both values were fixed before scoring any capture (see docs/methodology.md). The detector
never looks at payloads, URIs or user agents: it only uses timestamps and byte counts, which is what
remains visible when the channel is encrypted.

Channel mode (--mode channel) first merges the servers one client reaches on the same port with the
same connection size, so a beacon that rotates between redirectors is scored as one timeline.

Usage:
    python tools/beacon_score.py <conn.log or directory of hourly Zeek logs> [--mode pair|channel]
                                 [--hours N] [--top 15] [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zeeklog import read_zeek  # noqa: E402

MIN_CONNECTIONS = 20
THRESHOLD = 0.80
SIZE_TOLERANCE = 0.03  # channel mode: servers merged when their median connection sizes differ by <= 3 %


def quantiles(values: list[float]) -> tuple[float, float, float]:
    q = statistics.quantiles(values, n=4, method="inclusive")
    return q[0], q[1], q[2]


def mad(values: list[float], centre: float) -> float:
    return statistics.median(abs(v - centre) for v in values)


def bounded(x: float) -> float:
    return max(0.0, min(1.0, x))


def skip_destination(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_multicast or addr.is_unspecified or ip.endswith(".255")


def capture_hours(times: list[float]) -> set[int]:
    """Hours that belong to the capture: buckets holding at least a fifth of the median hourly volume.

    Zeek stamps a connection with its start time, so a long connection that began before the capture
    lands in a far earlier hour. Counting from the earliest timestamp would stretch the capture and
    understate every pair's persistence."""
    buckets = collections.Counter(int(t // 3600) for t in times)
    floor = 0.2 * statistics.median(buckets.values())
    return {h for h, n in buckets.items() if n >= floor}


def score_pair(times: list[float], sizes: list[int], hours_in_capture: set[int]) -> dict:
    times = sorted(times)
    gaps = [b - a for a, b in zip(times, times[1:])]
    if len(gaps) < 3:
        return {}
    q1, q2, q3 = quantiles(gaps)
    s_disp = bounded(1 - mad(gaps, q2) / q2) if q2 > 0 else 0.0
    s_skew = 1.0 if q3 == q1 else bounded(1 - abs((q1 + q3 - 2 * q2) / (q3 - q1)))
    size_med = statistics.median(sizes)
    s_size = bounded(1 - mad(sizes, size_med) / size_med) if size_med > 0 else 0.0
    hours = {int(t // 3600) for t in times} & hours_in_capture
    s_cov = bounded(len(hours) / len(hours_in_capture)) if hours_in_capture else 0.0
    score = (s_disp + s_skew + s_size + s_cov) / 4
    return {"connections": len(times), "median_gap_s": round(q2, 2), "mad_gap_s": round(mad(gaps, q2), 2),
            "s_disp": round(s_disp, 3), "s_skew": round(s_skew, 3), "s_size": round(s_size, 3),
            "s_cov": round(s_cov, 3), "score": round(score, 3)}


def load_pairs(path: str | Path, max_hours: float | None = None) -> tuple[dict, set[int]]:
    """Connection times and sizes per (client, server, port, protocol), plus the capture's hours."""
    rows = list(read_zeek(path, "conn"))
    if not rows:
        return {}, set()
    hours_in_capture = capture_hours([r["ts"] for r in rows])
    if max_hours is not None:
        # Windows start at the capture's first record, not at a clock hour: a capture that begins at hh:50
        # would otherwise get a first "hour" of ten minutes.
        start = min(r["ts"] for r in rows if int(r["ts"] // 3600) in hours_in_capture)
        end = start + max_hours * 3600
        rows = [r for r in rows if start <= r["ts"] < end]
        hours_in_capture = {h for h in hours_in_capture if h * 3600 < end and (h + 1) * 3600 > start}
    pairs = collections.defaultdict(lambda: ([], []))
    for r in rows:
        dst = r.get("id.resp_h")
        if skip_destination(dst):
            continue
        key = (r.get("id.orig_h"), dst, r.get("id.resp_p"), r.get("proto"))
        pairs[key][0].append(r["ts"])
        # IP-level bytes include headers, so a connection without payload still has a size.
        pairs[key][1].append((r.get("orig_ip_bytes") or 0) + (r.get("resp_ip_bytes") or 0))
    return dict(pairs), hours_in_capture


def channels(pairs: dict) -> dict:
    """Merge the servers one client reaches on the same port and protocol with the same connection size.

    A beacon that rotates between redirectors splits its rhythm across several server addresses, but
    every check-in keeps the same size. Servers whose median size is within SIZE_TOLERANCE of the
    group's smallest are merged into one channel and scored as a single timeline."""
    groups = collections.defaultdict(list)
    for (src, dst, port, proto), (times, sizes) in pairs.items():
        groups[(src, port, proto)].append((statistics.median(sizes), dst, times, sizes))
    merged = {}
    for (src, port, proto), members in groups.items():
        members.sort(key=lambda m: m[0])
        current: list = []
        for m in members + [None]:
            if current and (m is None or m[0] > current[0][0] * (1 + SIZE_TOLERANCE)):
                dsts = tuple(sorted(c[1] for c in current))
                merged[(src, dsts, port, proto)] = ([t for c in current for t in c[2]],
                                                    [s for c in current for s in c[3]])
                current = []
            if m is not None:
                current.append(m)
    return merged


def score_capture(path: str | Path, max_hours: float | None = None, mode: str = "pair",
                  keep=None) -> list[dict]:
    """Score every pair (mode="pair") or every merged channel (mode="channel").

    keep: optional predicate on the (client, server, port, protocol) key, applied before merging.
    With max_hours, only the first hours of the capture are used."""
    pairs, hours_in_capture = load_pairs(path, max_hours)
    if keep is not None:
        pairs = {k: v for k, v in pairs.items() if keep(k)}
    units = pairs if mode == "pair" else channels(pairs)
    out = []
    for (src, dst, port, proto), (times, sizes) in units.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        s = score_pair(times, sizes, hours_in_capture)
        if s:
            members = list(dst) if isinstance(dst, tuple) else [dst]
            s.update({"src": src, "dst": "+".join(members), "members": members, "port": port, "proto": proto,
                      "flagged": s["score"] >= THRESHOLD})
            out.append(s)
    return sorted(out, key=lambda s: s["score"], reverse=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("conn_log", type=Path)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--hours", type=float, help="only use the first N hours of the capture")
    ap.add_argument("--mode", choices=("pair", "channel"), default="pair",
                    help="channel: merge servers reached on the same port with the same connection size")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    ranked = score_capture(args.conn_log, args.hours, args.mode)
    print(f"pairs scored: {len(ranked)}  flagged (score >= {THRESHOLD}): {sum(r['flagged'] for r in ranked)}")
    print(f"{'#':>3} {'src':15} {'dst':15} {'port':>5} {'proto':5} {'conns':>6} {'gap s':>8} {'disp':>5} "
          f"{'skew':>5} {'size':>5} {'cov':>5} {'score':>6}")
    for i, r in enumerate(ranked[: args.top], 1):
        print(f"{i:3} {r['src']:15} {r['dst'][:15]:15} {r['port']:5} {r['proto']:5} {r['connections']:6} "
              f"{r['median_gap_s']:8} {r['s_disp']:5} {r['s_skew']:5} {r['s_size']:5} {r['s_cov']:5} "
              f"{r['score']:6}{'  FLAG' if r['flagged'] else ''}")
    if args.json:
        args.json.write_text(json.dumps(ranked, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
