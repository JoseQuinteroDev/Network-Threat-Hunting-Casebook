"""Upload Zeek logs from cases 01 and 02 to the Sentinel custom tables through the Logs Ingestion API.

The captures are years old and Log Analytics only accepts recent TimeGenerated values, so every record is shifted by
one constant offset that ends the capture ANCHOR_MINUTES before now. Relative timing, which is all the detections
use, is preserved; the original timestamp is kept in ts_original.

The bearer token comes from the environment (NTHC_MONITOR_TOKEN), obtained by deploy.ps1 with
`az account get-access-token --resource https://monitor.azure.com`.

Usage:
    python ingest_zeek.py --endpoint <DCE logs ingestion URL> --dcr <immutable id> --kind dns|conn
                          --log <zeek log file or directory> --capture <name> [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from beacon_score import capture_hours  # noqa: E402
from zeeklog import read_zeek  # noqa: E402

ANCHOR_MINUTES = 30
MAX_BATCH_BYTES = 900_000  # the API accepts up to 1 MB per call
STREAMS = {"dns": "Custom-ZeekDns", "conn": "Custom-ZeekConn"}
FIELDS = {
    "dns": ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name", "rcode_name", "answers"],
    "conn": ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes",
             "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "conn_state"],
}


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def records(kind: str, log: Path, capture: str):
    rows = list(read_zeek(log, kind))
    # Drop the few records of long connections that started before the capture (same rule as the detector):
    # shifted, they would land days before the rest and outside the window Log Analytics accepts.
    hours = capture_hours([r["ts"] for r in rows])
    start = min(hours) * 3600
    rows = [r for r in rows if r["ts"] >= start]
    last = max(r["ts"] for r in rows)
    offset = (time.time() - ANCHOR_MINUTES * 60) - last
    for r in rows:
        out = {"TimeGenerated": iso(r["ts"] + offset), "ts_original": iso(r["ts"]), "capture": capture}
        for f in FIELDS[kind]:
            out[f.replace(".", "_")] = r.get(f)
        yield out


def batches(items):
    batch, size = [], 2
    for it in items:
        s = len(json.dumps(it)) + 1
        if batch and size + s > MAX_BATCH_BYTES:
            yield batch
            batch, size = [], 2
        batch.append(it)
        size += s
    if batch:
        yield batch


def post(url: str, token: str, body: bytes):
    for attempt in range(6):
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(int(e.headers.get("Retry-After", 2 ** attempt)))
                continue
            raise SystemExit(f"HTTP {e.code}: {e.read()[:500]!r}")
    raise SystemExit("gave up after retries")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--dcr", required=True)
    ap.add_argument("--kind", choices=STREAMS, required=True)
    ap.add_argument("--log", type=Path, required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    token = os.environ.get("NTHC_MONITOR_TOKEN", "")
    if not token and not args.dry_run:
        raise SystemExit("NTHC_MONITOR_TOKEN is not set")
    url = f"{args.endpoint.rstrip('/')}/dataCollectionRules/{args.dcr}/streams/{STREAMS[args.kind]}?api-version=2023-01-01"
    sent = calls = 0
    for batch in batches(records(args.kind, args.log, args.capture)):
        body = json.dumps(batch).encode("utf-8")
        if not args.dry_run:
            post(url, token, body)
        sent += len(batch)
        calls += 1
    print(f"{args.capture}: {sent} {args.kind} records in {calls} calls{' (dry run)' if args.dry_run else ''}")


if __name__ == "__main__":
    main()
