"""Download the Zeek logs published with the nine beacon captures, verify them and extract the 24-hour set.

Each archive nests a 1-hour and a 24-hour zip whose hourly log names contain ':' (not valid on Windows). The 24-hour
logs are extracted into _private/zeek_published/<capture>/ with ':' replaced by '-', gzip members decompressed.
Checksums are the ones published on the source page (Active Countermeasures, "Understanding C2 Beacons, part 2").

Usage:
    python lab/fetch_published_zeek_logs.py
"""
from __future__ import annotations

import gzip
import hashlib
import io
import re
import shutil
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "_private" / "zeek_published"
BASE = "https://acm-motd.s3.amazonaws.com"
ARCHIVES = {
    "delay_var_d10_j25": "a99d7688065e65c801e1643de36b991b25822e34556913db019298bb4ef98ef7",
    "delay_var_d30_j25": "3a68c1bffa3b840e4a8c73482e60f5ed519087c7e68fdeaa5cc54f0e073091b5",
    "delay_var_d300_j25": "88bac80fa9b8f3d8252d97221ee71f651428c67d106d5f4e6a5a6339db240110",
    "jit_var_d30_j0": "16d379ba4cdd3af5fa5efed6019dc0c17db9701aaf2a7c44c84f9a1b5ccb6b3f",
    "jit_var_d30_j10": "624128047fb89a91ed9af4c89d8246c087257887285e9104b96ded013c15c2cd",
    "jit_var_d30_j99": "d0787aee3c4d88ef429db2ca96553187e597bdf524b2277470b2abcb2c80bd71",
    "random_d30_j0": "fba9d5c476fdb1db2e80222d700ee0a077d24335e1bc0f8b593b9e5f10980852",
    "random_d30_j25": "ecd5d77903025cfe840c6d31e150f510ee142de97ae65c219b528612be7ffc1d",
    "round_rob_d30_j25": "78288f66f401f02f2e9553dcf602a04d8c89b3364d71058c44b17d523721092b",
}


def extract(zf: zipfile.ZipFile, dest: Path) -> int:
    n = 0
    for info in zf.infolist():
        if info.is_dir() or "__MACOSX" in info.filename or "/._" in info.filename or info.filename.endswith(".DS_Store"):
            continue
        data = zf.read(info)
        if info.filename.endswith(".zip"):
            if "_1H" in info.filename:  # keep only the 24-hour logs
                continue
            n += extract(zipfile.ZipFile(io.BytesIO(data)), dest)
            continue
        name = re.sub(r'[:<>"|?*]', "-", Path(info.filename).name)
        if name.endswith(".gz"):
            data, name = gzip.decompress(data), name[:-3]
        (dest / name).write_bytes(data)
        n += 1
    return n


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for capture, expected in ARCHIVES.items():
        archive = OUT / f"{capture}_zeek_logs.zip"
        if not archive.exists():
            req = urllib.request.Request(f"{BASE}/{capture}_zeek_logs.zip", headers={"User-Agent": "nthc-lab"})
            with urllib.request.urlopen(req, timeout=120) as r:
                archive.write_bytes(r.read())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != expected:
            raise SystemExit(f"{archive.name}: SHA-256 {digest} does not match the published {expected}")
        dest = OUT / capture
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir()
        extract(zipfile.ZipFile(archive), dest)
        # Some archives hold the 24-hour folder both directly and as a nested zip; identical files overwrite.
        print(f"{capture:20} verified, {sum(1 for _ in dest.iterdir())} log files")


if __name__ == "__main__":
    main()
