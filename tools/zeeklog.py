"""Read Zeek logs in either format (JSON lines or the default tab-separated ASCII), from a file or a directory.

A directory is read in file-name order and may hold hourly rotated logs (dns.00-00-00-01-00-00.log, ...).
Values come back as JSON would give them: ts as float, sets/vectors as lists, unset fields as None.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

_LIST_TYPES = ("set[", "vector[")
_NUM_TYPES = {"time", "interval", "double"}
_INT_TYPES = {"count", "int", "port"}


def _files(path: Path, kind: str) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.iterdir() if p.is_file() and p.name.split(".")[0] == kind)


def _convert(value: str, ztype: str, sep: str, empty: str, unset: str):
    if value == unset:
        return None
    if ztype.startswith(_LIST_TYPES):
        return [] if value == empty else value.split(sep)
    if ztype in _NUM_TYPES:
        return float(value)
    if ztype in _INT_TYPES:
        return int(value)
    if ztype == "bool":
        return value == "T"
    return value


def read_zeek(path: str | Path, kind: str) -> Iterator[dict]:
    """Yield one dict per record of the given log kind (e.g. "dns", "conn")."""
    for f in _files(Path(path), kind):
        with open(f, encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
            if first.startswith("{"):
                yield json.loads(first)
                for line in fh:
                    if line.startswith("{"):
                        yield json.loads(line)
                continue
            fields, types, sep, set_sep, empty, unset = [], [], "\t", ",", "(empty)", "-"
            line = first
            while line:
                if line.startswith("#"):
                    key, _, rest = line.rstrip("\n").partition(sep if not line.startswith("#separator") else " ")
                    if key == "#separator":
                        sep = rest.encode().decode("unicode_escape")
                    elif key == "#set_separator":
                        set_sep = rest
                    elif key == "#empty_field":
                        empty = rest
                    elif key == "#unset_field":
                        unset = rest
                    elif key == "#fields":
                        fields = rest.split(sep)
                    elif key == "#types":
                        types = rest.split(sep)
                elif fields:
                    values = line.rstrip("\n").split(sep)
                    yield {k: _convert(v, t, set_sep, empty, unset) for k, v, t in zip(fields, values, types)}
                line = fh.readline()
