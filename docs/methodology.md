# Methodology

How the cases in this repository were built and measured, so every number can be checked and reproduced.

## 1. Principles

1. **Public, verifiable data.** Every capture comes from a published source and is identified by its SHA-256.
   Nothing is redistributed: the repository links to the source and records the hash (see
   [`lab/datasets.csv`](../lab/datasets.csv)).
2. **Thresholds before results.** Every detection threshold was written into the code before the detection was run
   on the evaluation data, and was never changed afterwards to improve a result. Where a later step uses what was
   learned from the data (the triage allowlist of case 02), it is measured on captures it has not seen.
3. **Detection and ground truth are independent.** The label that says "this is the malicious flow" never comes
   from the detector being evaluated.
4. **False positives count as much as detections.** A detection that fires on normal traffic every day is not
   deployable. Every result is reported with its false positives on normal traffic.
5. **Honest limits.** Each case ends with what the detection does not cover and how it would be tuned in production.

## 2. Data

### 2.1 Sources

All captures are lab recordings published by Active Countermeasures in its *Malware of the Day* series for
threat-hunting training. Each one contains 24 hours of ordinary traffic from lab hosts (Windows and Ubuntu desktops,
update services, telemetry) plus one documented C2 channel. According to the publisher they contain no malware
binaries. The series documents the configuration of each channel (tool, timing, servers), which is what makes an
evaluation against a known truth possible.

| Case | Captures | Role |
|---|---|---|
| 01 | dnscat2 DNS tunnel, 24 h | Positive case for DNS tunnelling |
| 01, 02 | Nine Cobalt Strike captures from *Understanding C2 Beacons, part 2*, 24 h each | Positives for beaconing (case 02); 216 hours of normal DNS traffic for the case 01 false-positive test |

### 2.2 Integrity

Every file was hashed after download and compared with the checksum published on the source page:

- eight of the nine 24-hour Cobalt Strike PCAPs and all nine 1-hour PCAPs: identical;
- `round_rob_r2_d30_j25_24h.pcap`: the checksum on the source page has 61 hexadecimal characters instead of 64;
  the file's SHA-256 starts with those 61 characters;
- the nine published Zeek log archives: identical;
- the dnscat2 captures have no published checksum; their hashes are recorded in `lab/datasets.csv`.

### 2.3 Processing

| Step | Tool and version | Notes |
|---|---|---|
| Transaction logs | Zeek 9.0.0 (`zeek/zeek` container), site policy `local`, JSON output, checksum validation off | `-C` because the captures were taken on hosts with checksum offloading |
| Alerts | Suricata 8.0.6 (`jasonish/suricata` container), ET Open ruleset fetched with `suricata-update` on 2026-09-25 (68,941 rules, 52,985 enabled) | Only alert events are kept for the 24-hour captures |
| Published Zeek logs | As released by the source (hourly TSV files) | Used for case 02 and for the 216-hour DNS baseline, with their own hashes |
| Analytics | Python 3.11, `tldextract` (bundled public suffix list, offline), `matplotlib` | [`requirements.txt`](../requirements.txt) |

Suricata processes a capture with several threads, so alert counts can differ by a few dozen between runs of the
same file (118,066 and 118,084 alerts for the same 24-hour capture). Counts are reported from a single
de-duplicated run.

## 3. Ground truth

| Case | Positive | How it was identified |
|---|---|---|
| 01 | Queries from `10.20.57.3` under `cisco-update[.]com` | Documented by the dataset; confirmed by the query names |
| 02 | Every (client, server, port) pair carrying the Cobalt Strike check-ins | HTTP content in Zeek `http.log`: the fixed check-in URI pattern and the spoofed Internet Explorer 8 user agent. The beacon detector never reads HTTP content; it only uses timestamps and byte counts |

Everything else in a capture is treated as a negative. Some negatives are themselves periodic (update services,
telemetry, NTP); that is intended, because they are the false positives a real deployment faces.

## 4. Metrics

| Metric | Definition |
|---|---|
| Detected | At least one positive unit flagged in the capture |
| Rank | Position of the best positive unit when all units are sorted by score |
| False positives | Negative units flagged; reported per capture and per day of traffic |
| Time to first alert | Time between the first malicious packet and the first alert (real-time detections) |
| Early detection | Whether the positive is flagged using only the first 1, 2, 6, 12 or 24 hours of a capture |

A *unit* is what a detection scores: a (client, base domain, hour) triple for DNS, and a (client, server, port,
protocol) pair or a merged channel for beaconing.

## 5. Allowlists

Two different things are called an allowlist in case 02, and they are kept apart:

1. **A-priori scope**, fixed before the evaluation: outbound traffic only (private client to public server), NTP
   excluded, and servers whose DNS name is an operating-system connectivity check or time service excluded. This is
   what any beacon hunt does before looking at results.
2. **Triage allowlist**, learned from data. The benign services flagged in four *training* captures (exact DNS
   names only) are allowlisted, and the result is measured on the five other captures. The in-sample alternative,
   allowlisting whatever turned up and reporting zero false positives on the same data, would be circular.

## 6. Limitations

- **Lab traffic is cleaner than an enterprise network.** A few hosts generate far less benign diversity than
  thousands of users. The false-positive rates here are a lower bound; the tuning notes in each case describe what to
  expect in production.
- **One tool per technique.** Case 01 uses dnscat2 and case 02 Cobalt Strike. The detections are behavioural and
  not specific to those tools, but they have only been measured on them.
- **Published logs versus own processing.** Case 02 scores the Zeek logs published with the captures. The same
  captures were also processed with Zeek 9.0.0 in this lab, and the results agree (see case 02).
- **Statement of process.** The order "thresholds first, results second" is how the work was done. The repository
  history starts after the analysis, so it documents the process but does not prove it.

## 7. Safety and ethics

- No attack traffic was generated for cases 01 and 02; they analyse published lab captures only.
- Indicators are defanged (`hxxp`, `[.]`) and the raw captures stay outside the repository (`_private/`, ignored by
  git).
- Case 03 uses only vendor-provided test methods (the Defender for Endpoint detection test and a standard IDS test
  request) in an isolated cloud lab that is deleted after the exercise.
