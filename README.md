# Network Threat Hunting Casebook

**Detecting command-and-control channels from network traffic: Zeek, Suricata, Python and KQL, measured against
known ground truth.**

Each case starts from a public packet capture with a documented C2 channel inside a day of ordinary traffic, and asks
the questions a SOC has to answer: *would we have seen it, how fast, and at what false-positive cost?* Every
detection threshold is fixed before the evaluation, every capture is verified against its published checksum, and
every result is reported together with its false positives on normal traffic.

| Case | Threat | What signatures saw | What this project built | Result |
|---|---|---|---|---|
| [**01 — DNS tunnelling**](cases/01-dns-tunnel/) | dnscat2 tunnel, 165,517 encoded queries in 24 h through the internal resolvers | ET Open (52,985 enabled): **0 alerts** on the tunnel | Python hunt, Zeek script, Suricata rule, KQL hunt | Zeek alerts in **27 s**, Suricata in 69 s; **0 false positives** in 216 h of normal traffic |
| [**02 — C2 beaconing**](cases/02-c2-beaconing/) | Cobalt Strike HTTP beacon in 9 configurations (10 s – 5 min, 0–99 % jitter, redirector rotation) | ET Open: only the initial payload delivery; **nothing on the check-ins** | Statistical beacon detector (timing + size only), channel merging, out-of-sample triage, Suricata rule, KQL hunt | **9 of 9** beacons found; **0 false positives** on held-out captures after triage; flagged within the first hour in 8 of 9 |
| [**03 — SOC lab: firewall, IDS, EDR and SIEM**](cases/03-soc-lab-firewall-edr-siem/) | End-to-end detection and response in a cloud lab | — | Ubuntu gateway (nftables + Suricata inline IPS), Defender for Endpoint, Microsoft Sentinel with custom tables, analytics rules and a network-to-endpoint correlation | See the case |

## Highlights

- **Signatures versus behaviour, measured.** The full ET Open ruleset produced 101,000–122,000 alerts a day on these
  captures and did not flag either C2 channel. Behavioural analytics on Zeek logs found both, and each finding was
  then turned into a cheap Suricata signature.
- **One detection logic, several engines.** The DNS-tunnel logic runs as a Python hunt, a real-time Zeek script, a
  Suricata rule and a KQL query for Sentinel and Defender XDR; the beacon score as Python and KQL.
- **Evaluation discipline.** Thresholds fixed in advance, ground truth independent of the detector, false positives
  reported per day, triage allowlists learned on training captures and tested on held-out ones
  ([methodology](docs/methodology.md)).
- **The maths checks out.** The effect of jitter on the timing score follows a closed-form prediction; the measured
  values match it to within 0.012 ([case 02](cases/02-c2-beaconing/#31-what-jitter-does-to-the-timing-score)).
- **Response, not just detection.** Each case ends with containment, scoping, eradication and hardening steps, and the
  defanged indicators.

## Repository layout

| Path | Content |
|---|---|
| [`cases/`](cases/) | The write-ups, one folder per case |
| [`detections/zeek/`](detections/zeek/) | Zeek scripts (real-time DNS-tunnel detection) |
| [`detections/suricata/`](detections/suricata/) | Custom Suricata rules (`sid` 9100001–9100002) |
| [`detections/kql/`](detections/kql/) | Hunting queries for Microsoft Sentinel and Defender XDR |
| [`tools/`](tools/) | Python analytics: DNS profiling, beacon scoring, evaluation, figures |
| [`lab/`](lab/) | Capture processing (Docker), dataset manifest, case 03 infrastructure |
| [`results/`](results/) | Machine-readable outputs behind every table |
| [`docs/`](docs/) | [Methodology](docs/methodology.md) and [lab setup](docs/lab-setup.md) |

## Reproduce

Requirements: Docker Desktop, Python 3.11, about 6 GB of free disk. Step by step in
[`docs/lab-setup.md`](docs/lab-setup.md); in short:

```powershell
python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt
docker pull zeek/zeek; docker pull jasonish/suricata
.\.venv\Scripts\python.exe lab\fetch_published_zeek_logs.py          # verified Zeek logs (case 02 + baseline)
.\.venv\Scripts\python.exe tools\evaluate_beacons.py _private\zeek_published --out results\beaconing
```

Raw captures are not redistributed. [`lab/datasets.csv`](lab/datasets.csv) lists every file with its source URL and
SHA-256.

## Stack

![Zeek](https://img.shields.io/badge/Zeek-9.0-2E4E7E?style=flat-square)
![Suricata](https://img.shields.io/badge/Suricata-8.0-EF7C00?style=flat-square)
![ET Open](https://img.shields.io/badge/ET_Open-68,941_rules-555555?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Sentinel_%7C_Defender_XDR-0078D4?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-lab-2496ED?style=flat-square&logo=docker&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-E34F26?style=flat-square)

## Data sources and credit

The captures are published by [Active Countermeasures](https://www.activecountermeasures.com/) in its *Malware of the
Day* series for threat-hunting training. All analysis, detections and write-ups in this repository are original.

**Author:** José Quintero · Blue Team / Detection Engineering · [GitHub](https://github.com/JoseQuinteroDev)

Code is released under the [MIT License](LICENSE). The datasets remain the property of their publishers.
