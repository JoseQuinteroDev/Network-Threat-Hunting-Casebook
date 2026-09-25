# Analysis lab setup

Everything in cases 01 and 02 runs on one Windows machine with Docker. Zeek and Suricata run in containers, so
nothing is installed on the host apart from Docker and Python.

## Requirements

| Component | Version used | Purpose |
|---|---|---|
| Windows 11 with PowerShell 5.1 | — | Scripts in `lab/` |
| Docker Desktop (WSL 2 backend) | Engine 29.2 | Zeek and Suricata containers |
| Python | 3.11 | Tools in `tools/` |
| Disk | ~6 GB free | The largest capture is 4.5 GB; captures are deleted after processing |

## 1. Prepare

```powershell
git clone https://github.com/JoseQuinteroDev/Network-Threat-Hunting-Casebook.git
cd Network-Threat-Hunting-Casebook
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

docker pull zeek/zeek:latest
docker pull jasonish/suricata:latest

# ET Open ruleset into _private/rules (the directory is git-ignored)
New-Item -ItemType Directory -Force _private\rules | Out-Null
docker run --rm -v "${PWD}\_private\rules:/var/lib/suricata" jasonish/suricata suricata-update --no-test
```

## 2. Process the captures

[`lab/process_pcap.ps1`](../lab/process_pcap.ps1) downloads one capture, records its SHA-256 in
`_private/manifest.csv`, runs Zeek and Suricata, and optionally keeps only the alerts and deletes the capture:

```powershell
# Case 01
.\lab\process_pcap.ps1 -Name dnscat2_dns_tunneling_24hr -Url "https://www.dropbox.com/s/4r9mcn792dbzonf/dnscat2_dns_tunneling_24hr.pcap?dl=1"

# Case 02: the nine beacon captures, one at a time (about 9 GB of downloads in total)
.\lab\process_beacon_datasets.ps1
```

Compare the hashes in `_private/manifest.csv` with [`lab/datasets.csv`](../lab/datasets.csv) before using the
results.

The published Zeek logs used by case 02 (and by the case 01 baseline) are downloaded, verified against the published
checksums and extracted with:

```powershell
.\.venv\Scripts\python.exe lab\fetch_published_zeek_logs.py
```

## 3. Run the analyses

```powershell
$py = ".\.venv\Scripts\python.exe"

# Case 01: DNS tunnel hunt on the tunnel capture and on the 216-hour baseline
& $py tools\dns_profile.py _private\zeek\dnscat2_dns_tunneling_24hr\dns.log
Get-ChildItem _private\zeek_published -Directory | ForEach-Object { & $py tools\dns_profile.py $_.FullName --top 3 }

# Case 02: beacon evaluation, triage split and Suricata summary
& $py tools\evaluate_beacons.py _private\zeek_published --out results\beaconing
& $py tools\beacon_triage_split.py _private\zeek_published --mode channel --out results\beaconing
& $py tools\beacon_triage_split.py _private\zeek_published --mode pair --out results\beaconing
& $py tools\suricata_summary.py --out results\beaconing\et_open_alerts.json

# Figures (light and dark variants)
& $py tools\make_figures.py
```

## 4. Run the custom detections on a capture

```powershell
# Zeek with the DNS-tunnel script
docker run --rm -v "${PWD}\_private\pcaps:/pcaps:ro" -v "${PWD}\detections:/detections:ro" `
  -v "${PWD}\_private\out:/out" -w /out zeek/zeek `
  zeek -C -r /pcaps/<capture>.pcap LogAscii::use_json=T local /detections/zeek/dns-tunnel-detect.zeek

# Suricata with the custom rules only
docker run --rm -v "${PWD}\_private\pcaps:/pcaps:ro" -v "${PWD}\detections:/detections:ro" `
  -v "${PWD}\_private\out:/out" jasonish/suricata `
  suricata -r /pcaps/<capture>.pcap -l /out -k none -S /detections/suricata/dns-tunnel.rules
```

## Repository layout

| Path | Content |
|---|---|
| `cases/` | One folder per case: write-up, figures |
| `detections/` | Zeek scripts, Suricata rules, KQL queries |
| `tools/` | Python analytics, evaluation and figure scripts |
| `lab/` | Processing scripts, dataset manifest, case 03 infrastructure |
| `results/` | Machine-readable outputs behind every table in the cases |
| `_private/` | Captures, raw logs and rules (git-ignored, never published) |
