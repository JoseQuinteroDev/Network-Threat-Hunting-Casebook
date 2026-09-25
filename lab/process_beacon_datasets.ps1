<#
.SYNOPSIS
    Process the nine Cobalt Strike beacon captures of Active Countermeasures' "Understanding C2 Beacons, part 2"
    one at a time: download, hash, Zeek, Suricata (alerts only), delete the capture.

.DESCRIPTION
    The nine 24-hour captures add up to about 9 GB. Processing them one by one keeps the disk footprint to the
    largest single capture (4.3 GB). Hashes go to _private/manifest.csv, so each file can be re-downloaded and
    verified later.
#>
$ErrorActionPreference = "Stop"
$base = "https://acm-motd.s3.amazonaws.com"
$datasets = @(
    "jit_var_d30_j99_24h", "random_d30_j0_24h", "random_d30_j25_24h", "jit_var_d30_j10_24h",
    "delay_var_d10_j25_24h", "jit_var_d30_j0_24h", "round_rob_r2_d30_j25_24h", "delay_var_d30_j25_24h",
    "delay_var_d300_j25_24h"
)
foreach ($d in $datasets) {
    $done = Join-Path (Split-Path -Parent $PSScriptRoot) "_private\suricata\$d\alerts.json"
    if (Test-Path $done) { Write-Host "skip $d (already processed)"; continue }
    & (Join-Path $PSScriptRoot "process_pcap.ps1") -Name $d -Url "$base/$d.pcap" -DeleteAfter -AlertsOnly
}
Write-Host "all beacon datasets processed"
