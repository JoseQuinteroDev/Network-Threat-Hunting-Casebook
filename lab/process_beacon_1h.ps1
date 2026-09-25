<#
.SYNOPSIS
    Process the nine official 1-hour captures of "Understanding C2 Beacons, part 2" (about 80 MB in total).
    They are the early-detection test of case 02: can the detector find the beacon with one hour of traffic?
#>
$ErrorActionPreference = "Stop"
$base = "https://acm-motd.s3.amazonaws.com"
$datasets = @(
    "delay_var_d10_j25_1h", "delay_var_d30_j25_1h", "delay_var_d300_j25_1h", "jit_var_d30_j0_1h",
    "jit_var_d30_j10_1h", "jit_var_d30_j99_1h", "random_d30_j0_1h", "random_d30_j25_1h", "round_rob_r2_d30_j25_1h"
)
foreach ($d in $datasets) {
    & (Join-Path $PSScriptRoot "process_pcap.ps1") -Name $d -Url "$base/$d.pcap" -AlertsOnly
}
