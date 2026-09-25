<#
.SYNOPSIS
    Download a public PCAP (if missing), record its SHA-256 and run Zeek and Suricata on it in Docker.

.DESCRIPTION
    Raw captures and tool output stay under _private/ and are never committed. Only the case write-ups,
    detections and aggregated results are published. Large captures can be deleted after processing
    (-DeleteAfter): the manifest keeps the hash, so the exact file can be downloaded and verified again.

.EXAMPLE
    .\lab\process_pcap.ps1 -Name dnscat2_dns_tunneling_24hr -Url "https://www.dropbox.com/s/4r9mcn792dbzonf/dnscat2_dns_tunneling_24hr.pcap?dl=1"
#>
param(
    [Parameter(Mandatory)] [string] $Name,
    [Parameter(Mandatory)] [string] $Url,
    [string] $Extension = "pcap",
    [switch] $DeleteAfter,
    # Keep only alert events from Suricata's eve.json (a 24-hour eve.json with flow, DNS and TLS events runs to GB).
    [switch] $AlertsOnly
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$priv = Join-Path $root "_private"
$pcapDir = Join-Path $priv "pcaps"
$pcap = Join-Path $pcapDir "$Name.$Extension"
$zeekOut = Join-Path $priv "zeek\$Name"
$suriOut = Join-Path $priv "suricata\$Name"
$rules = Join-Path $priv "rules"
New-Item -ItemType Directory -Force $pcapDir, $zeekOut, $suriOut | Out-Null

if (-not (Test-Path $pcap)) {
    Write-Host "downloading $Name ..."
    curl.exe -sSL --fail -o $pcap $Url
}
$sha = (Get-FileHash $pcap -Algorithm SHA256).Hash.ToLower()
$sizeMB = [math]::Round((Get-Item $pcap).Length / 1MB, 1)
Write-Host "$Name  $sizeMB MB  sha256 $sha"

# The containers write harmless warnings to stderr (Zeek reports the missing GeoIP database). Windows PowerShell
# turns redirected native stderr into error records, so both runs use "Continue", keep stderr in a log file and
# judge success by the exit code.
$ErrorActionPreference = "Continue"

# Zeek: JSON logs, checksum validation off (captures from hosts with checksum offloading), site policy "local".
docker run --rm -v "${pcapDir}:/pcaps:ro" -v "${zeekOut}:/out" -w /out zeek/zeek `
    zeek -C -r "/pcaps/$Name.$Extension" LogAscii::use_json=T local 2>&1 |
    Out-File -Encoding utf8 (Join-Path $zeekOut "zeek.stderr.log")
if ($LASTEXITCODE -ne 0) { Write-Warning "zeek exited with code $LASTEXITCODE for $Name (see zeek.stderr.log)" }

# Suricata appends to an existing eve.json: start from a clean output so a re-run does not double every event.
foreach ($old in "eve.json", "fast.log", "stats.log", "suricata.log", "alerts.json") {
    $p = Join-Path $suriOut $old
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }
}

# Suricata: ET Open rules previously fetched with suricata-update into _private/rules.
docker run --rm -v "${pcapDir}:/pcaps:ro" -v "${suriOut}:/out" -v "${rules}:/var/lib/suricata" jasonish/suricata `
    suricata -r "/pcaps/$Name.$Extension" -l /out -k none -S /var/lib/suricata/rules/suricata.rules 2>&1 |
    Out-File -Encoding utf8 (Join-Path $suriOut "suricata.stderr.log")
if ($LASTEXITCODE -ne 0) { Write-Warning "suricata exited with code $LASTEXITCODE for $Name (see suricata.stderr.log)" }
$ErrorActionPreference = "Stop"

if ($AlertsOnly) {
    $eve = Join-Path $suriOut "eve.json"
    Select-String -Path $eve -Pattern '"event_type":"alert"' -SimpleMatch | ForEach-Object { $_.Line } |
        Out-File -Encoding utf8 (Join-Path $suriOut "alerts.json")
    Remove-Item -LiteralPath $eve
}

$manifest = Join-Path $priv "manifest.csv"
if (-not (Test-Path $manifest)) { "name,url,sha256,size_mb,processed_utc" | Out-File -Encoding ascii $manifest }
"$Name,$Url,$sha,$sizeMB,$((Get-Date).ToUniversalTime().ToString('s'))" | Out-File -Encoding ascii -Append $manifest

if ($DeleteAfter) { Remove-Item $pcap; Write-Host "deleted $pcap (hash kept in manifest)" }
Write-Host "done: $Name"
