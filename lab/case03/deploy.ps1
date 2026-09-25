<#
.SYNOPSIS
    Deploy and run the case 03 SOC lab end to end, then collect the evidence into results/case03.

.DESCRIPTION
    1. Checks the Azure CLI session and registers the resource providers.
    2. Creates the lab secrets (Windows password, SSH key) under lab/case03/*.local.* (git-ignored).
    3. Deploys main.bicep into its own resource group.
    4. Waits for the gateway (cloud-init: nftables, Suricata IPS, log shipping).
    5. Enables Defender for Servers Plan 1 (30-day trial) and waits until the Windows endpoint runs the
       Defender for Endpoint extension.
    6. Uploads the Zeek logs of cases 01 and 02 to the custom tables (Logs Ingestion API).
    7. Runs the scenario on the endpoint, then blocks the IDS test destination on the gateway (response)
       and verifies the block.
    8. Waits for the alerts and incidents and writes every query result to results/case03.

    Run destroy.ps1 afterwards: the lab costs about 3-4 USD per day while the VMs are running.

.EXAMPLE
    az login
    .\lab\case03\deploy.ps1
#>
param(
    [string] $ResourceGroup = "rg-nthc-soclab",
    [string] $Location = "westeurope",
    [int] $EvidenceTimeoutMinutes = 90
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $here)
$results = Join-Path $repo "results\case03"
$py = Join-Path $repo ".venv\Scripts\python.exe"
New-Item -ItemType Directory -Force $results | Out-Null

function Step($m) { Write-Host ""; Write-Host "== $m" -ForegroundColor Cyan }
function Az { # az with native stderr kept out of PowerShell's error stream; returns stdout, throws on failure
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $out = & az @args 2>$null
    $code = $LASTEXITCODE; $ErrorActionPreference = $prev
    if ($code -ne 0) { throw "az $($args -join ' ') failed with exit code $code" }
    return $out
}
function AzJson { return (Az @args -o json | Out-String | ConvertFrom-Json) }
function Kql([string]$query) {
    $f = Join-Path $env:TEMP "nthc-query.kql"; Set-Content -Path $f -Value $query -Encoding UTF8
    return (AzJson monitor log-analytics query -w $script:customerId --analytics-query "@$f" --timespan P2D)
}
function RunOnVm([string]$vm, [string]$commandId, [string]$scriptFile) {
    $r = AzJson vm run-command invoke -g $ResourceGroup -n $vm --command-id $commandId --scripts "@$scriptFile"
    return ($r.value | ForEach-Object { $_.message }) -join "`n"
}

# ------------------------------------------------------------------------------------------ 1. session
Step "Azure session"
$account = AzJson account show
$sub = $account.id
Write-Host "subscription $($account.name) ($sub), user $($account.user.name)"
foreach ($ns in "Microsoft.Compute", "Microsoft.Network", "Microsoft.OperationalInsights", "Microsoft.OperationsManagement",
                "Microsoft.SecurityInsights", "Microsoft.Insights", "Microsoft.Security", "Microsoft.DevTestLab") {
    Az provider register --namespace $ns --wait | Out-Null
}

# ------------------------------------------------------------------------------------------ 2. secrets
Step "Lab secrets (git-ignored)"
$secretsFile = Join-Path $here "secrets.local.json"
$keyFile = Join-Path $here "gateway_ed25519.local"
if (-not (Test-Path $secretsFile)) {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".ToCharArray()
    $pw = -join (1..20 | ForEach-Object { $chars | Get-Random }) + "!9aZ"
    @{ windowsAdminPassword = $pw } | ConvertTo-Json | Set-Content -Path $secretsFile -Encoding UTF8
}
if (-not (Test-Path $keyFile)) { ssh-keygen -q -t ed25519 -N '""' -f $keyFile -C "nthc-lab" | Out-Null }
$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json
$sshPublicKey = (Get-Content "$keyFile.pub" -Raw).Trim()
$deployer = (Az ad signed-in-user show --query id -o tsv).Trim()

# ------------------------------------------------------------------------------------------ 3. deployment
Step "Deploy main.bicep into $ResourceGroup ($Location)"
Az group create -n $ResourceGroup -l $Location -o none | Out-Null
$params = @{
    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
    contentVersion = "1.0.0.0"
    parameters = @{
        sshPublicKey = @{ value = $sshPublicKey }
        windowsAdminPassword = @{ value = $secrets.windowsAdminPassword }
        deployerObjectId = @{ value = $deployer }
    }
}
$paramFile = Join-Path $here "parameters.local.json"
$params | ConvertTo-Json -Depth 5 | Set-Content -Path $paramFile -Encoding UTF8
$dep = AzJson deployment group create -g $ResourceGroup -n nthc-case03 -f (Join-Path $here "main.bicep") -p "@$paramFile"
$o = $dep.properties.outputs
$script:customerId = $o.workspaceCustomerId.value
$gw = $o.gatewayName.value; $win = $o.windowsName.value
Write-Host "workspace $($o.workspaceName.value) · gateway $gw ($($o.gatewayPublicIp.value)) · endpoint $win ($($o.windowsIp.value))"

# ------------------------------------------------------------------------------------------ 4. gateway
Step "Wait for the gateway (cloud-init)"
$check = Join-Path $env:TEMP "nthc-gw-check.sh"
Set-Content -Path $check -Value "test -f /var/lib/nthc/ready && echo READY; tail -n 3 /var/log/nthc-setup.log; systemctl is-active nthc-suricata nftables" -Encoding ASCII
$deadline = (Get-Date).AddMinutes(30)
do {
    Start-Sleep -Seconds 30
    $state = RunOnVm $gw "RunShellScript" $check
} until ($state -match "READY" -or (Get-Date) -gt $deadline)
if ($state -notmatch "READY") { throw "gateway not ready after 30 minutes:`n$state" }
Write-Host $state

# ------------------------------------------------------------------------------------------ 5. Defender for Endpoint
Step "Defender for Servers Plan 1 (trial) and Defender for Endpoint on $win"
Az security pricing create -n VirtualMachines --tier standard --subplan P1 -o none | Out-Null
$deadline = (Get-Date).AddMinutes(45)
do {
    Start-Sleep -Seconds 60
    $mde = Az vm extension list -g $ResourceGroup --vm-name $win --query "[?name=='MDE.Windows'].provisioningState" -o tsv
} until ($mde -eq "Succeeded" -or (Get-Date) -gt $deadline)
if ($mde -ne "Succeeded") {
    # Auto-provisioning can lag: install the extension with the subscription's onboarding package.
    Write-Host "auto-provisioning not finished; installing MDE.Windows with the onboarding package"
    $pkg = AzJson rest --method get --url "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Security/mdeOnboardings?api-version=2021-10-01-preview"
    $vmId = (Az vm show -g $ResourceGroup -n $win --query id -o tsv).Trim()
    $settings = Join-Path $here "mde-settings.local.json"; $protected = Join-Path $here "mde-protected.local.json"
    @{ azureResourceId = $vmId; vNextEnabled = "true" } | ConvertTo-Json | Set-Content $settings -Encoding UTF8
    @{ defenderForEndpointOnboardingScript = $pkg.value[0].properties.onboardingPackageWindows } | ConvertTo-Json | Set-Content $protected -Encoding UTF8
    Az vm extension set -g $ResourceGroup --vm-name $win --publisher Microsoft.Azure.AzureDefenderForServers --name MDE.Windows `
        --settings "@$settings" --protected-settings "@$protected" -o none | Out-Null
}
$sense = Join-Path $env:TEMP "nthc-sense.ps1"
Set-Content -Path $sense -Value "(Get-Service Sense).Status; (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue).OnboardingState" -Encoding UTF8
Write-Host ("Defender for Endpoint sensor: " + (RunOnVm $win "RunPowerShellScript" $sense))

# ------------------------------------------------------------------------------------------ 6. Zeek logs
Step "Upload the case 01 and case 02 Zeek logs to the custom tables"
$env:NTHC_MONITOR_TOKEN = (Az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv).Trim()
$uploads = @(
    @("dns", "$repo\_private\zeek\dnscat2_dns_tunneling_24hr\dns.log", "case01-dnscat2-24h"),
    @("dns", "$repo\_private\zeek_published\jit_var_d30_j99", "case02-jit-var-d30-j99"),
    @("conn", "$repo\_private\zeek_published\jit_var_d30_j99", "case02-jit-var-d30-j99")
)
foreach ($u in $uploads) {
    $ok = $false
    for ($i = 0; $i -lt 10 -and -not $ok; $i++) { # the role assignment on the DCR can take minutes to propagate
        & $py (Join-Path $here "ingest_zeek.py") --endpoint $o.dceIngestionEndpoint.value --dcr $o.dcrZeekImmutableId.value `
            --kind $u[0] --log $u[1] --capture $u[2]
        if ($LASTEXITCODE -eq 0) { $ok = $true } else { Start-Sleep -Seconds 60 }
    }
    if (-not $ok) { throw "upload of $($u[2]) ($($u[0])) failed" }
}
Remove-Item Env:\NTHC_MONITOR_TOKEN

# ------------------------------------------------------------------------------------------ 7. scenario and response
Step "Scenario on $win"
$scenarioOut = RunOnVm $win "RunPowerShellScript" (Join-Path $here "scenario-endpoint.ps1")
$scenarioOut | Set-Content (Join-Path $results "scenario-endpoint.log") -Encoding UTF8
Write-Host $scenarioOut
$scenarioTime = (Get-Date).ToUniversalTime()

Step "Response: block the IDS test destination on the gateway, then verify"
$block = Join-Path $env:TEMP "nthc-block.sh"
Set-Content -Path $block -Encoding ASCII -Value @'
for ip in $(getent ahostsv4 testmynids.org | awk '{print $1}' | sort -u); do nft add element inet nthc blocklist "{ $ip }"; done
nft list set inet nthc blocklist
'@
$blockOut = RunOnVm $gw "RunShellScript" $block
$blockOut | Set-Content (Join-Path $results "response-blocklist.txt") -Encoding UTF8
$verify = Join-Path $env:TEMP "nthc-verify.ps1"
Set-Content -Path $verify -Encoding UTF8 -Value "try { Invoke-WebRequest -UseBasicParsing -Uri 'http://testmynids.org/uid/index.html' -TimeoutSec 15 | Out-Null; 'request still succeeds' } catch { 'request blocked: ' + `$_.Exception.Message }"
$verifyOut = RunOnVm $win "RunPowerShellScript" $verify
$verifyOut | Set-Content (Join-Path $results "response-verification.txt") -Encoding UTF8
Write-Host $verifyOut

# ------------------------------------------------------------------------------------------ 8. evidence
Step "Wait for alerts and incidents, collect evidence"
$rules = Join-Path $repo "detections\kql\sentinel-rules"
$queries = [ordered]@{
    "suricata-alerts"      = Get-Content (Join-Path $rules "01-suricata-ips-alert.kql") -Raw
    "dns-tunnel"           = Get-Content (Join-Path $rules "02-dns-tunnel-zeek.kql") -Raw
    "beaconing"            = Get-Content (Join-Path $rules "03-c2-beaconing-zeek.kql") -Raw
    "correlation"          = Get-Content (Join-Path $rules "04-network-and-endpoint-correlation.kql") -Raw
    "endpoint-alerts"      = "SecurityAlert | where CompromisedEntity has '$win' | project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName, CompromisedEntity | order by TimeGenerated asc"
    "firewall-blocks"      = "Syslog | where Facility == 'kern' and SyslogMessage has 'NTHC-BLOCK' | project TimeGenerated, SyslogMessage | order by TimeGenerated asc"
    "zeek-volumes"         = "union ZeekDns_CL, ZeekConn_CL | summarize Records = count() by Table = Type, capture"
}
$deadline = (Get-Date).AddMinutes($EvidenceTimeoutMinutes)
do {
    Start-Sleep -Seconds 120
    $have = @{}
    foreach ($k in "suricata-alerts", "endpoint-alerts", "correlation") { $have[$k] = @(Kql $queries[$k]).Count }
    Write-Host ("waiting: " + (($have.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "))
} until (($have.Values | Where-Object { $_ -eq 0 }).Count -eq 0 -or (Get-Date) -gt $deadline)

foreach ($k in $queries.Keys) {
    $rows = @(Kql $queries[$k])
    $rows | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $results "$k.json") -Encoding UTF8
    Write-Host ("{0,-18} {1} rows" -f $k, $rows.Count)
}
$incidents = AzJson rest --method get --url ("https://management.azure.com/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/" +
    "Microsoft.OperationalInsights/workspaces/$($o.workspaceName.value)/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01")
$incidents.value | ForEach-Object { [ordered]@{
        number = $_.properties.incidentNumber; title = $_.properties.title; severity = $_.properties.severity
        created = $_.properties.createdTimeUtc; alerts = $_.properties.additionalData.alertsCount
        products = $_.properties.additionalData.alertProductNames } } |
    ConvertTo-Json -Depth 5 | Set-Content (Join-Path $results "incidents.json") -Encoding UTF8
Write-Host ("incidents: " + @($incidents.value).Count)
@{ scenarioUtc = $scenarioTime.ToString("s") + "Z"; resourceGroup = $ResourceGroup; location = $Location } |
    ConvertTo-Json | Set-Content (Join-Path $results "run.json") -Encoding UTF8

Step "Done. Evidence in results\case03. Remove the lab with .\lab\case03\destroy.ps1"
