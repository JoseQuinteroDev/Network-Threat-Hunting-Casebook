# Case 03 scenario, run on the Windows endpoint through Azure run-command (as SYSTEM).
# Three vendor-provided, harmless test signals; each produces evidence at a different layer.
$ErrorActionPreference = 'Continue'
$log = 'C:\nthc\scenario.log'
New-Item -ItemType Directory -Force 'C:\nthc' | Out-Null
function Note($m) { "$((Get-Date).ToUniversalTime().ToString('s'))Z  $m" | Tee-Object -FilePath $log -Append }

# 1. Network layer: the standard IDS test page. Plain HTTP, so the gateway's Suricata can read the response,
#    which matches ET Open "GPL ATTACK_RESPONSE id check returned root".
try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://testmynids.org/uid/index.html' -TimeoutSec 20
    Note "ids-test: HTTP $($r.StatusCode), $($r.Content.Trim())"
} catch { Note "ids-test: $($_.Exception.Message)" }

# 2. Endpoint layer: the Microsoft Defender for Endpoint detection test documented for onboarding checks.
#    The download from 127.0.0.1 fails by design; the command line itself is what raises the alert.
New-Item -ItemType Directory -Force 'C:\test-MDATP-test' | Out-Null
$test = "`$ErrorActionPreference = 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'"
Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-Command', $test)
Note 'mde-test: launched'

# 3. Endpoint layer: the EICAR anti-malware test file (HTTPS, so only the endpoint sees its content).
try {
    Invoke-WebRequest -UseBasicParsing -Uri 'https://secure.eicar.org/eicar.com.txt' -OutFile 'C:\nthc\eicar.com.txt' -TimeoutSec 20
    Note 'eicar: downloaded (Defender should quarantine it)'
} catch { Note "eicar: $($_.Exception.Message)" }

Start-Sleep -Seconds 20
Note ("eicar file present after 20 s: " + (Test-Path 'C:\nthc\eicar.com.txt'))
Get-Content $log
