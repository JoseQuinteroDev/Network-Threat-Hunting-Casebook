<#
.SYNOPSIS
    Remove the case 03 lab: delete the resource group, return Defender for Servers to the free tier and delete the
    local lab secrets. The evidence in results/case03 is kept.
#>
param([string] $ResourceGroup = "rg-nthc-soclab")
$ErrorActionPreference = "Continue"
$here = $PSScriptRoot

Write-Host "Deleting resource group $ResourceGroup (VMs, network, workspace, Sentinel content)..."
az group delete -n $ResourceGroup --yes 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "resource group deleted" } else { Write-Warning "az group delete returned $LASTEXITCODE" }

# Defender for Servers is a subscription setting: switch it back so nothing is billed after the trial.
az security pricing create -n VirtualMachines --tier free -o none 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "Defender for Servers set back to the free tier" }

Get-ChildItem $here -Filter "*.local*" | ForEach-Object { Remove-Item -LiteralPath $_.FullName; Write-Host "removed $($_.Name)" }
