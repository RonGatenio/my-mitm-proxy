#requires -RunAsAdministrator
<#
  Waits for the GW VM's unattended install to finish, then pushes the leaf cert
  and gw-provision.ps1 into it and runs provisioning - all over PowerShell Direct,
  so it needs no network to the GW yet. Run on the host after host-setup.ps1.
#>
[CmdletBinding()]
param(
  [string]$Lab = "C:\Users\RonGatenio\rdgw-lab",
  [string]$VM  = "rdgw-GW",
  [string]$Password = "1311"
)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
function Say($m){ Write-Host "[gw-configure] $m" -ForegroundColor Green }
$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString $Password -AsPlainText -Force))
if(-not(Test-Path "$Lab\certs\gw.pfx")){ throw "missing $Lab\certs\gw.pfx (run host-setup.ps1)" }

Say "waiting for $VM to finish installing + accept PowerShell Direct (up to ~30 min)..."
$name=$null
for($i=0;$i -lt 180;$i++){
  try { $name = Invoke-Command -VMName $VM -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop } catch {}
  if($name){ break }
  Start-Sleep 10
}
if(-not $name){ throw "$VM not reachable via PowerShell Direct - is the install done? (check the VM console)" }
Say "$VM up as computername '$name'"

$s = New-PSSession -VMName $VM -Credential $cred
try {
  Invoke-Command -Session $s -ScriptBlock { New-Item -ItemType Directory -Force C:\rdgw | Out-Null }
  Copy-Item -ToSession $s "$Lab\certs\gw.pfx"      -Destination "C:\rdgw\gw.pfx" -Force
  Copy-Item -ToSession $s "$Root\gw-provision.ps1" -Destination "C:\rdgw\gw-provision.ps1" -Force
  Say "pushed cert + provisioning script; running gw-provision.ps1 inside $VM ..."
  Invoke-Command -Session $s -FilePath "$Root\gw-provision.ps1"
}
finally { Remove-PSSession $s }

Say "GW provisioned. NEXT: .\b-deploy.ps1  then  mstsc (gateway gw.rdgw.test, computer 10.20.2.10, Administrator/1311)."
