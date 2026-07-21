#requires -RunAsAdministrator
<#
  Runs INSIDE the GW VM (Windows Server 2025), elevated. Turns a bare install into
  a working standalone RD Gateway that will demand NTLM auth and hand back a
  CHALLENGE_MESSAGE carrying this box's computername (RDGW1).

  gw-configure.ps1 (on the host) pushes this script + gw.pfx to C:\rdgw\ and
  invokes it over PowerShell Direct. Safe to re-run (idempotent).

  Manual fallback: everything here is also doable in Server Manager + RD Gateway
  Manager if a step fails.
#>
[CmdletBinding()]
param(
  [string]$IpAddress   = "10.20.2.10",
  [int]   $PrefixLen   = 24,
  [string]$Gateway     = "10.20.2.1",
  [string]$PfxPath     = "C:\rdgw\gw.pfx",
  [string]$PfxPassword = "1311"
)
$ErrorActionPreference = "Stop"
function Say($m){ Write-Host "[gw-provision] $m" -ForegroundColor Cyan }

# 1) Static IP toward B (single NIC on rdgw-right) --------------------------------
$nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $nic) { $nic = Get-NetAdapter -Physical | Select-Object -First 1 }
Say "using NIC '$($nic.Name)' (ifIndex $($nic.ifIndex))"
if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IpAddress -ErrorAction SilentlyContinue)) {
  Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IpAddress -PrefixLength $PrefixLen -DefaultGateway $Gateway | Out-Null
  Say "set $IpAddress/$PrefixLen gw $Gateway"
} else { Say "$IpAddress already configured" }

# 2) RD Gateway role -------------------------------------------------------------
if (-not (Get-WindowsFeature RDS-Gateway).Installed) {
  Say "installing RDS-Gateway role (a few minutes)..."
  Install-WindowsFeature -Name RDS-Gateway -IncludeManagementTools | Out-Null
} else { Say "RDS-Gateway already installed" }
Import-Module RemoteDesktopServices -ErrorAction Stop

# 3) Bind the real leaf cert (the one B also holds) ------------------------------
$sec = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $sec
Say "imported cert $($cert.Thumbprint) ($($cert.Subject))"
Set-Item -Path "RDS:\GatewayServer\SSLCertificate\SSLCertSHA1Hash" -Value $cert.Thumbprint
Say "bound cert to RD Gateway"

# 4) CAP (who may use the gateway) + RAP (what they may reach) -------------------
#    AuthMethod 1 = password (NTLM/Negotiate).  ComputerGroupType 2 = any resource.
$grp = "Administrators@$env:COMPUTERNAME"
if (Test-Path "RDS:\GatewayServer\CAP\rdgw-cap") { Remove-Item "RDS:\GatewayServer\CAP\rdgw-cap" -Recurse -Force }
New-Item -Path "RDS:\GatewayServer\CAP\rdgw-cap" -UserGroups $grp -AuthMethod 1 | Out-Null
Say "CAP rdgw-cap -> $grp (password auth)"
if (Test-Path "RDS:\GatewayServer\RAP\rdgw-rap") { Remove-Item "RDS:\GatewayServer\RAP\rdgw-rap" -Recurse -Force }
New-Item -Path "RDS:\GatewayServer\RAP\rdgw-rap" -UserGroups $grp -ComputerGroupType 2 | Out-Null
Say "RAP rdgw-rap -> any resource"

# 5) RDP on this box so it can be its own session host ---------------------------
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Say "RDP enabled"

Restart-Service TSGateway
Say "TSGateway restarted. Gateway host name: gw.rdgw.test ($IpAddress). Connect user: Administrator / 1311."
Say "DONE"
