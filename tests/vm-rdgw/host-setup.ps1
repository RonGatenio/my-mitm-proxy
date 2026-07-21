#requires -RunAsAdministrator
<#
  Elevated, on THIS Windows host. Stands up the RD Gateway bring-up lab:
    - two Internal vSwitches (rdgw-left host<->B, rdgw-right B<->GW)
    - host vEthernet IP + route so mstsc traffic to GW transits B
    - a self-signed leaf for gw.rdgw.test (bound on GW, split to PEM for B, trusted here)
    - B  = Debian 11 / kernel 5.10 proxy VM (from the prepared VHDX + cloud-init seed)
    - GW = Windows Server 2025 VM (unattended install from the eval ISO)

  Idempotent: re-running skips things that already exist. Uses WSL for
  openssl / cloud-localds / genisoimage (host has internet in WSL).

  After this: wait for GW's unattended install (~15-20 min), then run
  gw-configure.ps1, then b-deploy.ps1. See README.md.
#>
[CmdletBinding()]
param(
  [string]$Lab      = "C:\Users\RonGatenio\rdgw-lab",
  [string]$WinIso   = "C:\Users\RonGatenio\rdgw-lab\iso\WS2025-eval.iso",
  [string]$BBaseVhdx= "C:\Users\RonGatenio\rdgw-lab\b-vm\debian11.vhdx",
  [string]$WslDistro= "Ubuntu-24.04"
)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
function Say($m){ Write-Host "[host-setup] $m" -ForegroundColor Green }
function WslPath([string]$p){ $d=$p.Substring(0,1).ToLower(); "/mnt/$d"+($p.Substring(2) -replace '\\','/') }
function Invoke-WslBash([string]$script){
  ($script -replace "`r","") | wsl.exe -d $WslDistro -- bash -s
  if ($LASTEXITCODE -ne 0){ throw "wsl bash failed (exit $LASTEXITCODE)" }
}

# ---- topology constants --------------------------------------------------------
$SwLeft="rdgw-left"; $SwRight="rdgw-right"
$HostLeftIp="10.20.1.5"; $BLeftIp="10.20.1.1"; $BRightIp="10.20.2.1"; $GwIp="10.20.2.10"; $Pfx=24
$RightNet="10.20.2.0/24"
$MacBLeft="00155D200101"; $MacBRight="00155D200201"; $MacGw="00155D20020A"
$GwName="gw.rdgw.test"; $CertPw="1311"
$CertDir="$Lab\certs"; $SeedDir="$Lab\b-seed"
$BVhdx="$Lab\b-vm\rdgw-B.vhdx"; $GwVhdx="$Lab\gw-vm\gw.vhdx"
$SeedIso="$Lab\b-seed.iso"; $UnattendIso="$Lab\gw-vm\autounattend.iso"

New-Item -ItemType Directory -Force $CertDir,$SeedDir,"$Lab\gw-vm" | Out-Null
if (-not (Test-Path $WinIso))    { throw "missing WS2025 ISO: $WinIso" }
if (-not (Test-Path $BBaseVhdx)) { throw "missing Debian base VHDX: $BBaseVhdx" }

# ---- 1. vSwitches --------------------------------------------------------------
foreach($sw in @($SwLeft,$SwRight)){
  if (-not (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue)){
    New-VMSwitch -Name $sw -SwitchType Internal | Out-Null; Say "created switch $sw"
  } else { Say "switch $sw exists" }
}

# ---- 2. host networking on rdgw-left ------------------------------------------
$hostAlias = "vEthernet ($SwLeft)"
$idx = (Get-NetAdapter -Name $hostAlias -ErrorAction SilentlyContinue).ifIndex
if (-not $idx){ throw "host adapter '$hostAlias' not found (switch just created?) - re-run" }
if (-not (Get-NetIPAddress -InterfaceIndex $idx -IPAddress $HostLeftIp -ErrorAction SilentlyContinue)){
  New-NetIPAddress -InterfaceIndex $idx -IPAddress $HostLeftIp -PrefixLength $Pfx | Out-Null
  Say "host $HostLeftIp/$Pfx on '$hostAlias'"
}
if (-not (Get-NetRoute -DestinationPrefix $RightNet -ErrorAction SilentlyContinue | Where-Object NextHop -eq $BLeftIp)){
  New-NetRoute -DestinationPrefix $RightNet -InterfaceIndex $idx -NextHop $BLeftIp -RouteMetric 1 | Out-Null
  Say "route $RightNet -> $BLeftIp"
}
$hosts="$env:WinDir\System32\drivers\etc\hosts"
if (-not (Select-String -Path $hosts -Pattern ([regex]::Escape($GwName)) -Quiet)){
  Add-Content $hosts "`r`n$GwIp`t$GwName"; Say "hosts: $GwIp $GwName"
}

# ---- 3. cert for gw.rdgw.test --------------------------------------------------
if (-not (Test-Path "$CertDir\gw.pfx")){
  $cert = New-SelfSignedCertificate -Subject "CN=$GwName" -DnsName $GwName,$GwIp `
            -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(2) -KeyUsage DigitalSignature,KeyEncipherment `
            -Type SSLServerAuthentication
  $sec = ConvertTo-SecureString $CertPw -AsPlainText -Force
  Export-PfxCertificate -Cert $cert -FilePath "$CertDir\gw.pfx" -Password $sec | Out-Null
  Export-Certificate -Cert $cert -FilePath "$CertDir\gw.cer" | Out-Null
  Import-Certificate -FilePath "$CertDir\gw.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  Say "cert $($cert.Thumbprint) created, exported, trusted on host"
  # split PFX -> PEM cert + key for mymitm (via WSL openssl; AES pfx, fall back to -legacy)
  $pfxW=(WslPath "$CertDir\gw.pfx"); $pemW=(WslPath "$CertDir\leaf.pem"); $keyW=(WslPath "$CertDir\leaf.key")
  Invoke-WslBash @"
set -e
openssl pkcs12 -in '$pfxW' -nokeys -clcerts -out '$pemW' -passin pass:$CertPw 2>/dev/null || \
  openssl pkcs12 -legacy -in '$pfxW' -nokeys -clcerts -out '$pemW' -passin pass:$CertPw
openssl pkcs12 -in '$pfxW' -nocerts -nodes -out '$keyW' -passin pass:$CertPw 2>/dev/null || \
  openssl pkcs12 -legacy -in '$pfxW' -nocerts -nodes -out '$keyW' -passin pass:$CertPw
echo 'PEM/key written'
"@
} else { Say "cert already present in $CertDir" }

# ---- 4. B cloud-init seed ------------------------------------------------------
if (-not (Test-Path "$Lab\b_key")){ & ssh-keygen -t ed25519 -N '""' -f "$Lab\b_key" | Out-Null; Say "ssh key $Lab\b_key" }
$pub = (Get-Content "$Lab\b_key.pub" -Raw).Trim()
$ud  = (Get-Content "$Root\b-cloud-init\user-data" -Raw).Replace("__SSH_PUBKEY__",$pub)
# write seed inputs with LF endings
[IO.File]::WriteAllText("$SeedDir\user-data",     ($ud -replace "`r",""))
[IO.File]::WriteAllText("$SeedDir\meta-data",     ((Get-Content "$Root\b-cloud-init\meta-data" -Raw) -replace "`r",""))
[IO.File]::WriteAllText("$SeedDir\network-config",((Get-Content "$Root\b-cloud-init\network-config" -Raw) -replace "`r",""))
$sd=(WslPath $SeedDir); $iso=(WslPath $SeedIso)
Invoke-WslBash @"
set -e
command -v cloud-localds >/dev/null || sudo apt-get install -y cloud-image-utils
command -v genisoimage   >/dev/null || sudo apt-get install -y genisoimage
cloud-localds --network-config='$sd/network-config' '$iso' '$sd/user-data' '$sd/meta-data'
echo 'seed built'
"@
Say "B seed: $SeedIso"

# ---- 5. B VM (Debian, Gen2) ----------------------------------------------------
if (-not (Get-VM -Name rdgw-B -ErrorAction SilentlyContinue)){
  Copy-Item $BBaseVhdx $BVhdx -Force
  New-VM -Name rdgw-B -Generation 2 -MemoryStartupBytes 1GB -VHDPath $BVhdx -SwitchName $SwLeft | Out-Null
  Set-VMProcessor rdgw-B -Count 2
  Set-VMFirmware rdgw-B -EnableSecureBoot Off
  # NIC 1 -> left0 on rdgw-left ; NIC 2 -> right0 on rdgw-right
  $a=Get-VMNetworkAdapter -VMName rdgw-B | Select-Object -First 1
  Rename-VMNetworkAdapter -VMNetworkAdapter $a -NewName left0
  Set-VMNetworkAdapter -VMName rdgw-B -Name left0 -StaticMacAddress $MacBLeft
  Add-VMNetworkAdapter -VMName rdgw-B -Name right0 -SwitchName $SwRight -StaticMacAddress $MacBRight
  Add-VMDvdDrive -VMName rdgw-B -Path $SeedIso
  Start-VM rdgw-B
  Say "B created + started (boots via cloud-init; SSH at $BLeftIp)"
} else { Say "VM rdgw-B exists (skipping create)" }

# ---- 6. GW VM (Windows Server 2025, Gen2, unattended) --------------------------
if (-not (Get-VM -Name rdgw-GW -ErrorAction SilentlyContinue)){
  # tiny ISO carrying autounattend.xml at its root
  $uroot=(WslPath "$Lab\gw-vm"); $ubuild=(WslPath $Root)
  Invoke-WslBash @"
set -e
mkdir -p '$uroot/ua'
cp '$ubuild/autounattend.xml' '$uroot/ua/autounattend.xml'
genisoimage -quiet -o '$(WslPath $UnattendIso)' -J -r -V UNATTEND '$uroot/ua'
echo 'autounattend.iso built'
"@
  New-VHD -Path $GwVhdx -SizeBytes 60GB -Dynamic | Out-Null
  New-VM -Name rdgw-GW -Generation 2 -MemoryStartupBytes 4GB -VHDPath $GwVhdx -SwitchName $SwRight | Out-Null
  Set-VMProcessor rdgw-GW -Count 2
  Set-VMMemory rdgw-GW -DynamicMemoryEnabled $false
  $g=Get-VMNetworkAdapter -VMName rdgw-GW | Select-Object -First 1
  Rename-VMNetworkAdapter -VMNetworkAdapter $g -NewName gw0
  Set-VMNetworkAdapter -VMName rdgw-GW -Name gw0 -StaticMacAddress $MacGw
  $dvdWin = Add-VMDvdDrive -VMName rdgw-GW -Path $WinIso -Passthru
  Add-VMDvdDrive -VMName rdgw-GW -Path $UnattendIso
  Enable-VMIntegrationService -VMName rdgw-GW -Name "Guest Service Interface"
  Set-VMFirmware rdgw-GW -FirstBootDevice $dvdWin
  Start-VM rdgw-GW
  Say "GW created + started; unattended WS2025 install running (~15-20 min)"
} else { Say "VM rdgw-GW exists (skipping create)" }

Write-Host ""
Say "NEXT:"
Say "  1) wait for GW install to finish (C:\rdgw-firstlogon-done.txt appears; or it sits at the desktop)"
Say "  2) .\gw-configure.ps1     # pushes cert + runs gw-provision.ps1 inside GW"
Say "  3) .\b-deploy.ps1         # pushes mymitm to B and starts the proxy"
Say "  4) mstsc: gateway=$GwName, computer=$GwIp, creds=Administrator/1311; then inspect B:/opt/mymitm/dumps"
