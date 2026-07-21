#requires -RunAsAdministrator
<#
  Recreate B as a Generation 1 (BIOS) VM, reusing the same VHDX + cloud-init seed.
  Debian cloud images boot reliably under BIOS (this is what the tests/vm QEMU
  harness uses); Gen2/UEFI can fail to find the bootloader and sit dead at
  "Running" with no OS. Run this if B's console shows a boot failure / UEFI shell
  / PXE attempt rather than a Debian login prompt.
#>
[CmdletBinding()]
param([string]$Lab = "C:\Users\RonGatenio\rdgw-lab")
$ErrorActionPreference = "Stop"
$BVhdx="$Lab\b-vm\rdgw-B.vhdx"; $SeedIso="$Lab\b-seed.iso"
$SwLeft="rdgw-left"; $SwRight="rdgw-right"
$MacBLeft="00155D200101"; $MacBRight="00155D200201"
function Say($m){ Write-Host "[fix-b-gen1] $m" -ForegroundColor Green }
foreach($f in @($BVhdx,$SeedIso)){ if(-not(Test-Path $f)){ throw "missing $f (run host-setup.ps1 first)" } }

if (Get-VM rdgw-B -ErrorAction SilentlyContinue){
  Stop-VM rdgw-B -TurnOff -Force -ErrorAction SilentlyContinue
  Remove-VM rdgw-B -Force    # keeps the VHDX file on disk
  Say "removed old rdgw-B (VHDX kept)"
}
New-VM -Name rdgw-B -Generation 1 -MemoryStartupBytes 1GB -VHDPath $BVhdx -SwitchName $SwLeft | Out-Null
Set-VMProcessor rdgw-B -Count 2
$a=Get-VMNetworkAdapter -VMName rdgw-B | Select-Object -First 1
Rename-VMNetworkAdapter -VMNetworkAdapter $a -NewName left0
Set-VMNetworkAdapter -VMName rdgw-B -Name left0 -StaticMacAddress $MacBLeft
Add-VMNetworkAdapter -VMName rdgw-B -Name right0 -SwitchName $SwRight -StaticMacAddress $MacBRight
Add-VMDvdDrive -VMName rdgw-B -Path $SeedIso
Start-VM rdgw-B
Say "rdgw-B recreated as Gen1 (BIOS) + started. Give it ~1 min, then: .\b-deploy.ps1"
