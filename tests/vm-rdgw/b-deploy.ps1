<#
  Push mymitm + the GW leaf cert to B and start the proxy. Run on the host after
  host-setup.ps1 (B boots quickly via cloud-init). Re-runnable.

  Discovers the real interface names for B's two MACs and writes mymitm.toml with
  them, so it works whether or not cloud-init's set-name rename to left0/right0
  stuck on Debian.
#>
[CmdletBinding()]
param(
  [string]$Lab   = "C:\Users\RonGatenio\rdgw-lab",
  [string]$BHost = "10.20.1.1",
  [string]$User  = "admin"
)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Repo = (Resolve-Path "$Root\..\..").Path
$Bin  = "$Repo\target\x86_64-unknown-linux-musl\release\mymitm"
$Key  = "$Lab\b_key"
$Pem  = "$Lab\certs\leaf.pem"; $KeyPem = "$Lab\certs\leaf.key"
$MacLeft="00:15:5d:20:01:01"; $MacRight="00:15:5d:20:02:01"
$LocalAddr="10.20.1.1"; $GwIp="10.20.2.10"; $BoxIp="10.20.2.1"
function Say($m){ Write-Host "[b-deploy] $m" -ForegroundColor Green }
foreach($f in @($Bin,$Pem,$KeyPem,$Key)){ if(-not(Test-Path $f)){ throw "missing: $f (run host-setup.ps1 / build first)" } }

$O = @('-i',$Key,'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=NUL','-o','BatchMode=yes','-o','ConnectTimeout=5')
function BSsh([string]$cmd){ & ssh @O "$User@$BHost" $cmd }
function BScp([string]$src,[string]$dst){ & scp @O $src "$User@${BHost}:$dst"; if($LASTEXITCODE){throw "scp $src failed"} }

Say "waiting for B SSH at $BHost ..."
$ok=$false
for($i=0;$i -lt 90;$i++){ & ssh @O "$User@$BHost" "true" 2>$null 1>$null; if($LASTEXITCODE -eq 0){$ok=$true;break}; Start-Sleep 2 }
if(-not $ok){ throw "B never became SSH-reachable at $BHost (check the VM console / cloud-init)" }
Say "B reachable"

# map MACs -> interface names on B
$map = BSsh "for m in $MacLeft $MacRight; do for d in /sys/class/net/*; do [ -f `$d/address ] && [ `"`$(cat `$d/address)`" = `"`$m`" ] && echo `$m `$(basename `$d); done; done"
$tun = ($map | Where-Object { $_ -match $MacLeft }  | ForEach-Object { ($_ -split ' ')[1] }) | Select-Object -First 1
$egr = ($map | Where-Object { $_ -match $MacRight } | ForEach-Object { ($_ -split ' ')[1] }) | Select-Object -First 1
if(-not $tun -or -not $egr){ throw "could not resolve B interfaces from MACs. Got:`n$map" }
Say "interfaces: tun=$tun (left) egress=$egr (right)"

# deliver binary + cert + key
BScp $Bin    "/tmp/mymitm"
BScp $Pem    "/tmp/leaf.pem"
BScp $KeyPem "/tmp/leaf.key"

$toml = @"
target_server_ip = "$GwIp"
target_server_port = 443
box_ip = "$BoxIp"
cert_path = "/opt/mymitm/leaf.pem"
key_path = "/opt/mymitm/leaf.key"
tun_iface = "$tun"
egress_iface = "$egr"
local_addr = "$LocalAddr"
local_port = 8443
fwmark = 0x1337
dump_path = "/opt/mymitm/dumps"
log_level = "info"
server_name = "gw.rdgw.test"
data_plane = "ebpf"
"@
# hand the toml to B over stdin, place files, set route_localnet, (re)start
$install = @"
set -e
sudo install -m0755 /tmp/mymitm /opt/mymitm/mymitm
sudo install -m0644 /tmp/leaf.pem /opt/mymitm/leaf.pem
sudo install -m0600 /tmp/leaf.key /opt/mymitm/leaf.key
sudo tee /opt/mymitm/mymitm.toml >/dev/null <<'TOML'
$toml
TOML
sudo sysctl -wq net.ipv4.conf.$tun.route_localnet=1
sudo mkdir -p /opt/mymitm/dumps
sudo rm -f /opt/mymitm/dumps/*
sudo systemctl daemon-reload
sudo systemctl restart mymitm
"@
$install -replace "`r","" | & ssh @O "$User@$BHost" "bash -s"
if($LASTEXITCODE){ throw "install/start on B failed" }

Say "waiting for proxy readiness ..."
$up=$false; for($i=0;$i -lt 40;$i++){
  $j = BSsh "sudo journalctl -u mymitm --no-pager -n40 2>/dev/null"
  if($j -match "listening|proxy listening|entering proxy loop"){ $up=$true; break }
  if($j -match "panic|error|Error"){ Say "proxy log so far:`n$j"; break }
  Start-Sleep 1
}
if($up){ Say "mymitm is up on B (tun=$tun egress=$egr, target $GwIp:443)" }
else   { Say "did not see readiness; dumping recent log:"; BSsh "sudo journalctl -u mymitm --no-pager -n60" }
Say "dumps will appear in B:/opt/mymitm/dumps  (inspect .s2c for the NTLM challenge)"
