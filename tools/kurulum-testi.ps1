param([string]$Node = 'node', [int]$TrayWindowSec = 150)
# One-shot install test for developers. Run it as administrator, once per test session.
# Fixed sequence, then it exits; nothing stays installed afterwards:
#   1. stops a running GoodbyeDPI service (it must not run next to SONdpi)
#   2. installs SONdpi from target\release (service, files), checks what was created
#   3. measures through the service, flips the switch off and on over the control pipe
#   4. stops/starts the service through the SCM and checks the switch position survives
#   5. starts the tray unelevated, clicks it, then leaves it up for $TrayWindowSec seconds
#      (or until the file .dev\devam appears) so a person can look at it and click it
#   6. uninstalls from the installed copy and checks nothing is left
#   7. starts the GoodbyeDPI service again if it was running
# Results: .dev\kurulum-testi.log

$ErrorActionPreference = 'Continue'
$Repo = Split-Path $PSScriptRoot -Parent
$Dev  = Join-Path $Repo '.dev'
$Src  = Join-Path $Repo 'target\release\sondpi.exe'
$Dir  = Join-Path $env:ProgramFiles 'SONdpi'
$Inst = Join-Path $Dir 'sondpi.exe'
$Log  = Join-Path $Dev 'kurulum-testi.log'
$Go   = Join-Path $Dev 'devam'
New-Item -ItemType Directory -Force -Path $Dev | Out-Null
Remove-Item $Log, $Go, (Join-Path $Dev '*-result.txt') -Force -ErrorAction SilentlyContinue

function L([string]$m) { Add-Content -Path $Log -Value $m -Encoding UTF8; Write-Host $m }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L "START $(Get-Date -Format s) admin=$isAdmin"
if (-not $isAdmin) { L 'NOT ELEVATED - abort'; L 'DONE'; exit 1 }
if (-not (Test-Path $Src)) { L "missing $Src"; L 'DONE'; exit 1 }
Copy-Item (Join-Path $Repo 'vendor\windivert\WinDivert.dll'), (Join-Path $Repo 'vendor\windivert\WinDivert64.sys') -Destination (Split-Path $Src) -Force

# Run a program, capture its output, never hang.
function Run([string]$exe, [string]$argline, [int]$timeoutSec) {
  $o = Join-Path $Dev 'run-out.txt'; $e = Join-Path $Dev 'run-err.txt'
  Remove-Item $o, $e -Force -ErrorAction SilentlyContinue
  $p = Start-Process -FilePath $exe -ArgumentList $argline -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $p.WaitForExit($timeoutSec * 1000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; return @{ code = 'TIMEOUT'; out = '' } }
  $txt = @(); foreach ($f in $o, $e) { if (Test-Path $f) { $txt += (Get-Content $f -Encoding UTF8) } }
  return @{ code = $p.ExitCode; out = ($txt -join ' | ') }
}
function Ctl([string]$a) { $r = Run $Inst "ctl $a" 30; L ("  ctl {0,-6} -> exit {1}  {2}" -f $a, $r.code, $r.out); return $r }

function Real([string]$name) { (Resolve-DnsName $name -Server 1.1.1.1 -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress }
$TlsTargets = @()
foreach ($h in 'discord.com', 'gateway.discord.gg', 'pastebin.com', 'www.roblox.com') { $ip = Real $h; if ($ip) { $TlsTargets += "$h=$ip" } }
$SynTargets = @("discord=$(Real 'discord.com'):443", "cloudflare=$(Real 'www.cloudflare.com'):443")
function Tls([int]$rounds, [string]$expect) {
  $env:GD_PROBE_TO = '3000'; $ok = 0; $total = 0
  for ($i = 1; $i -le $rounds; $i++) {
    $r = & $Node (Join-Path $Repo 'tools\probe.js') @TlsTargets 2>&1
    foreach ($x in $r) { $line = "$x"; if ($line -notmatch 'bigCH') { continue }; $f = ([regex]::Matches($line, '=FAIL')).Count; $total += 2; $ok += (2 - $f) }
  }
  L "  TLS to blocked names: $ok/$total   (expected: $expect)"
}
function Syn { $env:N = '80'; $env:CONC = '10'; $env:TO = '3500'; $r = & $Node (Join-Path $Repo 'tools\synprobe.js') @SynTargets 2>&1; foreach ($x in $r) { L "  SYN $x" } }
function SvcLine { $s = Get-CimInstance Win32_Service -Filter "Name='SONdpi'" -ErrorAction SilentlyContinue; if ($s) { "state=$($s.State) start=$($s.StartMode) account=$($s.StartName) path=$($s.PathName)" } else { 'NOT INSTALLED' } }
function Enabled { $v = (Get-ItemProperty 'HKLM:\SOFTWARE\SONdpi' -ErrorAction SilentlyContinue).Enabled; if ($null -eq $v) { '(no value)' } else { "$v" } }

$gd = Get-Service GoodbyeDPI -ErrorAction SilentlyContinue
$gdWasRunning = ($gd -and $gd.Status -eq 'Running')
try {
  L "=== 1. stop GoodbyeDPI (was: $(if ($gd) { $gd.Status } else { 'not installed' }))"
  if ($gdWasRunning) { Stop-Service GoodbyeDPI -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Get-Process goodbyedpi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }

  L '=== 2. install'
  $res = Join-Path $Dev 'install-result.txt'
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = Run $Src "install --no-tray --no-autostart --result `"$res`"" 120
  L "  install exit=$($r.code) in $($sw.ElapsedMilliseconds) ms: $(if (Test-Path $res) { Get-Content $res -Encoding UTF8 } else { '(no result file)' }) $($r.out)"
  L "  service: $(SvcLine)"
  if (Test-Path $Dir) { Get-ChildItem $Dir | ForEach-Object { L ("  file {0,-18} {1}" -f $_.Name, $_.Length) } } else { L "  $Dir MISSING" }
  $fa = (sc.exe qfailure SONdpi | Out-String) -replace '\s+', ' '
  L "  failure actions: $fa"
  L "  registry Enabled: $(Enabled)"

  L '=== 3. through the service'
  Start-Sleep -Seconds 4
  [void](Ctl 'status')
  Tls 2 'all pass'
  Syn
  [void](Ctl 'off')
  Tls 1 'all fail (engine off, no other tool)'
  [void](Ctl 'on')
  Tls 1 'all pass'
  L "  registry Enabled: $(Enabled)"

  L '=== 4. service control manager'
  $sw.Restart(); Stop-Service SONdpi -ErrorAction SilentlyContinue
  L "  stop took $($sw.ElapsedMilliseconds) ms -> $(SvcLine)"
  [void](Ctl 'status')
  $sw.Restart(); Start-Service SONdpi -ErrorAction SilentlyContinue; Start-Sleep -Seconds 4
  L "  start -> $(SvcLine)"
  [void](Ctl 'status')
  [void](Ctl 'off')
  Restart-Service SONdpi -ErrorAction SilentlyContinue; Start-Sleep -Seconds 4
  L "  restarted while switched off -> registry Enabled: $(Enabled)"
  [void](Ctl 'status')
  [void](Ctl 'on')
  $svcLog = Join-Path $Dir 'service.log'
  if (Test-Path $svcLog) { L '  service.log (tail):'; Get-Content $svcLog -Tail 12 -Encoding UTF8 | ForEach-Object { L "    | $_" } }

  L '=== 5. tray, unelevated'
  Start-Process explorer.exe -ArgumentList "`"$Inst`""
  Start-Sleep -Seconds 5
  $tp = Get-CimInstance Win32_Process -Filter "Name='sondpi.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -notmatch ' service' }
  L "  tray processes: $(@($tp).Count)"
  [void](Ctl 'tip')
  [void](Ctl 'click'); Start-Sleep -Seconds 3
  [void](Ctl 'status'); [void](Ctl 'tip')
  [void](Ctl 'click'); Start-Sleep -Seconds 3
  [void](Ctl 'status'); [void](Ctl 'tip')
  L "TRAY-WINDOW open for $TrayWindowSec s (create .dev\devam to continue sooner)"
  $t0 = Get-Date
  while (-not (Test-Path $Go) -and ((Get-Date) - $t0).TotalSeconds -lt $TrayWindowSec) { Start-Sleep -Milliseconds 500 }
  L "TRAY-WINDOW closed after $([int]((Get-Date) - $t0).TotalSeconds) s"
  [void](Ctl 'status')

  L '=== 6. uninstall (from the installed copy, as the tray menu does)'
  $res = Join-Path $Dev 'uninstall-result.txt'
  $sw.Restart()
  $r = Run $Inst "uninstall --result `"$res`"" 120
  L "  uninstall exit=$($r.code) in $($sw.ElapsedMilliseconds) ms: $(if (Test-Path $res) { Get-Content $res -Encoding UTF8 } else { '(no result file)' }) $($r.out)"
  Start-Sleep -Seconds 8
  L "  service: $(SvcLine)"
  L "  install folder: $(if (Test-Path $Dir) { 'STILL THERE: ' + ((Get-ChildItem $Dir -Force | ForEach-Object Name) -join ', ') } else { 'gone' })"
  L "  HKLM\SOFTWARE\SONdpi: $(if (Test-Path 'HKLM:\SOFTWARE\SONdpi') { 'STILL THERE' } else { 'gone' })"
  $run = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).SONdpi
  L "  HKCU Run value: $(if ($run) { "STILL THERE: $run" } else { 'none' })"
  L "  sondpi processes: $(@(Get-Process sondpi -ErrorAction SilentlyContinue).Count)"
  $wd = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
  L "  WinDivert driver entry: $(if ($wd) { "$($wd.State) $($wd.PathName)" } else { 'none' })"
}
finally {
  if (Get-Service SONdpi -ErrorAction SilentlyContinue) {
    L '  CLEANUP: SONdpi service still present -> removing'
    sc.exe stop SONdpi | Out-Null; Start-Sleep -Seconds 3; sc.exe delete SONdpi | ForEach-Object { L "    $_" }
  }
  Get-Process sondpi -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($Dir, [StringComparison]::OrdinalIgnoreCase) } | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($gdWasRunning) {
    Start-Service GoodbyeDPI -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3
    if ((Get-Service GoodbyeDPI).Status -ne 'Running') {
      L '  GoodbyeDPI did not start; clearing a stale WinDivert entry and retrying'
      sc.exe delete WinDivert | Out-Null; Start-Sleep -Seconds 1; Start-Service GoodbyeDPI -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3
    }
    L "=== 7. restored: GoodbyeDPI service is $((Get-Service GoodbyeDPI -ErrorAction SilentlyContinue).Status)"
    Tls 1 'all pass (GoodbyeDPI)'
  }
  L "END $(Get-Date -Format s)"
  L 'DONE'
}
