param([string]$Node = 'node', [int]$Rounds = 4, [int]$SynN = 120)
# One-shot line test for developers. Run it as administrator, once per test session.
# It does a fixed sequence and exits; nothing stays running and nothing listens for commands:
#   0. measures with whatever is installed now (a running GoodbyeDPI service, if any)
#   1. stops that service and measures with no tool at all
#   2. runs the engine built in target\release (all features) and measures
#   3. runs the engine without re-dial, to show what re-dial contributes
#   4. stops the engine and starts the GoodbyeDPI service again if it was running
# Results: .dev\hat-testi.log and .dev\engine-*.log (the .dev folder is not committed).

$ErrorActionPreference = 'Continue'
$Repo = Split-Path $PSScriptRoot -Parent
$Dev  = Join-Path $Repo '.dev'
$Exe  = Join-Path $Repo 'target\release\sondpi.exe'
$Log  = Join-Path $Dev 'hat-testi.log'
New-Item -ItemType Directory -Force -Path $Dev | Out-Null
Remove-Item (Join-Path $Dev '*.log'), (Join-Path $Dev 'stop-*') -Force -ErrorAction SilentlyContinue

function L([string]$m) { Add-Content -Path $Log -Value $m -Encoding UTF8; Write-Host $m }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L "START $(Get-Date -Format s) admin=$isAdmin"
if (-not $isAdmin) { L 'NOT ELEVATED - abort'; L 'DONE'; exit 1 }
if (-not (Test-Path $Exe)) { L "missing $Exe (cargo build --release first)"; L 'DONE'; exit 1 }
Copy-Item (Join-Path $Repo 'vendor\windivert\WinDivert.dll'), (Join-Path $Repo 'vendor\windivert\WinDivert64.sys') -Destination (Split-Path $Exe) -Force

function Real([string]$name) {
  (Resolve-DnsName $name -Server 1.1.1.1 -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress
}
$TlsTargets = @()
foreach ($h in 'discord.com', 'gateway.discord.gg', 'cdn.discordapp.com', 'pastebin.com', 'www.roblox.com') { $ip = Real $h; if ($ip) { $TlsTargets += "$h=$ip" } }
$dIp = Real 'discord.com'; $cIp = Real 'www.cloudflare.com'; $gIp = Real 'www.google.com'
$SynTargets = @("discord=${dIp}:443", "cloudflare=${cIp}:443", "one.one=1.1.1.1:443", "google=${gIp}:443")
L "tls targets: $($TlsTargets -join ' ')"
L "syn targets: $($SynTargets -join ' ')"

$gw4 = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
$r6  = Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
$gw6 = if ($r6 -and $r6.NextHop -like 'fe80*') { "$($r6.NextHop)%$($r6.ifIndex)" } else { $null }

function Tls([int]$rounds) {
  $env:GD_PROBE_TO = '3000'
  $ok = 0; $total = 0
  for ($i = 1; $i -le $rounds; $i++) {
    $r = & $Node (Join-Path $Repo 'tools\probe.js') @TlsTargets 2>&1
    foreach ($x in $r) {
      $line = "$x"
      if ($line -notmatch 'bigCH') { continue }
      $f = ([regex]::Matches($line, '=FAIL')).Count
      $total += 2; $ok += (2 - $f)
      if ($f -gt 0) { L "    r$i $line" }
    }
  }
  L "  TLS (pinned real IPs): $ok/$total"
}

function Syn {
  $env:N = "$SynN"; $env:CONC = '10'; $env:TO = '3500'
  $r = & $Node (Join-Path $Repo 'tools\synprobe.js') @SynTargets 2>&1
  foreach ($x in $r) { L "  SYN $x" }
}

function Dns {
  foreach ($srv in @($gw4, $gw6)) {
    if (-not $srv) { continue }
    foreach ($n in 'discord.com', 'pastebin.com') {
      $sw = [Diagnostics.Stopwatch]::StartNew()
      $a = try { (Resolve-DnsName $n -Server $srv -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ',' } catch { "ERR $($_.Exception.Message)" }
      L ("  DNS via modem {0,-28} {1,-13} -> {2} ({3} ms)" -f $srv, $n, $a, $sw.ElapsedMilliseconds)
    }
  }
}

function EndToEnd {
  foreach ($u in 'https://discord.com/', 'https://pastebin.com/', 'https://www.roblox.com/', 'https://www.google.com/') {
    $o = & cmd /c "curl.exe -s -m 8 -o NUL -w ""%{http_code} ip=%{remote_ip} t=%{time_total}"" $u 2>&1"
    L ("  e2e {0,-26} {1}" -f $u, ($o -join ' '))
  }
  $o = & cmd /c "curl.exe -s -m 25 -o NUL -w ""%{http_code} %{size_download} bytes in %{time_total}s = %{speed_download} B/s"" ""https://speed.cloudflare.com/__down?bytes=25000000"" 2>&1"
  L "  download 25 MB from Cloudflare: $($o -join ' ')"
}

$script:proc = $null
function Start-Engine([string]$name, [string]$extra) {
  $elog = Join-Path $Dev "engine-$name.log"
  $stop = Join-Path $Dev "stop-$name"
  $a = "dev $extra --log `"$elog`" --stop-file `"$stop`" --stats-every 2000"
  L "  engine: sondpi.exe $a"
  $script:proc = Start-Process -FilePath $Exe -ArgumentList $a -WorkingDirectory (Split-Path $Exe) -PassThru -WindowStyle Hidden
  Start-Sleep -Milliseconds 2500
  if ($script:proc.HasExited) {
    L "  ENGINE EXITED EARLY code=$($script:proc.ExitCode)"
    if (Test-Path $elog) { Get-Content $elog -Tail 20 | ForEach-Object { L "    | $_" } }
    $script:proc = $null
    return $false
  }
  return $true
}
function Stop-Engine([string]$name) {
  $elog = Join-Path $Dev "engine-$name.log"
  if ($script:proc -and -not $script:proc.HasExited) {
    Set-Content -Path (Join-Path $Dev "stop-$name") -Value 'stop' -Encoding ASCII
    if (-not $script:proc.WaitForExit(8000)) { L '  engine did not stop in 8 s - killing'; Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue; [void]$script:proc.WaitForExit(3000) }
    else { L "  engine stopped, exit code $($script:proc.ExitCode)" }
  } elseif ($script:proc) { L "  ENGINE DIED DURING THE PHASE, exit code $($script:proc.ExitCode)" }
  $script:proc = $null
  if (Test-Path $elog) {
    $all = Get-Content $elog
    L ("  engine log: {0} lines; alt SYNs={1} won-by-alt={2} won-by-orig={3} loser-rst={4} gave-up={5} map-close={6} errors={7}" -f $all.Count,
      ($all | Select-String 'redial alt#').Count, ($all | Select-String 'by=alt').Count, ($all | Select-String 'by=orig').Count,
      ($all | Select-String 'loser-rst').Count, ($all | Select-String 'gave-up').Count, ($all | Select-String 'map close').Count,
      ($all | Select-String -Pattern 'FAILED|fatal|error' | Where-Object { $_.Line -notmatch 'send_err=0' }).Count)
    $all | Select-String -Pattern 'FAILED|fatal|panick' | Select-Object -First 8 | ForEach-Object { L "    | $($_.Line)" }
    $all | Select-String 'stats ' | Select-Object -Last 1 | ForEach-Object { L "    | $($_.Line)" }
  }
}

$gd = Get-Service GoodbyeDPI -ErrorAction SilentlyContinue
$gdWasRunning = ($gd -and $gd.Status -eq 'Running')
try {
  L "=== 0. as installed now (GoodbyeDPI service: $(if ($gd) { $gd.Status } else { 'not installed' }))"
  Tls 3
  Syn
  EndToEnd

  if ($gdWasRunning) { Stop-Service GoodbyeDPI -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Get-Process goodbyedpi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
  L '=== 1. no tool at all'
  Tls 1
  Dns

  L '=== 2. SONdpi engine, all features'
  if (Start-Engine 'tam' '') {
    Tls $Rounds
    Syn
    Dns
    EndToEnd
    Stop-Engine 'tam'
  }

  L '=== 3. SONdpi engine without re-dial (shows what re-dial adds)'
  if (Start-Engine 'redialsiz' '--no-redial') {
    Syn
    Stop-Engine 'redialsiz'
  }
}
finally {
  if ($script:proc -and -not $script:proc.HasExited) { Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue }
  Get-Process sondpi -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($gdWasRunning) {
    Start-Service GoodbyeDPI -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    L "=== 4. restored: GoodbyeDPI service is $((Get-Service GoodbyeDPI -ErrorAction SilentlyContinue).Status)"
    Tls 1
  }
  L "END $(Get-Date -Format s)"
  L 'DONE'
}
