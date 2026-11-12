param([string]$Repo = (Split-Path $PSScriptRoot -Parent))
# Development helper. Run it ONCE as administrator; it then starts and stops the engine built in
# this repository on request, so that every test run does not need its own UAC prompt.
#
# Requests are text files dropped into <repo>\.dev\req ; the answer appears under the same name
# in <repo>\.dev\res. First line of a request:
#   start <args...>      (re)start  target\release\sondpi.exe dev <args...>  with --log and --stop-file
#   stop                 stop the engine
#   gdpi stop|start      stop/start the installed GoodbyeDPI service (it must not run next to the engine)
#   status               what is running
#   quit                 stop the engine and close this helper
#
# SECURITY: while this window is open, any program running under this user account can make it
# run the repository's build as administrator. Close the window when the test session is over.

$ErrorActionPreference = 'Continue'
$Dev  = Join-Path $Repo '.dev'
$Req  = Join-Path $Dev 'req'
$Res  = Join-Path $Dev 'res'
$Exe  = Join-Path $Repo 'target\release\sondpi.exe'
$Log  = Join-Path $Dev 'engine.log'
$Stop = Join-Path $Dev 'stop'
New-Item -ItemType Directory -Force -Path $Req, $Res | Out-Null
Get-ChildItem $Req -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Yonetici olarak calistirilmali.'; Start-Sleep 5; exit 1 }
$Host.UI.RawUI.WindowTitle = 'SONdpi gelistirme kosucusu - kapatmak icin pencereyi kapat'
Write-Host "SONdpi gelistirme kosucusu hazir. Depo: $Repo"
Write-Host 'Bu pencere acikken motor denemeleri yonetici onayi sormadan calisir. Is bitince kapat.'

$script:proc = $null

function Engine-Running { return ($script:proc -and -not $script:proc.HasExited) }

function Stop-Engine {
  if (Engine-Running) {
    Set-Content -Path $Stop -Value 'stop' -Encoding ASCII
    if (-not $script:proc.WaitForExit(4000)) { Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue; [void]$script:proc.WaitForExit(3000) }
  }
  Get-Process sondpi -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force -ErrorAction SilentlyContinue
  Remove-Item $Stop -Force -ErrorAction SilentlyContinue
  $script:proc = $null
}

function Tail-Log([int]$n) { if (Test-Path $Log) { return (Get-Content $Log -Tail $n) -join "`n" } else { return '(log yok)' } }

function Handle([string]$line) {
  $parts = $line.Trim() -split '\s+', 2
  $verb = $parts[0].ToLower()
  $rest = if ($parts.Count -gt 1) { $parts[1] } else { '' }
  switch ($verb) {
    'start' {
      Stop-Engine
      if (-not (Test-Path $Exe)) { return "HATA: $Exe yok (once cargo build --release)" }
      Copy-Item (Join-Path $Repo 'vendor\windivert\WinDivert.dll'), (Join-Path $Repo 'vendor\windivert\WinDivert64.sys') -Destination (Split-Path $Exe) -Force -ErrorAction SilentlyContinue
      Remove-Item $Log -Force -ErrorAction SilentlyContinue
      $a = "dev $rest --log `"$Log`" --stop-file `"$Stop`""
      $script:proc = Start-Process -FilePath $Exe -ArgumentList $a -WorkingDirectory (Split-Path $Exe) -PassThru -WindowStyle Hidden
      Start-Sleep -Milliseconds 1500
      if ($script:proc.HasExited) { return "HATA: motor hemen kapandi, kod=$($script:proc.ExitCode)`n$(Tail-Log 30)" }
      return "OK pid=$($script:proc.Id)`n$(Tail-Log 15)"
    }
    'stop' { Stop-Engine; return "OK durdu`n$(Tail-Log 25)" }
    'gdpi' {
      if ($rest -eq 'stop') { Stop-Service GoodbyeDPI -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Get-Process goodbyedpi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
      elseif ($rest -eq 'start') { Start-Service GoodbyeDPI -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
      else { return 'HATA: gdpi stop|start' }
      return "OK GoodbyeDPI=$((Get-Service GoodbyeDPI -ErrorAction SilentlyContinue).Status)"
    }
    'status' { return "motor=$(if (Engine-Running) { "calisiyor pid=$($script:proc.Id)" } else { 'kapali' }) GoodbyeDPI=$((Get-Service GoodbyeDPI -ErrorAction SilentlyContinue).Status)" }
    'quit' { Stop-Engine; return 'OK cikiliyor' }
    default { return "HATA: bilinmeyen istek '$verb'" }
  }
}

while ($true) {
  $f = Get-ChildItem $Req -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
  if (-not $f) { Start-Sleep -Milliseconds 250; continue }
  Start-Sleep -Milliseconds 60
  $line = (Get-Content $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
  Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
  if (-not $line) { continue }
  Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $line)
  $out = try { Handle $line } catch { "HATA: $($_.Exception.Message)" }
  Set-Content -Path (Join-Path $Res $f.Name) -Value $out -Encoding UTF8
  if ($line.Trim().ToLower() -eq 'quit') { break }
}
