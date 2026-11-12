param([string]$Edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
# Regenerates the mascot icons from the SVG definitions below:
#   assets\icons\src\*.svg      the drawings (three states, a detailed and a small variant)
#   assets\icons\{acik,kapali,sorun}.ico
#   assets\sondpi.rc / sondpi.res   resources linked into sondpi.exe by build.rs
#   assets\icons\onizleme.png   preview sheet
# Needs Microsoft Edge (to rasterise the SVGs) and rc.exe from the Windows SDK. No elevation.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$Repo  = Split-Path $PSScriptRoot -Parent
$Icons = Join-Path $Repo 'assets\icons'
$SrcD  = Join-Path $Icons 'src'
$Tmp   = Join-Path $env:TEMP "sondpi-ikon-$PID"
New-Item -ItemType Directory -Force -Path $SrcD, $Tmp | Out-Null

$States = @{
  acik   = @{ ht = '#a48bff'; hb = '#5a3fd6'; hk = '#4a35b8'; skin = '#ffe3d3'; pin = '#22c55e'; pind = '#15803d'; badge = '#22c55e'; knob = 22.6 }
  kapali = @{ ht = '#bcb9cc'; hb = '#85829a'; hk = '#6c697f'; skin = '#f2e6df'; pin = '#a3a7b7'; pind = '#7b7f92'; badge = '#8b8fa3'; knob = 15.4 }
  sorun  = @{ ht = '#a48bff'; hb = '#5a3fd6'; hk = '#4a35b8'; skin = '#ffe3d3'; pin = '#f59e0b'; pind = '#b45309'; badge = '#f59e0b'; knob = 22.6 }
}

function Svg([string]$state, [bool]$small) {
  $c = $States[$state]
  $head = @"
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="512" height="512">
<defs>
<linearGradient id="h" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="$($c.ht)"/><stop offset="1" stop-color="$($c.hb)"/></linearGradient>
<linearGradient id="i" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0a6f5c"/><stop offset="1" stop-color="#5df2cf"/></linearGradient>
</defs>
<path d="M7 35 C4 11 60 11 57 35 C58 47 59.5 55 61.5 61 L2.5 61 C4.5 55 6 47 7 35Z" fill="$($c.hk)"/>
<path d="M15 33 C15 20 49 20 49 33 C49 45 42 53.5 32 56 C22 53.5 15 45 15 33Z" fill="$($c.skin)"/>
"@
  $face = ''
  if ($small) {
    if ($state -eq 'kapali') {
      $face = '<path d="M19.5 38 Q24.4 43 29.3 38 M34.7 38 Q39.6 43 44.5 38" fill="none" stroke="#4b4763" stroke-width="3" stroke-linecap="round"/>'
    } else {
      $face = '<ellipse cx="24.5" cy="38" rx="4.2" ry="5.4" fill="#0c6b59"/><ellipse cx="39.5" cy="38" rx="4.2" ry="5.4" fill="#0c6b59"/><circle cx="23.1" cy="36" r="1.7" fill="#fff"/><circle cx="38.1" cy="36" r="1.7" fill="#fff"/>'
      if ($state -eq 'acik') { $face += '<path d="M28.6 47 Q32 50.4 35.4 47" fill="none" stroke="#a8324f" stroke-width="2.2" stroke-linecap="round"/>' }
    }
  } else {
    switch ($state) {
      'acik' {
        $face = @'
<ellipse cx="19.5" cy="43.6" rx="3.3" ry="1.8" fill="#ff7f9d" opacity=".5"/><ellipse cx="44.5" cy="43.6" rx="3.3" ry="1.8" fill="#ff7f9d" opacity=".5"/>
<ellipse cx="24.3" cy="37" rx="4.6" ry="5.6" fill="#fff"/><ellipse cx="24.5" cy="37.5" rx="3.6" ry="4.7" fill="url(#i)"/><ellipse cx="24.5" cy="37.7" rx="1.5" ry="2.4" fill="#04322a"/><circle cx="23" cy="35.3" r="1.5" fill="#fff"/>
<ellipse cx="39.7" cy="37" rx="4.6" ry="5.6" fill="#fff"/><ellipse cx="39.5" cy="37.5" rx="3.6" ry="4.7" fill="url(#i)"/><ellipse cx="39.5" cy="37.7" rx="1.5" ry="2.4" fill="#04322a"/><circle cx="38" cy="35.3" r="1.5" fill="#fff"/>
<path d="M19.6 35.2 C21.5 31.2 27.5 31.2 29.4 35 M34.6 35 C36.5 31.2 42.5 31.2 44.4 35.2" fill="none" stroke="#2b1e57" stroke-width="1.5" stroke-linecap="round"/>
<path d="M28.3 46.2 Q32 51 35.9 46 Q32 47.4 28.3 46.2Z" fill="#a8324f"/><path d="M33.6 46.6 l.8 1.8 l.9 -2Z" fill="#fff"/>
'@
      }
      'kapali' {
        $face = @'
<ellipse cx="19.5" cy="43.6" rx="3.3" ry="1.8" fill="#e59aad" opacity=".35"/><ellipse cx="44.5" cy="43.6" rx="3.3" ry="1.8" fill="#e59aad" opacity=".35"/>
<path d="M20 37.5 Q24.4 41.6 28.8 37.5 M35.2 37.5 Q39.6 41.6 44 37.5" fill="none" stroke="#4b4763" stroke-width="1.9" stroke-linecap="round"/>
<path d="M30.2 47.4 Q32 48.7 33.8 47.4" fill="none" stroke="#9a6f7a" stroke-width="1.5" stroke-linecap="round"/>
<path d="M49.5 13 h5 l-5 6 h5" fill="none" stroke="#9a9db0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M56.3 5.5 h3.4 l-3.4 4.2 h3.4" fill="none" stroke="#9a9db0" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
'@
      }
      'sorun' {
        $face = @'
<ellipse cx="24.3" cy="37" rx="4.6" ry="5.6" fill="#fff"/><ellipse cx="24.5" cy="37.6" rx="2.5" ry="3.1" fill="url(#i)"/><circle cx="24.5" cy="37.8" r="1.1" fill="#04322a"/>
<ellipse cx="39.7" cy="37" rx="4.6" ry="5.6" fill="#fff"/><ellipse cx="39.5" cy="37.6" rx="2.5" ry="3.1" fill="url(#i)"/><circle cx="39.5" cy="37.8" r="1.1" fill="#04322a"/>
<path d="M19.6 35.2 C21.5 31.2 27.5 31.2 29.4 35 M34.6 35 C36.5 31.2 42.5 31.2 44.4 35.2" fill="none" stroke="#2b1e57" stroke-width="1.5" stroke-linecap="round"/>
<path d="M27.5 47.8 q2.2 -2.4 4.5 0 t4.5 0" fill="none" stroke="#a8324f" stroke-width="1.7" stroke-linecap="round"/>
<path d="M47.6 23.5 C49.6 26.6 50.4 28.2 49.3 29.7 C48.3 30.9 46.5 30.6 46.1 29.1 C45.8 27.7 46.7 25.6 47.6 23.5Z" fill="#7dd3fc"/>
'@
      }
    }
  }
  $bangs = if ($small) {
    'M12 35 C10 15 23 8 32 8 C41 8 54 15 52 35 C49.5 29.5 46 27.5 43.5 27.5 C43 31.5 40 34 36.5 35 C35.5 31 33.5 28.5 31 27.5 C29.5 31.5 26 34.5 21.5 35.5 C20.5 32 18.5 30 16.5 29.5 C14.8 31 13.2 33 12 35Z'
  } else {
    'M12 35 C10 15 23 8 32 8 C41 8 54 15 52 35 C50.5 30 48 27 45.5 26 C45.5 30 44 33 41 34.8 C40.5 30.5 38.5 27.8 36 26.6 C35.5 30.5 33 33.6 29.8 35.2 C29.4 31 27.6 28.2 25 26.8 C24.4 30.6 22.2 33.8 19 35.8 C18.6 32.2 17 30 15.4 29.2 C14.2 31 13 33 12 35Z'
  }
  $shine = if ($small) { '' } else { '<path d="M20 18 Q32 11.5 44 18" fill="none" stroke="#e8e2ff" stroke-width="2" stroke-linecap="round" opacity=".65"/>' }
  $hair = @"
<path d="M13.5 30 C10 41 12 50 17.5 55.5 C16 48 16.5 39 18.5 31.5Z" fill="url(#h)"/><path d="M50.5 30 C54 41 52 50 46.5 55.5 C48 48 47.5 39 45.5 31.5Z" fill="url(#h)"/>
<path d="$bangs" fill="url(#h)"/>$shine
<path d="M31 9.5 C29 3.5 35.5 0.8 40.5 2.6 C36.5 3.4 34.5 6.4 34.5 10Z" fill="url(#h)"/>
"@
  $pin = if ($small) {
    "<g transform=`"rotate(-18 19 22)`"><rect x=`"10`" y=`"17.4`" width=`"18`" height=`"9.2`" rx=`"4.6`" fill=`"$($c.pin)`"/><circle cx=`"$(if ($c.knob -gt 20) { 23.2 } else { 14.8 })`" cy=`"22`" r=`"3`" fill=`"#fff`"/></g>"
  } else {
    "<g transform=`"rotate(-18 19 22)`"><rect x=`"11.5`" y=`"18.5`" width=`"15`" height=`"7.4`" rx=`"3.7`" fill=`"$($c.pind)`"/><rect x=`"12.3`" y=`"19.3`" width=`"13.4`" height=`"5.8`" rx=`"2.9`" fill=`"$($c.pin)`"/><circle cx=`"$($c.knob)`" cy=`"22.2`" r=`"2.3`" fill=`"#fff`"/></g>"
  }
  $bc = if ($small) { @{ x = 48.5; y = 48.5; ro = 14.5; ri = 12.6; w = 3.8 } } else { @{ x = 50.5; y = 50.5; ro = 11.8; ri = 10.2; w = 2.8 } }
  $glyph = switch ($state) {
    'acik'   { "<path d=`"M$($bc.x - 5.6) $($bc.y + 0.4) l3.9 3.9 l7.2 -8`" fill=`"none`" stroke=`"#fff`" stroke-width=`"$($bc.w)`" stroke-linecap=`"round`" stroke-linejoin=`"round`"/>" }
    'kapali' { "<path d=`"M$($bc.x - 5) $($bc.y) h10`" fill=`"none`" stroke=`"#fff`" stroke-width=`"$($bc.w)`" stroke-linecap=`"round`"/>" }
    'sorun'  { "<path d=`"M$($bc.x) $($bc.y - 6) v6.6`" fill=`"none`" stroke=`"#fff`" stroke-width=`"$($bc.w)`" stroke-linecap=`"round`"/><circle cx=`"$($bc.x)`" cy=`"$($bc.y + 5.4)`" r=`"$([math]::Round($bc.w * 0.62, 2))`" fill=`"#fff`"/>" }
  }
  $badge = "<circle cx=`"$($bc.x)`" cy=`"$($bc.y)`" r=`"$($bc.ro)`" fill=`"#fff`"/><circle cx=`"$($bc.x)`" cy=`"$($bc.y)`" r=`"$($bc.ri)`" fill=`"$($c.badge)`"/>$glyph"
  return "$head$face`n$hair$pin`n$badge`n</svg>`n"
}

function Render([string]$svgPath, [string]$pngPath) {
  $html = Join-Path $Tmp 'r.html'
  $uri = 'file:///' + ($svgPath -replace '\\', '/')
  [IO.File]::WriteAllText($html, "<!doctype html><html style='background:transparent'><body style='margin:0;background:transparent'><img src='$uri' width='512' height='512'></body></html>")
  Remove-Item $pngPath -Force -ErrorAction SilentlyContinue
  $p = Start-Process -FilePath $Edge -ArgumentList "--headless=new --disable-gpu --hide-scrollbars --default-background-color=00000000 --window-size=512,512 --screenshot=`"$pngPath`" `"file:///$($html -replace '\\','/')`"" -PassThru -WindowStyle Hidden
  [void]$p.WaitForExit(60000)
  if (-not (Test-Path $pngPath)) { throw "render failed: $svgPath" }
}

function Scale([System.Drawing.Bitmap]$src, [int]$size) {
  $b = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $g = [System.Drawing.Graphics]::FromImage($b)
  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
  $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
  $attr = New-Object System.Drawing.Imaging.ImageAttributes
  $attr.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)
  $g.DrawImage($src, (New-Object System.Drawing.Rectangle 0, 0, $size, $size), 0, 0, $src.Width, $src.Height, [System.Drawing.GraphicsUnit]::Pixel, $attr)
  $g.Dispose()
  return $b
}

# One ICO image entry: PNG for 256, a 32-bit DIB with an empty AND mask for the rest.
function IcoImage([System.Drawing.Bitmap]$b) {
  $n = $b.Width
  if ($n -ge 256) {
    $ms = New-Object IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return , $ms.ToArray()
  }
  $rect = New-Object System.Drawing.Rectangle 0, 0, $n, $n
  $d = $b.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $px = New-Object byte[] ($n * $n * 4)
  [Runtime.InteropServices.Marshal]::Copy($d.Scan0, $px, 0, $px.Length)
  $b.UnlockBits($d)
  $ms = New-Object IO.MemoryStream
  $w = New-Object IO.BinaryWriter $ms
  $maskRow = [int]([math]::Ceiling($n / 32.0) * 4)
  $w.Write([uint32]40); $w.Write([int32]$n); $w.Write([int32]($n * 2)); $w.Write([uint16]1); $w.Write([uint16]32)
  $w.Write([uint32]0); $w.Write([uint32]($n * $n * 4 + $maskRow * $n)); $w.Write([int32]0); $w.Write([int32]0); $w.Write([uint32]0); $w.Write([uint32]0)
  for ($y = $n - 1; $y -ge 0; $y--) { $w.Write($px, $y * $n * 4, $n * 4) }
  $w.Write((New-Object byte[] ($maskRow * $n)))
  $w.Flush()
  return , $ms.ToArray()
}

function WriteIco([string]$path, [System.Drawing.Bitmap[]]$images) {
  $blobs = @(); foreach ($i in $images) { $blobs += , (IcoImage $i) }
  $ms = New-Object IO.MemoryStream
  $w = New-Object IO.BinaryWriter $ms
  $w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$images.Count)
  $off = 6 + 16 * $images.Count
  for ($k = 0; $k -lt $images.Count; $k++) {
    $n = $images[$k].Width
    $w.Write([byte]($(if ($n -ge 256) { 0 } else { $n }))); $w.Write([byte]($(if ($n -ge 256) { 0 } else { $n })))
    $w.Write([byte]0); $w.Write([byte]0); $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$blobs[$k].Length); $w.Write([uint32]$off)
    $off += $blobs[$k].Length
  }
  foreach ($bl in $blobs) { $w.Write($bl) }
  $w.Flush()
  [IO.File]::WriteAllBytes($path, $ms.ToArray())
}

$SmallSizes = 16, 20, 24
$BigSizes = 32, 40, 48, 64, 256
$sheet = @{}
foreach ($state in 'acik', 'kapali', 'sorun') {
  $imgs = @()
  foreach ($variant in @(@{ small = $true; tag = 'kucuk'; sizes = $SmallSizes }, @{ small = $false; tag = 'ayrintili'; sizes = $BigSizes })) {
    $svg = Join-Path $SrcD "$state-$($variant.tag).svg"
    [IO.File]::WriteAllText($svg, (Svg $state $variant.small))
    $png = Join-Path $Tmp "$state-$($variant.tag).png"
    Render $svg $png
    $src = New-Object System.Drawing.Bitmap $png
    foreach ($s in $variant.sizes) { $imgs += (Scale $src $s) }
    $src.Dispose()
  }
  WriteIco (Join-Path $Icons "$state.ico") $imgs
  $sheet[$state] = $imgs
  Write-Host "$state.ico: $($imgs.Count) images, $((Get-Item (Join-Path $Icons "$state.ico")).Length) bytes"
}

# Preview sheet: every state at tray sizes on a dark and a light taskbar colour, plus a 4x
# nearest-neighbour blow-up of the 16 and 24 px images to judge legibility.
$show = 16, 24, 32, 48, 64
$W = 880; $H = 460
$bmp = New-Object System.Drawing.Bitmap $W, $H
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dark = [System.Drawing.Color]::FromArgb(255, 32, 32, 32)
$light = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 243, 243, 243))
$g.Clear($dark)
$g.FillRectangle($light, 0, 100, $W, 100)
$g.FillRectangle($light, 0, 330, $W, 130)
foreach ($bgY in 18, 118) {
  $x = 24
  foreach ($state in 'acik', 'kapali', 'sorun') {
    foreach ($s in $show) {
      $im = $sheet[$state] | Where-Object { $_.Width -eq $s } | Select-Object -First 1
      $g.DrawImage($im, $x, $bgY + (64 - $s) / 2, $s, $s)
      $x += $s + 12
    }
    $x += 40
  }
}
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
foreach ($rowY in 217, 347) {
  $x = 24
  foreach ($state in 'acik', 'kapali', 'sorun') {
    foreach ($s in 16, 24) {
      $im = $sheet[$state] | Where-Object { $_.Width -eq $s } | Select-Object -First 1
      $g.DrawImage($im, $x, $rowY + (96 - $s * 4), $s * 4, $s * 4)
      $x += $s * 4 + 16
    }
    $x += 84
  }
}
$g.Dispose()
$bmp.Save((Join-Path $Icons 'onizleme.png'), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

# Resource script and compiled resources.
$rc = @'
#pragma code_page(65001)
1 ICON "icons\\acik.ico"
2 ICON "icons\\kapali.ico"
3 ICON "icons\\sorun.ico"

1 VERSIONINFO
FILEVERSION VERCOMMA
PRODUCTVERSION VERCOMMA
FILEOS 0x40004L
FILETYPE 0x1L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "041F04B0"
    BEGIN
      VALUE "ProductName", "SONdpi"
      VALUE "FileDescription", "SONdpi"
      VALUE "FileVersion", "VERDOT"
      VALUE "ProductVersion", "VERDOT"
      VALUE "OriginalFilename", "sondpi.exe"
      VALUE "LegalCopyright", "MIT"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x041F, 0x04B0
  END
END
'@
$ver = ((Get-Content (Join-Path $Repo 'Cargo.toml')) | Where-Object { $_ -match '^version\s*=\s*"([0-9.]+)"' } | Select-Object -First 1) -replace '.*"([0-9.]+)".*', '$1'
$rc = $rc.Replace('VERCOMMA', (($ver -split '\.') + '0' -join ',')).Replace('VERDOT', $ver)
$rcPath = Join-Path $Repo 'assets\sondpi.rc'
[IO.File]::WriteAllText($rcPath, $rc, (New-Object Text.UTF8Encoding $false))
$rcExe = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter rc.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $rcExe) { throw 'rc.exe not found (Windows SDK)' }
Push-Location (Join-Path $Repo 'assets')
& $rcExe.FullName /nologo /fo sondpi.res sondpi.rc
Pop-Location
Write-Host "sondpi.res: $((Get-Item (Join-Path $Repo 'assets\sondpi.res')).Length) bytes (version $ver)"
Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
