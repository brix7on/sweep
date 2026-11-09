# sweep launcher
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$p = Join-Path $env:TEMP 'sweep.exe'
Invoke-WebRequest 'https://github.com/brix7on/sweep/releases/latest/download/sweep.exe' -OutFile $p -UseBasicParsing
$a = @()
if ($sweepArgs) { $a = $sweepArgs -split ' ' }
& $p @a
Remove-Item $p -Force -ErrorAction SilentlyContinue
