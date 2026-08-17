#Requires -Version 5.1
<#
.SYNOPSIS
  Load BENCpass into a scratch Zen/Firefox profile and open the form-shapes page.

.DESCRIPTION
  The Windows counterpart of tools/run-extension.sh. Same job, but almost none
  of the shell script survives the trip: `trap`, `command -v`, backgrounding with
  `&` and the browser's location are all different here.

  A temporary profile, deliberately: the extension is installed unsigned and
  temporarily, so nothing touches the browser you actually use, and the vault
  created during testing is thrown away with the profile.

  The test page is served over http://127.0.0.1, which BENCpass treats as a
  private host — so filling is allowed without a certificate and the
  insecure-page refusal is not in the way of testing everything else.

.PARAMETER Browser
  Full path to zen.exe or firefox.exe. Only needed when the probe below misses;
  it prints everywhere it looked. $env:BENCPASS_BROWSER works too.

.PARAMETER Port
  Port for the local static server. Default 8731.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\run-extension.ps1

.EXAMPLE
  .\tools\run-extension.ps1 -Browser "D:\Apps\Zen Browser\zen.exe"

.NOTES
  Windows blocks unsigned scripts by default. Either launch it as in the first
  example, or unblock the file once with:
      Unblock-File tools\run-extension.ps1
#>
[CmdletBinding()]
param(
    [string] $Browser = $env:BENCPASS_BROWSER,
    [int]    $Port = 8731
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path -Path $root -ChildPath 'src'
$serve = Join-Path -Path (Join-Path -Path $root -ChildPath 'tools') -ChildPath 'serve.mjs'

# A wrong $root is the failure that produces the most confusing symptom later —
# web-ext reports a manifest error rather than a missing directory — so check it
# here where the message can say what actually happened.
if (-not (Test-Path (Join-Path -Path $srcDir -ChildPath 'manifest.json'))) {
    throw "No manifest at $srcDir\manifest.json. Run this from the repository's tools\ directory."
}

function Find-Tool {
    param([string] $Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-Browser {
    # Zen ships both a machine-wide and a per-user installer, and has used more
    # than one folder name. Firefox and its Developer Edition are the fallbacks.
    $bases = @()
    foreach ($b in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs'))) {
        if ($b) { $bases += $b }
    }

    $relatives = @(
        'Zen Browser\zen.exe',
        'Zen\zen.exe',
        'zen\zen.exe',
        'Mozilla Firefox\firefox.exe',
        'Firefox Developer Edition\firefox.exe',
        'Mozilla Firefox Developer Edition\firefox.exe'
    )

    $tried = @()
    foreach ($base in $bases) {
        foreach ($rel in $relatives) {
            $candidate = Join-Path -Path $base -ChildPath $rel
            $tried += $candidate
            if (Test-Path $candidate) {
                return [pscustomobject]@{ Path = $candidate; Tried = $tried }
            }
        }
    }

    # Last resort: something already on PATH.
    foreach ($n in @('zen', 'firefox')) {
        $found = Find-Tool $n
        if ($found) { return [pscustomobject]@{ Path = $found; Tried = $tried } }
    }

    return [pscustomobject]@{ Path = $null; Tried = $tried }
}

# ---- prerequisites ---------------------------------------------------------

$node = Find-Tool 'node'
if (-not $node) { throw 'node is not on PATH. Install Node.js, then reopen this terminal.' }

$npx = Find-Tool 'npx'
if (-not $npx) { throw 'npx is not on PATH. It ships with Node.js; reopen this terminal after installing.' }

if (-not (Test-Path (Join-Path -Path $root -ChildPath 'node_modules\web-ext'))) {
    throw "web-ext is not installed. Run 'npm install' in $root first."
}

if (-not $Browser) {
    $probe = Find-Browser
    $Browser = $probe.Path
    if (-not $Browser) {
        $list = ($probe.Tried | ForEach-Object { "  $_" }) -join "`n"
        throw "Could not find Zen or Firefox. Looked in:`n$list`n`nPass one explicitly:`n  .\tools\run-extension.ps1 -Browser 'C:\Path\To\zen.exe'"
    }
}
elseif (-not (Test-Path $Browser)) {
    throw "No such browser: $Browser"
}

# ---- run -------------------------------------------------------------------

$url = "http://127.0.0.1:$Port/tools/testpage/index.html"
$server = $null

try {
    # Hidden rather than minimised: the static server has no output worth
    # watching, and a stray console window outliving a Ctrl-C is a nuisance.
    $server = Start-Process -FilePath $node `
        -ArgumentList @($serve, $root, "$Port") `
        -WindowStyle Hidden -PassThru

    Start-Sleep -Milliseconds 700

    if ($server.HasExited) {
        throw "The static server exited immediately. Port $Port is probably already in use; pass -Port with another."
    }

    Write-Host ''
    Write-Host 'BENCpass' -ForegroundColor Cyan
    Write-Host "  browser      $Browser"
    Write-Host "  form shapes  $url"
    Write-Host '  manager      about:addons -> BENCpass -> Preferences'
    Write-Host ''
    Write-Host '  Close the browser to stop.' -ForegroundColor DarkGray
    Write-Host ''

    # Blocks until the browser is closed. Argument array rather than one string,
    # so a path with spaces — which is the normal case here — survives.
    & $npx @(
        'web-ext', 'run',
        "--source-dir=$srcDir",
        "--firefox=$Browser",
        '--start-url', $url,
        '--browser-console'
    )
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}
