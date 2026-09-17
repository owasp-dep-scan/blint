# Ground-rule-29 oracle: blint's load-config decode vs `dumpbin /loadconfig`.
#
# W0.3 of the PE lane: the GuardFlags bit table in blint/lib/pe_constants.py
# is pinned against dumpbin's own decode of the same bits on real files, and
# against the IMAGE_GUARD defines in the Windows SDK's winnt.h.
#
# Copy to the VM (from the mini):
#   scp scripts/windows/dumpbin_loadconfig_check.ps1 win11-vm:C:/Users/appthreat/blint/
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\dumpbin_loadconfig_check.ps1'
#   scp win11-vm:C:/Users/appthreat/blint-corpus/tier0-sample/loadconfig-dumpbin.json /tmp/
#
# For every file it captures the raw dumpbin output (saved alongside for the
# PR paste) and a parsed summary {file, guard_flags, guard_flag_names[]}
# parsed from the "Guard Flags" section dumpbin prints. The winnt.h IMAGE_GUARD
# table is captured once into the same JSON so the bit table can be diffed
# against blint's without a second round trip.
param(
    [string]$SampleDir = "C:\Users\appthreat\blint-corpus\tier0-sample",
    [string]$VcvarsBat = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $VcvarsBat)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        $candidate = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $candidate) { $VcvarsBat = $candidate }
    }
}
if (-not (Test-Path $VcvarsBat)) { throw "vcvars64.bat not found; install the C++ Build Tools workload" }

$summary = New-Object System.Collections.Generic.List[object]
Get-ChildItem -File $SampleDir -Include *.exe, *.dll, *.pyd -Recurse | ForEach-Object {
    $file = $_.FullName
    $rel = $file.Substring($SampleDir.Length).TrimStart("\", "/")
    $rawFile = Join-Path $SampleDir (($rel -replace "[\\/]", "_") + ".loadconfig.txt")
    $cmd = "`"$VcvarsBat`" >nul 2>&1 && dumpbin /nologo /loadconfig `"$file`""
    $raw = cmd /c $cmd 2>&1
    $raw | Set-Content -Encoding UTF8 $rawFile

    # dumpbin /loadconfig prints:
    #     Guard Flags                       00000500
    #          CF Instrumented
    #          Module has CFI table
    # ...one indented flag name per line until a non-flag line. Names are
    # captured verbatim; the value is kept as the raw 8-digit hex string.
    $guardFlags = $null
    $names = @()
    $inFlags = $false
    foreach ($line in $raw) {
        $t = ("$line").Trim()
        if ($t -match "^([0-9A-Fa-f]{8})\s+Guard Flags\s*$") {
            $guardFlags = "0x" + $Matches[1].ToUpper()
            $inFlags = $true
            continue
        }
        if ($inFlags) {
            if ($t -eq "" -or $t -match "^[0-9A-Fa-f]{8}\s" -or $t -match "^[A-Za-z][A-Za-z0-9 ]+:" ) {
                $inFlags = $false
            } elseif ($t) {
                $names += $t
            }
        }
    }
    $summary.Add([ordered]@{
        file             = $rel
        guard_flags      = $guardFlags
        guard_flag_names = $names
    })
}

# The SDK's own bit table, straight from the headers the toolchain ships.
$winnt = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include" -Recurse -Filter winnt.h |
    Sort-Object FullName -Descending | Select-Object -First 1
$winntPath = $null
$guardDefines = [ordered]@{}
if ($winnt) {
    $winntPath = $winnt.FullName
    Get-Content $winntPath | ForEach-Object {
        if ($_ -match "^#define\s+(IMAGE_GUARD_\w+)\s+(0x[0-9A-Fa-f]+)") {
            $guardDefines[$Matches[1]] = $Matches[2]
        }
        if ($_ -match "^#define\s+IMAGE_DLLCHARACTERISTICS_EX_\w+\s+0x[0-9A-Fa-f]+") {
            $guardDefines[($Matches[0] -replace "^#define\s+", "" -replace "\s+", " ")] = $true
        }
    }
}

$out = Join-Path $SampleDir "loadconfig-dumpbin.json"
$result = [ordered]@{
    winnt_header = $winntPath
    winnt_image_guard_defines = $guardDefines
    files = $summary
}
$result | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $out
Write-Host "== loadconfig check: $($summary.Count) file(s) summarized in $out"
$result | ConvertTo-Json -Depth 4 | Write-Host
