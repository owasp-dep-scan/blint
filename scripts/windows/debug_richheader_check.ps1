# Ground-rule-29 oracle: blint's debug/CodeView and toolchain decode vs
# Windows tools.
#
# W1.1 of the PE lane: for every sample file this captures `dumpbin
# /headers` — the "Debug Directories" section (type, RVA, size, and the
# RSDS line with GUID, age and PDB path) plus the linker version line the
# toolchain block is pinned against. Note this toolchain's link.exe does
# not implement /RICHHEADER (LNK4044), so the rich header's ground truth is
# two-sided: the checksum validation (a header cannot validate without the
# linker's own algorithm and bytes) and the freshly built fixture whose
# comp.ids must name the toolchain that built it.
#
# Copy to the VM (from the mini):
#   scp scripts/windows/debug_richheader_check.ps1 win11-vm:C:/Users/appthreat/blint/
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\debug_richheader_check.ps1'
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
    $tag = ($rel -replace "[\\/]", "_")

    $headersRaw = Join-Path $SampleDir ($tag + ".headers.txt")
    $cmd = "`"$VcvarsBat`" >nul 2>&1 && dumpbin /nologo /headers `"$file`""
    $headers = cmd /c $cmd 2>&1
    $headers | Set-Content -Encoding UTF8 $headersRaw

    # Debug Directories section: dumpbin prints one line per entry:
    #   689DF006 cv            39 004CF510   4CE310    Format: RSDS, {...}, 1, D:\...
    #   689DF006 feat          14 004CF54C   4CE34C    Counts: Pre-VC++ 11.00=0, ...
    #   689DF006 coffgrp      408 004CF560   4CE360    50475500 (PGU)
    $debugRows = New-Object System.Collections.Generic.List[object]
    $inDebug = $false
    foreach ($line in $headers) {
        $t = ("$line").TrimEnd()
        if ($t -match "^\s*Debug Directories") { $inDebug = $true; continue }
        if (-not $inDebug) { continue }
        if ($t -match "^\s*SECTION HEADER|^\s*Summary") { $inDebug = $false; continue }
        if ($t -match "^\s*([0-9A-Fa-f]{8})\s+(\S+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s*(.*)$") {
            $row = [ordered]@{
                timestamp = $Matches[1].ToUpper()
                type      = $Matches[2]
                size      = $Matches[3]
                rva       = $Matches[4]
                pointer   = $Matches[5]
                detail    = $Matches[6].Trim()
            }
            if ($row.detail -match "Format:\s*(\S+),\s*\{([0-9A-Fa-f\-]+)\},\s*(\d+),\s*(.+)$") {
                $row["format"] = $Matches[1]
                $row["guid"] = $Matches[2].ToUpper()
                $row["age"] = $Matches[3]
                $row["pdb_path"] = $Matches[4].Trim()
            }
            $debugRows.Add($row)
        }
    }

    $summary.Add([ordered]@{
        file            = $rel
        debug_entries   = $debugRows
        linker_version  = (($headers | Where-Object { $_ -match "linker version" } | Select-Object -First 1) -replace "^\s*", "")
    })
}

$outPath = Join-Path $SampleDir "debug-richheader-dumpbin.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $outPath
Write-Host "== wrote $outPath"
