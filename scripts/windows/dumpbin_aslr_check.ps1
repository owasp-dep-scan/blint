# Ground-rule-29 oracle: blint's aslr vs `dumpbin /headers` on tier-0 files.
#
# Copy a handful of tier-0 binaries to the VM, then:
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\dumpbin_aslr_check.ps1'
#   scp win11-vm:C:/Users/appthreat/blint-corpus/tier0-sample/aslr-dumpbin.json /tmp/
#
# For every file it captures the raw dumpbin output (saved alongside for the
# PR paste) and a parsed summary {file, machine, dll_characteristics[]} built
# from the "machine" and "DLL characteristics" sections dumpbin prints.
# Comparison against blint's own output happens on the mini; the point here
# is that the numbers come from a Windows tool on a Windows VM, not from
# blint's parser.
param(
    [string]$SampleDir = "C:\Users\appthreat\blint-corpus\tier0-sample",
    [string]$VcvarsBat = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $VcvarsBat)) {
    # Fall back to vswhere when the BuildTools path moves.
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
    # Relative path under the sample dir: same-named binaries from different
    # architectures must not collapse into one summary entry.
    $rel = $file.Substring($SampleDir.Length).TrimStart("\", "/")
    $rawFile = Join-Path $SampleDir (($rel -replace "[\\/]", "_") + ".dumpbin.txt")
    # vcvars64.bat is a batch file, so dumpbin runs through cmd; the known-
    # good pattern on this VM is cmd /c "vcvars && dumpbin" (no inline
    # quoting games outside the one double-quoted string).
    $cmd = "`"$VcvarsBat`" >nul 2>&1 && dumpbin /nologo /headers `"$file`""
    $raw = cmd /c $cmd 2>&1
    $raw | Set-Content -Encoding UTF8 $rawFile

    # dumpbin /headers prints "AA64 machine (ARM64)" and the characteristics
    # block as a hex value followed by the label, then one indented flag name
    # per line until the next value+label line:
    #     160 DLL characteristics
    #          High Entropy Virtual Addresses
    #          Dynamic base
    #          NX compatible
    $machine = $null
    $charValue = $null
    $flags = @()
    $inChar = $false
    foreach ($line in $raw) {
        $t = ("$line").Trim()
        if ($t -match "^([0-9A-Fa-f]{4})\s+machine \((.+)\)\s*$") {
            $machine = "{0} ({1})" -f $Matches[1].ToUpper(), $Matches[2]
            continue
        }
        if ($t -match "^([0-9A-Fa-f]*)\s+DLL characteristics\s*(\S*)") {
            $inChar = $true
            $charValue = "0x{0}" -f ($Matches[1], "0" | Where-Object { $_ } | Select-Object -First 1)
            if ($Matches[2] -notin @("", "0x0", "0")) { $flags += $Matches[2] }
            continue
        }
        if ($inChar) {
            if ($t -eq "" -or $t -match "^[0-9A-Fa-f]+\s") {
                $inChar = $false
            } elseif ($t -match "^[A-Za-z]") {
                $flags += $t
            }
        }
    }
    $summary.Add([ordered]@{
        file                = $rel
        machine             = $machine
        dll_characteristics_value = $charValue
        dll_characteristics = $flags
    })
}

$out = Join-Path $SampleDir "aslr-dumpbin.json"
$summary | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 $out
Write-Host "== dumpbin check: $($summary.Count) file(s) summarized in $out"
$summary | ConvertTo-Json -Depth 3 | Write-Host
