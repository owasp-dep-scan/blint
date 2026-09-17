# Tier-5 corpus collector: bounded sample of the VM's own system binaries
# (06-corpus.md). Runs ON the Windows VM; the archive is pulled to the mini
# afterwards:
#
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\collect_vm_corpus.ps1'
#   scp win11-vm:C:/Users/appthreat/blint-corpus/tier5-system.tar.gz /tmp/
#   mkdir -p ~/sandbox/pe-corpus/tier5-system && tar xzf /tmp/tier5-system.tar.gz -C ~/sandbox/pe-corpus/tier5-system
#
# Selection: every image whose COFF machine field says ARM64X/ARM64EC (the
# fixtures that exist nowhere else per 01/B.2, bounded by -MaxHybrid), then
# ARM64 system images and kernel drivers, then a bounded AMD64 (x64-on-ARM
# emulation) slice, then the newest CatRoot catalog files. Note the machine
# field alone cannot identify most real ARM64X images — their primary header
# says ARM64 and the x64 view hides behind dynamic relocations — so this
# collector over-samples plain ARM64 files; the ARM64X census belongs to the
# W1/B.2 packet, which parses the load config. An inventory.json records each
# file's PE machine type, origin path and size so any later claim can name
# the binary that produced it (a corpus without provenance is not evidence).
#
# Licence note: these are Microsoft binaries. They stay on the mini and the
# VM as a test corpus; nothing from tier 5 is committed or published.
param(
    [string]$OutDir = "C:\Users\appthreat\blint-corpus\tier5",
    [int]$MaxTotal = 300,
    [int]$MaxHybrid = 100,
    [int]$MaxDrivers = 60,
    [int]$MaxAmd64 = 40,
    [int]$MaxCatRoot = 30
)
$ErrorActionPreference = "Stop"

$System32 = "C:\Windows\System32"
$DriversDir = Join-Path $System32 "drivers"
$CatRootDir = Join-Path $System32 "catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
$Archive = "C:\Users\appthreat\blint-corpus\tier5-system.tar.gz"

if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path "$OutDir\system32" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir\drivers" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir\catroot" | Out-Null

function Get-PEMachine([string]$Path) {
    # Reads the COFF machine field without loading the file: MZ -> e_lfanew
    # -> "PE\0\0" -> 2-byte machine. Returns $null for anything else.
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            # 0x40 bytes covers the DOS header including e_lfanew at 0x3C.
            $head = New-Object byte[] 0x40
            if ($fs.Read($head, 0, 0x40) -lt 0x40) { return $null }
            if ($head[0] -ne 0x4D -or $head[1] -ne 0x5A) { return $null }
            $peOff = [BitConverter]::ToInt32($head, 0x3C)
            if ($peOff -le 0 -or ($peOff + 6) -gt $fs.Length) { return $null }
            $fs.Position = $peOff
            $pe = New-Object byte[] 6
            if ($fs.Read($pe, 0, 6) -lt 6) { return $null }
            if ($pe[0] -ne 0x50 -or $pe[1] -ne 0x45 -or $pe[2] -ne 0 -or $pe[3] -ne 0) { return $null }
            return [BitConverter]::ToUInt16($pe, 4)
        } finally { $fs.Dispose() }
    } catch { return $null }
}

$machineNames = @{
    0x14C  = "I386"; 0x8664 = "AMD64"; 0x1C0 = "ARM"; 0x1C4 = "ARMNT"
    0x3A64 = "CHPE_X86"; 0x5064 = "RISCV64"; 0xA641 = "ARM64EC"
    0xA64E = "ARM64X"; 0xAA64 = "ARM64"
}

Write-Host "== collect: scanning $System32"
# Sorted enumeration keeps the selection stable across runs: an unstable
# corpus would make two invocations produce different evidence.
$candidates = @(
    Get-ChildItem -File $System32 -Include *.dll, *.exe -Recurse -Depth 1 -ErrorAction SilentlyContinue |
        Sort-Object FullName
)
$drivers = @(
    Get-ChildItem -File $DriversDir -Filter *.sys -ErrorAction SilentlyContinue | Sort-Object FullName
)
Write-Host ("== collect: {0} system candidates, {1} drivers" -f $candidates.Count, $drivers.Count)

$inventory = New-Object System.Collections.Generic.List[object]
$hybridTaken = 0; $arm64Taken = 0; $driversTaken = 0; $amd64Taken = 0

function Copy-Selected([System.IO.FileInfo]$file, [string]$subdir, [string]$kind, [int]$machineValue) {
    $destDir = Join-Path $OutDir $subdir
    $dest = Join-Path $destDir $file.Name
    $n = 1
    while (Test-Path $dest) {
        $dest = Join-Path $destDir ("{0}_{1}{2}" -f $file.BaseName, $n, $file.Extension)
        $n++
    }
    Copy-Item $file.FullName $dest
    $inventory.Add([ordered]@{
        file    = $file.FullName
        stored  = ("{0}\{1}" -f $subdir, (Split-Path $dest -Leaf))
        kind    = $kind
        machine = $machineNames[[int]$machineValue]
        bytes   = $file.Length
    })
}

# The system32 slice leaves room for the driver slice so a full System32
# pass cannot starve drivers out of the sample. The arm64 share leaves the
# amd64 slots free, and amd64 gets its own pass over the same enumeration,
# because sorted order can place every x64 image after the arm64 budget
# runs out.
$SystemBudget = $MaxTotal - $MaxDrivers
$Arm64Budget = $SystemBudget - $MaxAmd64
foreach ($f in $candidates) {
    if ($inventory.Count -ge ($Arm64Budget)) { break }
    $m = Get-PEMachine $f.FullName
    if ($null -eq $m) { continue }
    if (($m -eq 0xA64E -or $m -eq 0xA641) -and $hybridTaken -lt $MaxHybrid) {
        Copy-Selected $f "system32" "hybrid" $m; $hybridTaken++
    } elseif ($m -eq 0xAA64) {
        Copy-Selected $f "system32" "arm64" $m; $arm64Taken++
    }
}
foreach ($f in $candidates) {
    if ($amd64Taken -ge $MaxAmd64) { break }
    $m = Get-PEMachine $f.FullName
    if ($m -eq 0x8664) {
        Copy-Selected $f "system32" "amd64" $m; $amd64Taken++
    }
}
foreach ($f in $drivers) {
    if ($inventory.Count -ge $MaxTotal -or $driversTaken -ge $MaxDrivers) { break }
    $m = Get-PEMachine $f.FullName
    if ($null -eq $m) { continue }
    Copy-Selected $f "drivers" "driver" $m; $driversTaken++
}

$cats = @(Get-ChildItem -File $CatRootDir -Filter *.cat -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First $MaxCatRoot)
foreach ($f in $cats) {
    $dest = Join-Path (Join-Path $OutDir "catroot") $f.Name
    Copy-Item $f.FullName $dest
    $inventory.Add([ordered]@{
        file = $f.FullName; stored = ("catroot\{0}" -f $f.Name)
        kind = "catalog"; machine = $null; bytes = $f.Length
    })
}

$inventory | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 (Join-Path $OutDir "inventory.json")
# Counts come from the copy-loop counters; Group-Object cannot see ordered-
# dictionary keys as properties on PS 5.1 and would print empty group names.
Write-Host ("== collect: {0} files: hybrid={1} arm64={2} amd64={3} drivers={4} catalogs={5}" -f `
    $inventory.Count, $hybridTaken, $arm64Taken, $amd64Taken, $driversTaken, $cats.Count)

New-Item -ItemType Directory -Force -Path (Split-Path $Archive) | Out-Null
tar -czf $Archive -C $OutDir system32 drivers catroot inventory.json
if ($LASTEXITCODE -ne 0) { throw "tar failed" }
Write-Host "== collect: archive ready at $Archive"
