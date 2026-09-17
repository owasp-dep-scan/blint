# Runs the blint test suite on the Windows VM (PE-lane ground rule 31).
#
# Deploy (from the mini):
#   scp scripts/windows/run-tests.ps1 win11-vm:C:/Users/appthreat/blint/
# Run:
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\run-tests.ps1'
#
# Every ssh call is a fresh login session, so this script is self-contained:
# it clones (or resets) the checkout, builds the venv on first use, installs
# the suite dependencies, and runs pytest, echoing everything it does. Exit
# code is pytest's.
param(
    [string]$RepoDir = "C:\Users\appthreat\blint-src",
    [string]$RepoUrl = "https://github.com/owasp-dep-scan/blint.git",
    [string]$Branch = "feat/pe-sep",
    [string]$Python = "C:\Python314\python.exe"
)
$ErrorActionPreference = "Stop"
Write-Host "== run-tests: repo $RepoUrl branch $Branch"

if (Test-Path $RepoDir) {
    git -C $RepoDir fetch origin $Branch
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed" }
    git -C $RepoDir checkout $Branch
    git -C $RepoDir reset --hard "origin/$Branch"
    if ($LASTEXITCODE -ne 0) { throw "git reset failed" }
} else {
    git clone --branch $Branch $RepoUrl $RepoDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
}
& git -C $RepoDir log --oneline -1
Set-Location $RepoDir

$VenvDir = Join-Path $RepoDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "== run-tests: creating venv with $Python"
    & $Python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -e .
    if ($LASTEXITCODE -ne 0) { throw "pip install -e . failed" }
    & $VenvPython -m pip install pytest pytest-cov
    if ($LASTEXITCODE -ne 0) { throw "pip install test deps failed" }
} else {
    # Keep the checkout and the installed tree in sync on later runs.
    & $VenvPython -m pip install --quiet -e .
    if ($LASTEXITCODE -ne 0) { throw "pip install -e . failed" }
}

Write-Host "== run-tests: pytest"
& $VenvPython -m pytest -q (Join-Path $RepoDir "tests")
$Code = $LASTEXITCODE
$Summary = "PYTEST_EXIT=$Code"
Add-Content -Path (Join-Path $env:TEMP "blint-run-tests-last.txt") -Value ("{0}: {1}" -f (Get-Date -Format o), $Summary)
Write-Host "== run-tests: $Summary"
exit $Code
