# =====================================================================
#  Bastion IDS - build the embedded Python runtime for packaging
#  Produces  _runtime\pybackend\python.exe  with ALL backend deps installed.
#  Run once before building the installer.  Needs internet; downloads a
#  portable CPython and installs requirements (TensorFlow etc. -> multi-GB).
#  (c) 2026 Kadian Inc.
# =====================================================================
$ErrorActionPreference = "Stop"
$BASE     = "C:\Bastion_IDS"
$RUNTIME  = Join-Path $BASE "_runtime"
$PYDIR    = Join-Path $RUNTIME "pybackend"
# Portable, fully self-contained CPython 3.12 (python-build-standalone, install_only)
$PYVER    = "3.12.7"
$TAG      = "20241016"
$URL      = "https://github.com/astral-sh/python-build-standalone/releases/download/$TAG/cpython-$PYVER+$TAG-x86_64-pc-windows-msvc-install_only.tar.gz"
$TARBALL  = Join-Path $RUNTIME "cpython.tar.gz"

New-Item -ItemType Directory -Force -Path $RUNTIME | Out-Null
if (Test-Path $PYDIR) { Remove-Item -Recurse -Force $PYDIR }

Write-Host "[1/4] Downloading portable CPython $PYVER ..."
Invoke-WebRequest -Uri $URL -OutFile $TARBALL

Write-Host "[2/4] Extracting ..."
tar -xzf $TARBALL -C $RUNTIME          # extracts a 'python' folder
if (Test-Path (Join-Path $RUNTIME "python")) {
  Rename-Item (Join-Path $RUNTIME "python") "pybackend"
}
$PYEXE = Join-Path $PYDIR "python.exe"
if (-not (Test-Path $PYEXE)) { throw "python.exe not found after extract: $PYEXE" }

Write-Host "[3/4] Upgrading pip ..."
& $PYEXE -m pip install --upgrade pip

Write-Host "[4/4] Installing backend dependencies (this is the big one) ..."
& $PYEXE -m pip install -r (Join-Path $BASE "requirements-runtime.txt")

Remove-Item $TARBALL -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "DONE. Embedded runtime ready at $PYDIR"
Write-Host "Size:" ([math]::Round((Get-ChildItem $PYDIR -Recurse | Measure-Object Length -Sum).Sum/1MB)) "MB"
Write-Host "Next: cd app-desktop ; npm run dist   (produces the Setup.exe in _installer\)"
