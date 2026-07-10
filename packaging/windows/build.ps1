$ErrorActionPreference = "Stop"
$Root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $Root
python -m pip install --upgrade pip
python -m pip install ".[build]"
python -m PyInstaller --noconfirm --clean cover-vault-gui.spec
$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $iscc) { throw "Inno Setup 6 (iscc.exe) was not found." }
& $iscc.Source "packaging\windows\cover-vault.iss"
