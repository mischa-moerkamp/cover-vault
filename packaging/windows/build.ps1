$ErrorActionPreference = "Stop"
$Root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $Root
python -m pip install --disable-pip-version-check --only-binary=:all: -r requirements/release.txt
python -m pip install --disable-pip-version-check --no-deps .
python -m PyInstaller --noconfirm --clean cover-vault-gui.spec
$PackageVersion = python -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])'
if ($env:COVER_VAULT_VERSION -and $env:COVER_VAULT_VERSION -ne $PackageVersion) {
    throw "COVER_VAULT_VERSION ($env:COVER_VAULT_VERSION) does not match pyproject.toml ($PackageVersion)."
}
$env:COVER_VAULT_VERSION = $PackageVersion
$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $iscc) { throw "Inno Setup 6 (iscc.exe) was not found." }
& $iscc.Source "packaging\windows\cover-vault.iss"
