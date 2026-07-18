#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python3 -m pip install --disable-pip-version-check --only-binary=:all: -r requirements/release.txt
python3 -m pip install --disable-pip-version-check --no-deps .
python3 -m PyInstaller --noconfirm --clean cover-vault-gui.spec
PACKAGE_VERSION="$(python3 -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
VERSION="${COVER_VAULT_VERSION:-$PACKAGE_VERSION}"
if [[ "$VERSION" != "$PACKAGE_VERSION" ]]; then
  echo "COVER_VAULT_VERSION ($VERSION) does not match pyproject.toml ($PACKAGE_VERSION)." >&2
  exit 1
fi
mkdir -p dist/dmg
rm -f "dist/CoverVault-${VERSION}-macOS.dmg"
cp -R "dist/Cover Vault.app" dist/dmg/
ln -s /Applications dist/dmg/Applications
hdiutil create -volname "Cover Vault" -srcfolder dist/dmg -ov -format UDZO "dist/CoverVault-${VERSION}-macOS.dmg"
