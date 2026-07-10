#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python3 -m pip install --upgrade pip
python3 -m pip install '.[build]'
python3 -m PyInstaller --noconfirm --clean cover-vault-gui.spec
VERSION="${COVER_VAULT_VERSION:-1.0.0}"
mkdir -p dist/dmg
rm -f "dist/CoverVault-${VERSION}-macOS.dmg"
cp -R "dist/Cover Vault.app" dist/dmg/
ln -s /Applications dist/dmg/Applications
hdiutil create -volname "Cover Vault" -srcfolder dist/dmg -ov -format UDZO "dist/CoverVault-${VERSION}-macOS.dmg"
