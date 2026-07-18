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
PKGROOT="dist/deb/cover-vault_${VERSION}_amd64"
rm -rf "$PKGROOT"
mkdir -p "$PKGROOT/DEBIAN" "$PKGROOT/opt/cover-vault" "$PKGROOT/usr/share/applications" "$PKGROOT/usr/share/icons/hicolor/scalable/apps"
cp -R dist/CoverVault/* "$PKGROOT/opt/cover-vault/"
cp packaging/linux/cover-vault.desktop "$PKGROOT/usr/share/applications/"
cp assets/cover-vault.svg "$PKGROOT/usr/share/icons/hicolor/scalable/apps/cover-vault.svg"
cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: cover-vault
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Cover Vault
Description: Desktop application for encrypted folders hidden in cover files
EOF
dpkg-deb --build "$PKGROOT" "dist/CoverVault-${VERSION}-Linux-amd64.deb"
