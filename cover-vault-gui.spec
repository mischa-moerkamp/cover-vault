# PyInstaller specification for the graphical application.
from pathlib import Path
import sys

root = Path(SPECPATH)
icon_candidates = {
    "win32": root / "assets" / "cover-vault.ico",
    "darwin": root / "assets" / "cover-vault.icns",
}
icon = icon_candidates.get(sys.platform)
icon_arg = str(icon) if icon and icon.exists() else None

a = Analysis(
    [str(root / "src" / "cover_vault" / "gui.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[],
    hiddenimports=["PIL._tkinter_finder"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CoverVault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=icon_arg,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name="CoverVault")
if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Cover Vault.app",
        icon=icon_arg,
        bundle_identifier="io.covervault.desktop",
        info_plist={"CFBundleDisplayName": "Cover Vault"},
    )
