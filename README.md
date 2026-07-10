# Cover Vault

Cover Vault encrypts the current filesystem state of a folder and stores the encrypted archive inside a cover file that remains usable as an ordinary WAV, lossless image, or PDF document.

```text
codebase/                    # folder to protect; Git history excluded by default
cover.wav/png/pdf            # public, non-secret original cover
cover.stego.wav/png/pdf      # cover carrying the encrypted folder payload
restored-codebase/           # recovered folder after reveal
```

To reveal a folder, you need:

1. the stego file,
2. the password, and
3. the exact original cover-file bytes, from a local file or the original download URL.

## What gets archived

Cover Vault archives the current files in the target folder. It excludes these names by default:

- `.git`
- `.hg`
- `.svn`
- `__pycache__`
- `.DS_Store`

A Git repository is therefore treated as a snapshot of its current working tree rather than its complete version-control database. Untracked files are included unless an exclusion rule matches them.

Include Git commit history explicitly:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png --include-git-history
cover-vault plan ./my-codebase ./cover.png --include-git-history
```

`--include-git-history` includes `.git` while retaining the other default exclusions. This is usually safer than `--no-default-excludes`, which disables every default exclusion.

Add custom exclusions by name:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png \
  --exclude node_modules \
  --exclude dist \
  --exclude .venv
```

## Supported carrier modes

### `wav-lsb`

Stores encrypted bits in the least significant bit of PCM WAV samples.

Recommended covers:

- uncompressed PCM WAV,
- longer recordings,
- naturally textured or noisy audio rather than silence or sparse tones.

The output must be a WAV file.

### `image-lsb`

Stores encrypted bits in the least significant bit of RGB image channels.

Recommended covers:

- PNG, BMP, or TIFF output,
- large photographs or textured artwork,
- images without large flat or solid-color regions.

JPEG and lossy WebP output are not supported because lossy encoding can destroy the hidden bits.

### `pdf-append`

Appends a structured encrypted payload after the PDF's final `%%EOF` marker. Most PDF readers tolerate trailing data, so the resulting file remains usable as a PDF.

Important differences from the LSB modes:

- PDF mode does not alter page pixels, text, or objects.
- It is broadly compatible and fully reversible.
- It is less covert than LSB embedding because appended data can be found by inspecting the file structure or size.
- PDF optimization, sanitization, rewriting, linearization, or “Save As” operations may remove the appended payload.

Use an ordinary, sufficiently large PDF and keep the exact original PDF unchanged for recovery.

## Capacity and cover selection

Use `plan` before hiding:

```bash
cover-vault plan ./my-codebase ./cover.png
cover-vault plan ./my-codebase ./cover.wav --mode wav-lsb
cover-vault plan ./my-codebase ./cover.pdf --mode pdf-append
```

For WAV and image modes, capacity is based on the number of available LSB positions. For PDF mode, the original PDF file size is used as the reference denominator because appended data is not constrained by a fixed physical bit capacity.

The default maximum usage ratio is 25%:

```text
max usage ratio = encrypted payload bytes / reference capacity bytes
```

Cover Vault warns above 10% and refuses the operation above 25%. Lower ratios generally make file-size changes and carrier modifications less conspicuous.

Raise the limit explicitly when required:

```bash
cover-vault hide ./my-codebase ./cover.pdf ./cover.stego.pdf \
  --max-usage-ratio 0.40
```

Use `1.0` to disable the ratio guard. This does not make a high-ratio carrier discreet.

## Security model

Cover Vault uses:

- `scrypt` to derive a 256-bit key from the password and exact original cover bytes,
- AES-256-GCM authenticated encryption,
- a fresh random salt and nonce per payload,
- a compressed `tar.gz` archive before encryption,
- password-and-cover-derived pseudorandom bit placement for WAV and image modes.

The original cover is part of key derivation. A modified, re-encoded, optimized, or otherwise non-identical original cover will not unlock the payload.

Passwords supplied with `--password` may be visible in shell history or process listings. For interactive use, omit the option and enter the password at the prompt.

## Installation for local development

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
```

Run tests:

```bash
python -m pytest
```

## Command-line usage

### Inspect a cover

```bash
cover-vault info ./cover.png
cover-vault info ./cover.wav
cover-vault info ./cover.pdf
```

This prints the exact SHA-256 hash, detected carrier modes, and capacity or reference-capacity values.

### Hide in an image

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png
```

### Reveal from an image

```bash
cover-vault reveal ./cover.stego.png ./cover.png ./restored-codebase
```

### Hide in WAV audio

```bash
cover-vault hide ./my-codebase ./cover.wav ./cover.stego.wav --mode wav-lsb
```

### Reveal from WAV audio

```bash
cover-vault reveal ./cover.stego.wav ./cover.wav ./restored-codebase --mode wav-lsb
```

### Hide in a PDF

```bash
cover-vault hide ./my-codebase ./cover.pdf ./cover.stego.pdf
```

Or select the mode explicitly:

```bash
cover-vault hide ./my-codebase ./cover.pdf ./cover.stego.pdf --mode pdf-append
```

### Reveal from a PDF

```bash
cover-vault reveal ./cover.stego.pdf ./cover.pdf ./restored-codebase
```

### Use a remotely hosted original cover

If the exact original cover remains available at a stable URL:

```bash
cover-vault reveal ./cover.stego.pdf \
  "https://example.org/public-document.pdf" \
  ./restored-codebase
```

## Desktop application

Cover Vault includes a cross-platform graphical interface with:

- folder, cover-file, output-file, and restore-destination pickers,
- masked password and password-confirmation fields,
- automatic carrier detection or explicit image, WAV, and PDF modes,
- a capacity preview showing estimated encrypted size, carrier usage, and fit status,
- configurable maximum usage ratio,
- optional inclusion of Git history and comma-separated custom exclusions,
- progress and status reporting while work runs outside the UI thread,
- create-vault and restore-vault tabs.

Run the GUI from a development checkout:

```bash
pip install -e .
cover-vault-gui
```

You can also start it as a module:

```bash
python -m cover_vault.gui
```

The GUI deliberately keeps passwords in memory only for the duration of an operation and clears the password fields after a successful create or restore. It does not store passwords in preferences or pass them through command-line arguments.

## Building desktop installers

Installer builds are platform-specific because PyInstaller must build on the operating system it targets. The repository includes local build scripts and a GitHub Actions workflow at `.github/workflows/release.yml`.

### Windows installer

Requirements:

- Python 3.10 or newer,
- Inno Setup 6 available as `iscc.exe`.

Build from PowerShell:

```powershell
.\packaging\windows\build.ps1
```

This creates an Inno Setup `.exe` installer under `dist\installer`. The installer creates a Start Menu shortcut and offers an optional desktop shortcut.

### macOS disk image

Build on macOS:

```bash
./packaging/macos/build.sh
```

This creates a `.dmg` containing `Cover Vault.app` and an Applications link. Users install it by dragging the application into Applications. macOS applications normally appear in Launchpad and Spotlight rather than installing a desktop shortcut.

For public distribution, sign the `.app` with an Apple Developer ID and notarize the final DMG. The included script builds an unsigned development artifact.

### Linux Debian package

Build on a Debian or Ubuntu system:

```bash
./packaging/linux/build.sh
```

This creates an `amd64` `.deb` under `dist`. Installation adds Cover Vault to the desktop environment's application menu through a `.desktop` launcher and installs the application icon. Users can pin or copy that launcher to the desktop according to their desktop environment's policy.

### Automated release builds

Push a version tag such as `v1.0.0`, or run the workflow manually, to build all three artifacts on native GitHub-hosted runners. Artifacts are uploaded separately as:

- `windows-installer`,
- `macos-dmg`,
- `linux-deb`.

The workflow runs the test suite before building packages. Production releases should additionally configure Windows code signing and Apple signing/notarization secrets.

## Desktop packaging notes

- `cover-vault-gui.spec` is the shared PyInstaller specification.
- `assets/cover-vault.svg` is used by the Linux desktop launcher. Optional `.ico` and `.icns` files can be placed in the same directory for branded Windows and macOS binaries; builds fall back to the default application icon when they are absent.
- The generated application remains fully offline except when a user explicitly supplies an HTTP(S) original-cover URL during restore through the command-line interface. The current GUI uses local file pickers only.
- The Windows and Linux packages target 64-bit systems. Additional architectures should be built on matching runners and labeled separately.
