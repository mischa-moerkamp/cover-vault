# Cover Vault

Cover Vault encrypts the current filesystem state of a folder and stores the encrypted archive in a carrier that remains usable as an ordinary WAV, lossless image, or PDF document.

```text
codebase/                    # folder to protect; Git history excluded by default
cover.wav/png/pdf            # public, non-secret original cover
cover.stego.wav/png/pdf      # cover carrying the encrypted folder payload
restored-codebase/           # recovered folder after reveal
```

To reveal any vault, you need:

1. the carrier file containing the encrypted vault,
2. the password, and
3. the exact original cover-file bytes, from a local file or the original download URL.

The original cover is included in password-based key derivation. Re-saving, optimizing, re-encoding, or otherwise changing it produces different bytes and prevents recovery.

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

Symbolic links, FIFOs, sockets, device nodes, and other special filesystem objects are rejected before encryption with the offending paths listed. Hard-linked regular files are archived as independent regular files so the vault is always restorable. Ownership, ACLs, extended attributes, sparse-file layout, and platform-specific metadata are not preserved; Cover Vault creates a portable file-tree snapshot rather than a byte-for-byte filesystem image.

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

### `pdf-attachment`

Stores the encrypted vault as a standard PDF embedded-file attachment named `cover-vault.cvault`. The PDF is parsed and rewritten with a normal cross-reference table, trailer, `startxref`, and final `%%EOF`. Existing attachments are retained.

Important differences from the LSB modes:

- The output is a structurally valid PDF rather than a file with arbitrary bytes after `%%EOF`.
- Page pixels and text are not used as a steganographic channel.
- The encrypted attachment is easy to discover with PDF inspection or attachment tools. This mode is a standards-based encrypted container, not covert steganography.
- PDF sanitizers, attachment-removal tools, optimization software, or some “Save As” operations may remove embedded files.
- Rewriting a digitally signed PDF invalidates its existing signatures, so signed PDFs should not be used as covers.
- Encrypted/password-protected PDF covers and PDFs that already contain the reserved attachment name are rejected.

Use PDF attachment mode when PDF compatibility matters more than concealment. Keep a separate tested backup of important vaults.

## Capacity and cover selection

Use `plan` before hiding:

```bash
cover-vault plan ./my-codebase ./cover.png
cover-vault plan ./my-codebase ./cover.wav --mode wav-lsb
cover-vault plan ./my-codebase ./cover.pdf --mode pdf-attachment
```

For WAV and image modes, capacity is based on the number of available LSB positions. A PDF attachment has no fixed steganographic capacity, so the original PDF file size is used only as a reference denominator for the size-ratio guard.

The default maximum usage ratio is 25%:

```text
max usage ratio = encrypted payload bytes / reference capacity bytes
```

Cover Vault warns above 10% and refuses the operation above 25%. Lower ratios generally make carrier changes less conspicuous, although a PDF attachment remains directly discoverable regardless of ratio.

Raise the limit explicitly when required:

```bash
cover-vault hide ./my-codebase ./cover.pdf ./cover.stego.pdf \
  --max-usage-ratio 0.40
```

Use `1.0` to disable the ratio guard. This does not make a high-ratio carrier discreet.

## Security model

New vaults use format version 2 with:

- `scrypt` with `N=2^17`, `r=8`, and `p=1` to derive a 256-bit cover-bound master key,
- separate HKDF-derived keys for payload encryption and LSB placement,
- AES-256-GCM authenticated encryption,
- the complete serialized payload header authenticated as AES-GCM associated data,
- a fresh random salt and nonce per payload,
- a compressed `tar.gz` archive before encryption,
- a cover-derived, scattered, whitened, and authenticated LSB bootstrap containing the fixed version-2 KDF tuple and random salt, followed by password-keyed payload placement.

The LSB bootstrap lets recovery software obtain the random salt before running scrypt, but new vaults no longer expose a fixed marker in the first carrier samples or channels. Its positions and whitening are derived from the exact original cover. The encrypted payload marker remains password-keyed and scattered. Placement version 2 from Cover Vault 2.0 remains readable; new image and WAV vaults are written with placement version 3.

Version-2 KDF metadata must exactly match `N=2^17`, `r=8`, and `p=1`; attacker-selected higher-cost values are rejected before scrypt runs. KDF metadata, nonce lengths, header sizes, archive member counts, extraction sizes, and path depth are validated before expensive or destructive operations.

Output carrier files are written through a temporary sibling file. Existing output files are not replaced unless `--overwrite-output` (or the GUI checkbox) is selected, and the output can never be the exact original cover or a path inside the source folder. Folder restoration is staged in a temporary directory and installed with a rename-to-backup/replace/rollback sequence. Filesystem roots, the home directory, the current working directory or its parents, symbolic-link destinations, and destinations containing the vault or original cover are rejected.

Only version-2 encrypted payloads are accepted. Vaults made with 1.x must be restored using that release and then recreated.

The exact original WAV, image, or PDF cover is part of key derivation. A modified, re-encoded, optimized, or otherwise non-identical original cover will not unlock the payload.

Passwords supplied with `--password` may be visible in shell history or process listings. For interactive use, omit the option and enter the password at the prompt.

This project provides authenticated encryption, but its carrier techniques should not be assumed to make encrypted data undetectable. Use a long, unique password and retain tested backups.

To keep the current one-shot archive and AES-GCM implementation from exhausting memory, creation rejects source trees above 512 MiB of regular-file data, local cover/stego files above 512 MiB, decoded WAV data above 512 MiB, and images above 50 million pixels. Remote covers remain limited to 256 MiB. Split larger folders or add exclusions.

## Installation for local development

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
```

Install development checks and run them locally:

```bash
pip install -e '.[dev]'
ruff check .
ruff format --check .
python -m pytest
```

Repository automation includes:

- `.github/workflows/ci.yml` for Ruff checks, a Python/OS test matrix, and package-build validation,
- `.github/workflows/codeql.yml` for scheduled and pull-request CodeQL analysis,
- `.github/workflows/dependency-review.yml` to reject newly introduced high-severity vulnerable dependencies in pull requests,
- `.github/workflows/release.yml` for verified Windows, macOS, and Linux installer builds,
- `.github/dependabot.yml` for monthly Python and GitHub Actions dependency updates.

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

Existing output files are preserved by default. Replace one only with explicit opt-in:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png --overwrite-output
```

The original cover path is always rejected as the output, even with this option.

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
cover-vault hide ./my-codebase ./cover.pdf ./cover.stego.pdf --mode pdf-attachment
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
- an explicit checkbox before an existing output vault may be replaced,
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

Installer builds are platform-specific because PyInstaller must build on the operating system it targets. The repository includes local build scripts and a GitHub Actions workflow at `.github/workflows/release.yml`. Installer builds use the exact top-level runtime and PyInstaller versions recorded in `requirements/release.txt`; update that file deliberately and validate all three platforms together.

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

Push a version tag matching `pyproject.toml` (for example `v2.1.0`), or run the workflow manually, to build all three artifacts on native GitHub-hosted runners. Local and CI installer scripts reject a version override that disagrees with the package version. Artifacts are uploaded separately as:

- `windows-installer`,
- `macos-dmg`,
- `linux-deb`.

The workflow runs Ruff formatting/lint checks and the full test suite before building packages. Production releases should additionally configure Windows code signing and Apple signing/notarization secrets.

## Desktop packaging notes

- `cover-vault-gui.spec` is the shared PyInstaller specification.
- `assets/cover-vault.svg` is used by the Linux desktop launcher. Optional `.ico` and `.icns` files can be placed in the same directory for branded Windows and macOS binaries; builds fall back to the default application icon when they are absent.
- The generated application remains fully offline except when a user explicitly supplies an HTTP(S) original-cover URL during restore through the command-line interface. The current GUI uses local file pickers only.
- The Windows and Linux packages target 64-bit systems. Additional architectures should be built on matching runners and labeled separately.
