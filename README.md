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
