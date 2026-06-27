# Cover Vault

Cover Vault encrypts the current filesystem state of a folder and hides the encrypted archive inside a lossless audio or image cover file.

The intended workflow is:

```text
codebase/                   # folder to protect; .git history excluded by default
cover.wav or cover.png      # public, non-secret cover file
cover.stego.wav/png         # file that carries the encrypted folder payload
restored-codebase/          # recovered folder after reveal
```

To reveal the folder, you need:

1. the stego file,
2. the password, and
3. the exact original cover file bytes, either from a local copy or from the original download URL.

Cover Vault archives the current files in the target folder. It excludes Git commit history by default. Default excludes:

- `.git`
- `.hg`
- `.svn`
- `__pycache__`
- `.DS_Store`

That means a Git repository is treated as its current working tree snapshot, not as its full version-control database. Untracked files are included unless they match an exclude rule.

To include Git commit history, include the `.git` directory explicitly:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png --include-git-history
cover-vault plan ./my-codebase ./cover.png --include-git-history
```

`--include-git-history` keeps the other default excludes in place. This is usually preferable to `--no-default-excludes`, because Git history can be included without also archiving `__pycache__`, `.DS_Store`, `.hg`, or `.svn`.

You can add more excludes:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png \
  --exclude node_modules \
  --exclude dist \
  --exclude .venv
```

You can disable all default excludes with `--no-default-excludes`. This also includes `.git`, but it removes every other default exclude too.

## Supported carrier modes

Cover Vault intentionally focuses on reversible, lossless carriers.

### `wav-lsb`

Hides encrypted bits in the least significant bit of PCM WAV samples.

Good covers:

- uncompressed PCM WAV,
- longer audio files,
- naturally textured/noisy recordings rather than very quiet/sparse audio.

### `image-lsb`

Hides encrypted bits in the least significant bit of RGB image channels.

Good covers:

- PNG,
- BMP,
- TIFF,
- larger images,
- photographs or textured artwork rather than flat diagrams or solid-color images.

## Capacity and cover selection

Cover choice matters. Cover Vault estimates how much payload can fit in a cover and refuses to hide data when the payload would occupy too much of the available carrier capacity.

The default limit is:

```text
max usage ratio = 25% of available carrier capacity
```

It also prints a warning above 10% usage. Lower is better.

A larger cover with a smaller payload causes fewer changed LSB positions as a fraction of the total carrier, while a small cover with a large payload changes more of the cover and is more likely to create visible, audible, or statistical artifacts.

Use `plan` before hiding:

```bash
cover-vault plan ./my-codebase ./cover.png
cover-vault plan ./my-codebase ./cover.png --include-git-history
```

Example output:

```text
Selected mode: image-lsb
Files to encrypt: 12
Compressed archive estimate: 18420 bytes
Encrypted payload estimate: 18742 bytes
Payload capacity: 245744 bytes
Cover usage: 7.63%
Fits raw capacity: yes
Fits ratio limit (25.00%): yes
```

If the plan does not fit, use a larger cover, reduce the source folder, add excludes, or explicitly raise the limit:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png --max-usage-ratio 0.40
```

Use `1.0` only when you want to disable the ratio guard.

## Security model

Cover Vault uses:

- `scrypt` to derive a 256-bit key from the password and the exact original cover bytes,
- `AES-256-GCM` for authenticated encryption,
- a fresh random salt and nonce per hidden payload,
- a compressed `tar.gz` archive before encryption,
- password-and-cover-derived pseudorandom placement of stego bits across the full carrier.

## Install for local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run tests:

```bash
python -m pytest
```

## Usage

### Check a cover file

This prints the exact SHA-256 hash and detected payload capacities:

```bash
cover-vault info ./cover.png
cover-vault info ./cover.wav
```

### Plan a hide operation

```bash
cover-vault plan ./my-codebase ./cover.png
cover-vault plan ./my-codebase ./cover.wav --mode wav-lsb
```

### Hide a folder in an image

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png
```

With an explicit password for scripts or tests:

```bash
cover-vault hide ./my-codebase ./cover.png ./cover.stego.png \
  --password "correct horse battery staple"
```

### Reveal a folder from an image

```bash
cover-vault reveal ./cover.stego.png ./cover.png ./restored-codebase
```

Or, if the exact original cover is available at a stable URL:

```bash
cover-vault reveal ./cover.stego.png "https://example.org/public-domain-cover.png" ./restored-codebase
```

### Hide a folder in a WAV file

```bash
cover-vault hide ./my-codebase ./cover.wav ./cover.stego.wav --mode wav-lsb
```

### Reveal a folder from a WAV file

```bash
cover-vault reveal ./cover.stego.wav ./cover.wav ./restored-codebase --mode wav-lsb
```
