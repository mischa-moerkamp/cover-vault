from __future__ import annotations

import argparse
import getpass
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .archive import DEFAULT_EXCLUDES, GIT_HISTORY_EXCLUDE
from .errors import CoverVaultError
from .stego import DEFAULT_MAX_USAGE_RATIO
from .vault import cover_info, hide_folder, plan_folder, reveal_folder


def _package_version() -> str:
    try:
        return version("cover-vault")
    except PackageNotFoundError:  # pragma: no cover - source-tree convenience
        return "0+unknown"


def _password_from_args(args: argparse.Namespace, *, confirm: bool = False) -> str:
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Password: ")
    if confirm and not args.password:
        repeated = getpass.getpass("Confirm password: ")
        if password != repeated:
            raise CoverVaultError("Passwords do not match.")
    return password


def _excludes_from_args(args: argparse.Namespace) -> tuple[str, ...]:
    if args.no_default_excludes:
        default_excludes: tuple[str, ...] = ()
    elif args.include_git_history:
        default_excludes = tuple(
            sorted(name for name in DEFAULT_EXCLUDES if name != GIT_HISTORY_EXCLUDE)
        )
    else:
        default_excludes = tuple(sorted(DEFAULT_EXCLUDES))
    return default_excludes + tuple(args.exclude)


def _add_exclude_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Folder or file name to exclude. Can be repeated, e.g. --exclude node_modules --exclude dist.",
    )
    parser.add_argument(
        "--include-git-history",
        action="store_true",
        help=(
            "Include the .git directory so the encrypted archive contains Git commit history. "
            "Other default excludes still apply."
        ),
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Do not apply default excludes such as .git, .hg, .svn, __pycache__, and .DS_Store.",
    )


def _add_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode",
        choices=("auto", "wav-lsb", "image-lsb"),
        default="auto",
        help="Carrier mode. auto selects PCM WAV or lossless image LSB from the cover type.",
    )


def _add_usage_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-usage-ratio",
        type=float,
        default=DEFAULT_MAX_USAGE_RATIO,
        help=(
            "Fail if the encrypted payload would use more than this fraction of the cover capacity. "
            f"Default: {DEFAULT_MAX_USAGE_RATIO:.2f}. Use 1.0 to disable the ratio guard."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cover-vault",
        description="Encrypt folders and hide them inside lossless audio or image cover files.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cover-vault {_package_version()}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    hide = subparsers.add_parser(
        "hide", help="Encrypt a folder and hide it in a cover file."
    )
    hide.add_argument(
        "source",
        type=Path,
        help="Folder to encrypt. VCS history is excluded by default.",
    )
    hide.add_argument("cover", help="Original cover file path or HTTP(S) URL.")
    hide.add_argument(
        "output",
        type=Path,
        help="Output stego file. Use .wav for WAV mode or .png/.bmp/.tiff for image mode.",
    )
    _add_mode_arg(hide)
    _add_usage_arg(hide)
    hide.add_argument("--password", help="Password to use. Omit to enter securely.")
    _add_exclude_args(hide)

    reveal = subparsers.add_parser(
        "reveal", help="Recover a hidden folder from a stego file."
    )
    reveal.add_argument(
        "stego", type=Path, help="Stego file containing the hidden payload."
    )
    reveal.add_argument(
        "cover", help="The exact original cover file path or HTTP(S) URL."
    )
    reveal.add_argument("destination", type=Path, help="Folder to restore into.")
    reveal.add_argument(
        "--mode",
        choices=("auto", "wav-lsb", "image-lsb"),
        default="auto",
        help="Payload extraction mode.",
    )
    reveal.add_argument("--password", help="Password to use. Omit to enter securely.")
    reveal.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace destination if it already exists.",
    )

    info = subparsers.add_parser(
        "info", help="Print exact cover hash and supported mode capacities."
    )
    info.add_argument("cover", help="Cover file path or HTTP(S) URL.")

    plan = subparsers.add_parser(
        "plan", help="Estimate whether a folder fits a cover before hiding it."
    )
    plan.add_argument(
        "source",
        type=Path,
        help="Folder to encrypt. VCS history is excluded by default.",
    )
    plan.add_argument("cover", help="Original cover file path or HTTP(S) URL.")
    _add_mode_arg(plan)
    _add_usage_arg(plan)
    _add_exclude_args(plan)

    return parser


def _print_usage(result: dict) -> None:
    print(f"Payload capacity: {result['capacity_bytes']} bytes")
    print(f"Cover usage: {result['usage_percent']:.2f}%")
    if result.get("usage_warning"):
        print(
            "Note: usage is above 10%. A larger cover or smaller source is recommended for lower distortion."
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "hide":
            password = _password_from_args(args, confirm=True)
            result = hide_folder(
                args.source,
                args.cover,
                args.output,
                password=password,
                mode=args.mode,
                excludes=_excludes_from_args(args),
                max_usage_ratio=args.max_usage_ratio,
            )
            print(
                f"Hidden encrypted archive with {result['files_encrypted']} files in {result['output']} "
                f"using {result['mode']} mode. Payload: {result['payload_bytes']} bytes."
            )
            _print_usage(result)
            print(f"Original cover SHA-256: {result['cover_sha256']}")
            return 0

        if args.command == "reveal":
            password = _password_from_args(args)
            result = reveal_folder(
                args.stego,
                args.cover,
                args.destination,
                password=password,
                mode=args.mode,
                overwrite=args.overwrite,
            )
            print(
                f"Restored {result['files_decrypted']} files into {result['destination']} "
                f"using {result['mode']} mode."
            )
            print(f"Original cover SHA-256: {result['cover_sha256']}")
            return 0

        if args.command == "info":
            result = cover_info(args.cover)
            print(f"Cover bytes: {result['cover_bytes']}")
            print(f"Cover SHA-256: {result['cover_sha256']}")
            if result["supported_modes"]:
                print("Supported modes:")
                for mode in result["supported_modes"]:
                    print(f"  - {mode}: {result['capacities'][mode]} payload bytes")
            else:
                print("Supported modes: none detected")
            return 0

        if args.command == "plan":
            result = plan_folder(
                args.source,
                args.cover,
                mode=args.mode,
                excludes=_excludes_from_args(args),
                max_usage_ratio=args.max_usage_ratio,
            )
            print(f"Selected mode: {result['mode']}")
            print(f"Files to encrypt: {result['files_to_encrypt']}")
            print(f"Compressed archive estimate: {result['archive_bytes']} bytes")
            print(
                f"Encrypted payload estimate: {result['estimated_payload_bytes']} bytes"
            )
            _print_usage(result)
            print(f"Fits raw capacity: {'yes' if result['fits_capacity'] else 'no'}")
            print(
                f"Fits ratio limit ({result['max_usage_ratio']:.2%}): {'yes' if result['fits_ratio_limit'] else 'no'}"
            )
            if result["advisory"]:
                print(f"Advisory: {result['advisory']}")
            print(f"Original cover SHA-256: {result['cover_sha256']}")
            return 0 if result["fits_capacity"] and result["fits_ratio_limit"] else 1

        parser.error("Unknown command.")
        return 2
    except CoverVaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
