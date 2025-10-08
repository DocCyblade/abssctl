#!/usr/bin/env python3
"""Utility script to validate tagging conventions against package version.

This script is invoked from CI workflows to ensure that Git tags follow the
policy defined in ADR-033 and that the tag's semantic version matches the
``__version__`` value declared in ``src/abssctl/__init__.py``.
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
INIT_PATH = PROJECT_ROOT / "src" / "abssctl" / "__init__.py"


class TagValidationError(RuntimeError):
    """Raised when a tag does not match the expected scheme."""


def load_package_version() -> str:
    """Parse ``__version__`` from the package without importing it."""
    source = INIT_PATH.read_text(encoding="utf-8")
    module = ast.parse(source, filename=str(INIT_PATH))

    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, "id", None) == "__version__":
                    value = getattr(node.value, "value", None)
                    if value is None and isinstance(node.value, ast.Str):
                        value = node.value.s
                    if value is None:
                        raise TagValidationError(
                            "Unable to determine __version__ from __init__.py"
                        )
                    return value  # type: ignore[return-value]
    raise TagValidationError("Unable to determine __version__ from __init__.py")


def expected_version_from_tag(tag: str, kind: str) -> str:
    """Return the expected version string extracted from the tag."""
    if kind == "release":
        if not tag.startswith("v") or tag.endswith("-dev"):
            raise TagValidationError(
                f"Release tags must be formatted as v<version>; received '{tag}'."
            )
        return tag[1:]
    if kind == "dev":
        if not (tag.startswith("v") and tag.endswith("-dev")):
            raise TagValidationError(
                f"Dev tags must be formatted as v<version>-dev; received '{tag}'."
            )
        return tag[1:-4]  # strip leading v and trailing -dev
    if kind == "docs":
        if not tag.startswith("docs-v"):
            raise TagValidationError(
                f"Docs tags must be formatted as docs-v<version>; received '{tag}'."
            )
        return tag[len("docs-v") :]
    raise TagValidationError(f"Unknown tag kind '{kind}'.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Return parsed CLI arguments for tag validation."""
    parser = argparse.ArgumentParser(description="Validate tag name against package version.")
    parser.add_argument(
        "--kind",
        required=True,
        choices=["release", "dev", "docs"],
        help="Tag category to validate.",
    )
    parser.add_argument("--tag", required=True, help="Git tag name to validate.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for GitHub Actions tag validation."""
    args = parse_args(argv)
    try:
        expected_version = expected_version_from_tag(args.tag, args.kind)
        package_version = load_package_version()
    except TagValidationError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    if package_version != expected_version:
        sys.stderr.write(
            f"Tag version '{expected_version}' does not match package version "
            f"'{package_version}'.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
