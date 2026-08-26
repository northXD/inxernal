"""Apply the tested, narrow marker patch to Frida Gadget 17.17.0.

The previous implementation replaced every case variant of ``frida``. That
also mutated RPC resource names, GType symbols, protocol strings and enum
names. This version is deliberately fail-closed: it accepts one source hash,
asserts every expected occurrence count and verifies the exact output hash.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path


SOURCE_SIZE = 26_590_424
SOURCE_SHA256 = "2f683924ea0c8a43fad01a7d01b77a238696936b9cd2412a0634480187d56c2a"
OUTPUT_SHA256 = "cfd21e76394bcf86481707754720c3d279016066e71aadeeef26d6ecdff4f981"


@dataclass(frozen=True)
class Rule:
    old: bytes
    new: bytes
    count: int
    label: str


RULES = (
    Rule(b"frida-gadget", b"nxrth-gadgxt", 5, "frida-gadget"),
    Rule(b"gum-js-loop", b"app-js-loop", 1, "gum-js-loop"),
    Rule(b"\0gmain\0", b"\0gloop\0", 1, "standalone gmain"),
    Rule(b"\0gdbus\0", b"\0bndrs\0", 1, "standalone gdbus"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch(input_path: Path, output_path: Path) -> None:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must differ")

    data = input_path.read_bytes()
    if len(data) != SOURCE_SIZE:
        raise ValueError(f"unexpected source size: {len(data):,} (expected {SOURCE_SIZE:,})")
    source_hash = sha256(data)
    if source_hash != SOURCE_SHA256:
        raise ValueError(f"unsupported source SHA-256: {source_hash}")
    if data.count(b"linjector") != 0:
        raise ValueError("unexpected linjector marker count")

    for rule in RULES:
        if len(rule.old) != len(rule.new):
            raise RuntimeError(f"internal length mismatch for {rule.label}")
        actual = data.count(rule.old)
        if actual != rule.count:
            raise ValueError(
                f"{rule.label}: found {actual}, expected exactly {rule.count}"
            )
        data = data.replace(rule.old, rule.new)
        print(f"{rule.label}: patched {actual}")

    if len(data) != SOURCE_SIZE:
        raise RuntimeError("patched binary size changed")
    output_hash = sha256(data)
    if output_hash != OUTPUT_SHA256:
        raise RuntimeError(f"unexpected output SHA-256: {output_hash}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(output_path)
    print(f"wrote {output_path} ({len(data):,} bytes, SHA-256 {output_hash})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create the verified narrow-marker Frida Gadget build"
    )
    parser.add_argument("input", type=Path, help="stock Frida Gadget 17.17.0")
    parser.add_argument("output", type=Path, help="patched output path")
    args = parser.parse_args()
    patch(args.input, args.output)


if __name__ == "__main__":
    main()
