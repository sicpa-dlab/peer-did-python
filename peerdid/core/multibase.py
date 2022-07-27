"""Multibase utility methods."""

from enum import Enum
from typing import Tuple

import base58


class MultibaseFormat(Enum):
    """Supported multibase formats."""

    BASE58 = "z"


def from_base58(base58encoded: str) -> bytes:
    """Convert from base58 to bytes."""
    try:
        return base58.b58decode(base58encoded)
    except ValueError:
        raise ValueError(
            "Invalid key: Invalid base58 encoding: " + base58encoded
        ) from None


def to_base58(value: bytes) -> str:
    """Convert a bytes value to base58 encoding."""
    return base58.b58encode(value).decode("utf-8")


def from_multibase(multibase: str) -> Tuple[str, bytes]:
    """Convert from multibase to bytes."""
    if not multibase:
        raise ValueError("Invalid key: No transform part in multibase encoding")
    transform = multibase[0]
    if not transform == MultibaseFormat.BASE58.value:
        raise ValueError(
            "Invalid key: Unsupported transform part of peer_did: " + transform
        )
    encnumbasis = multibase[1:]
    decoded = from_base58(encnumbasis)
    return encnumbasis, decoded


def to_multibase(value: bytes, format: MultibaseFormat = None) -> str:
    """Convert to base58-encoded multibase."""
    if not format or format == MultibaseFormat.BASE58:
        return MultibaseFormat.BASE58.value + to_base58(value)
    raise ValueError("Unsupported multibase format")
