from enum import Enum
from typing import Tuple

import base58


class MultibasePrefix(Enum):
    BASE58 = "z"


def to_base58_multibase(value: bytes) -> str:
    return MultibasePrefix.BASE58.value + to_base58(value)


def to_base58(value: bytes) -> str:
    return base58.b58encode(value).decode("utf-8")


def from_base58_multibase(multibase: str) -> Tuple[str, bytes]:
    if not multibase:
        raise ValueError("Invalid key: No transform part in multibase encoding")
    transform = multibase[0]
    if not transform == MultibasePrefix.BASE58.value:
        raise ValueError(
            "Invalid key: Unsupported transform part of peer_did: " + transform
        )
    encnumbasis = multibase[1:]
    decoded = from_base58(encnumbasis)
    return encnumbasis, decoded


def from_base58(base58encoded: str) -> bytes:
    if not is_base58(base58encoded):
        raise ValueError("Invalid key: Invalid base58 encoding: " + base58encoded)
    decoded = base58.b58decode(base58encoded)
    return decoded


def is_base58(key: str) -> bool:
    alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    invalid_chars = set(key) - alphabet
    return not invalid_chars
