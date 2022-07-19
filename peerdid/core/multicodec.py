"""Multicodec utility methods."""

from enum import Enum
from typing import Tuple, Union

import varint


class Codec(Enum):
    """Multicodec supported codecs."""

    X25519 = 0xEC
    ED25519 = 0xED

    def encode_multicodec(self, value: bytes) -> bytes:
        """Encode a value with this codec."""
        prefix = varint.encode(self.value)
        return prefix + value


def from_multicodec(value: Union[str, bytes]) -> Tuple[bytes, Codec]:
    """Decode a multicodec value."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    try:
        prefix_int = varint.decode_bytes(value)
    except Exception:
        raise ValueError(
            "Invalid key: Invalid multicodec prefix in {}".format(str(value))
        )

    try:
        codec = Codec(prefix_int)
    except ValueError:
        raise ValueError(
            "Invalid key: Unknown multicodec prefix {} in {}".format(
                str(prefix_int), str(value)
            )
        )

    prefix = varint.encode(prefix_int)
    return value[len(prefix) :], codec
