"""Multicodec utility methods."""

from enum import Enum
from io import BytesIO
from typing import Tuple, Union

import varint


class Codec(Enum):
    """Multicodec supported codecs."""

    X25519 = 0xEC
    ED25519 = 0xED
    SHA256 = 0x12

    def encode_multicodec(self, value: bytes) -> bytes:
        """Encode a value with this codec."""
        prefix = varint.encode(self.value)
        return prefix + value

    def encode_multicodec_with_length(self, value: bytes) -> bytes:
        """Encode a value with this codec."""
        prefix = varint.encode(self.value) + varint.encode(len(value))
        return prefix + value


def from_multicodec(value: Union[str, bytes]) -> Tuple[bytes, Codec]:
    """Decode a multicodec value."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    buffer = BytesIO(value)
    try:
        prefix_int = varint.decode_stream(buffer)
    except Exception:
        raise ValueError("Invalid key: Invalid multicodec prefix in {}".format(value))
    remain = buffer.read()

    try:
        codec = Codec(prefix_int)
    except ValueError:
        raise ValueError(
            "Invalid key: Unknown multicodec prefix {} in {}".format(
                hex(prefix_int), value
            )
        )

    return remain, codec
