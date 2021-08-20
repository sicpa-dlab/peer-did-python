from enum import Enum
from typing import NamedTuple


class PublicKeyTypeAgreement(Enum):
    X25519 = 0xEC


class PublicKeyTypeAuthentication(Enum):
    ED25519 = 0xED
    SECP256K1 = 0xE7


class EncodingType(Enum):
    BASE58 = 0


PublicKeyAgreement = NamedTuple(
    "PublicKeyAgreement",
    [
        ("encoding_type", EncodingType),
        ("encoded_value", str),
        ("type", PublicKeyTypeAgreement),
    ],
)

PublicKeyAuthentication = NamedTuple(
    "PublicKeyAuthentication",
    [
        ("encoding_type", EncodingType),
        ("encoded_value", str),
        ("type", PublicKeyTypeAuthentication),
    ],
)

JSON = str
PEER_DID = str
