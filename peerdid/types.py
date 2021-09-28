from enum import Enum
from typing import NamedTuple, Union


class PublicKeyTypeAgreement(Enum):
    X25519 = 0xEC


class PublicKeyTypeAuthentication(Enum):
    ED25519 = 0xED


PublicKeyType = Union[PublicKeyTypeAgreement, PublicKeyTypeAuthentication]


class EncodingType(Enum):
    BASE58 = 0


class VerificationMaterialFormat(Enum):
    JWK = 1
    BASE58 = 2
    MULTIBASE = 3

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
