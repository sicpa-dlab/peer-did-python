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


class VerificationMaterialTypeAgreement(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    X25519_KEY_AGREEMENT_KEY_2019 = "X25519KeyAgreementKey2019"

    @staticmethod
    def values():
        return [e.value for e in VerificationMaterialTypeAgreement]


class VerificationMaterialTypeAuthentication(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    ED25519_VERIFICATION_KEY_2018 = "Ed25519VerificationKey2018"
    ED25519_VERIFICATION_KEY_2020 = "Ed25519VerificationKey2020"

    @staticmethod
    def values():
        return [e.value for e in VerificationMaterialTypeAuthentication]


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
