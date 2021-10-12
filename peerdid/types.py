from enum import Enum
from typing import NamedTuple, Union


class VerificationMaterialFormatPeerDID(Enum):
    JWK = 1
    BASE58 = 2
    MULTIBASE = 3


class VerificationMethodTypeAgreement(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    X25519_KEY_AGREEMENT_KEY_2019 = "X25519KeyAgreementKey2019"
    X25519_KEY_AGREEMENT_KEY_2020 = "X25519KeyAgreementKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


class VerificationMethodTypeAuthentication(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    ED25519_VERIFICATION_KEY_2018 = "Ed25519VerificationKey2018"
    ED25519_VERIFICATION_KEY_2020 = "Ed25519VerificationKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


VerificationMethodTypePeerDID = Union[
    VerificationMethodTypeAgreement, VerificationMethodTypeAuthentication
]

VerificationMaterialAuthentication = NamedTuple(
    "VerificationMaterialAuthentication",
    [
        ("format", VerificationMaterialFormatPeerDID),
        ("type", VerificationMethodTypeAuthentication),
        ("value", Union[str, dict]),
    ],
)

VerificationMaterialAgreement = NamedTuple(
    "VerificationMaterialAgreement",
    [
        ("format", VerificationMaterialFormatPeerDID),
        ("type", VerificationMethodTypeAgreement),
        ("value", Union[str, dict]),
    ],
)


VerificationMaterialPeerDID = Union[
    VerificationMaterialAuthentication, VerificationMaterialAgreement
]

JSON = str
PEER_DID = str
