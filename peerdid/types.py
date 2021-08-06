from dataclasses import dataclass
from enum import Enum


class KeyTypeAgreement(Enum):
    X25519 = 1
    SECP256K1 = 2


class KeyTypeAuthentication(Enum):
    ED25519 = 1
    SECP256K1 = 2


@dataclass
class PublicKeyAgreement:
    encoded_value: str
    type: KeyTypeAgreement


@dataclass
class PublicKeyAuthentication:
    encoded_value: str
    type: KeyTypeAuthentication


JSON = str
PEER_DID = str
