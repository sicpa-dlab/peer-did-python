from dataclasses import dataclass
from enum import Enum


class PublicKeyTypeAgreement(Enum):
    X25519 = 0xec


class PublicKeyTypeAuthentication(Enum):
    ED25519 = 0xed
    SECP256K1 = 0xe7


@dataclass
class PublicKeyAgreement:
    encoded_value: str
    type: PublicKeyTypeAgreement


@dataclass
class PublicKeyAuthentication:
    encoded_value: str
    type: PublicKeyTypeAuthentication


JSON = str
PEER_DID = str
