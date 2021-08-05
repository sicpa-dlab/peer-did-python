from dataclasses import dataclass
from enum import Enum


class KeyType(Enum):
    ED25519 = 1
    X25519 = 2
    SECP256K1 = 3


@dataclass
class PublicKey:
    encoded_value: str
    type: KeyType


JSON = str
PEER_DID = str
