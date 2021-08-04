from enum import Enum, auto


class KeyTypes(Enum):
    CURVE25519 = auto()
    SECP256K1 = auto()


JSON = str
