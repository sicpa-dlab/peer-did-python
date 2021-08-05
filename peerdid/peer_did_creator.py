import re
from typing import List
from .types import PEER_DID, PublicKey


def is_peer_did(peer_did: PEER_DID) -> bool:
    peer_did_pattern = re.compile(r'^did:peer:[01](z)([1-9a-km-zA-HJ-NP-Z]{46,47})$')
    return bool(re.match(peer_did_pattern, peer_did))


def create_peer_did_numalgo_0(inception_key: PublicKey) -> PEER_DID:
    pass


def create_peer_did_numalgo_2(encryption_keys: List[PublicKey], signing_keys: List[PublicKey],
                              service_endpoint: str) -> PEER_DID:
    pass
