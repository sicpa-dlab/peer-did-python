import re
from typing import List, Optional

from peerdid.storage import Storage, FileStorage
from peerdid.types import PEER_DID, PublicKeyAgreement, PublicKeyAuthentication, JSON


def is_peer_did(peer_did: PEER_DID) -> bool:
    """
    Checks if peer_did parameter matches Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#matching-regex)
    :param peer_did: peer_did to check
    :return: true if peer_did matches spec, otherwise false
    """
    if peer_did is None:
        return False
    peer_did_pattern = re.compile(r'^did:peer:[01](z)([1-9a-km-zA-HJ-NP-Z]{46,47})$')
    return bool(re.match(peer_did_pattern, peer_did))


def create_peer_did_numalgo_0(inception_key: PublicKeyAgreement) -> PEER_DID:
    """
    Generates peer_did according to the zero algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param inception_key: the key that creates the DID and authenticates when exchanging it with the first peer
    :return: generated peer_did
    """
    pass


def create_peer_did_numalgo_2(encryption_keys: List[PublicKeyAgreement], signing_keys: List[PublicKeyAuthentication],
                              service_endpoint: str) -> PEER_DID:
    """
    Generates peer_did according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param encryption_keys: list of encryption keys
    :param signing_keys: list of signing keys
    :param service_endpoint: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: generated peer_did
    """
    pass


def resolve_peer_did(peer_did: PEER_DID, version_id=None) -> JSON:
    """
    Resolves did_doc from peer_did
    :param peer_did: peer_did to resolve
    :param version_id: a specific version of a DID doc. If value is default, version of DID doc will be latest.
    version_id is not used for now, as we support only static layer where did doc never changes
    :return: resolved did_doc as a JSON string
    """
    pass


def save_peer_did(peer_did: PEER_DID, storage: Optional[Storage] = None):
    """
    Saves peer_did to a storage (FileStorage by default)
    :param peer_did: peer_did to save
    :param storage: repository responsible for peer_did saving
    :raise ValueError: raises if peer_did parameter does not match peer_did spec
    """
    if is_peer_did(peer_did=peer_did):
        storage = storage or FileStorage()
        storage.save(data=peer_did.encode())
    else:
        raise ValueError("Wrong Peer DID")
