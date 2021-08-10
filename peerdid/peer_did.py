import re
from typing import List, Optional

from peerdid.storage import Storage, FileStorage
from peerdid.types import PEER_DID, PublicKeyAgreement, PublicKeyAuthentication, JSON
import base64


def is_peer_did(peer_did: PEER_DID) -> bool:
    """
    Checks if peer_did parameter matches Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#matching-regex)
    :param peer_did: peer_did to check
    :return: true if peer_did matches spec, otherwise false
    """
    if peer_did is None:
        return False
    peer_did_pattern = re \
        .compile(r"^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))|(2(\.[AEVIDS][0-9a-zA-Z=]+)+))$")
    # TODO: METHOD 2:
    #  1) this regex will work even if AEVIDS methods run out.
    #  2) Key length is {46, 47} (in case of 2 keys we will have length 92 or 94 etc), but this regex
    #  will work at any length
    return bool(re.match(peer_did_pattern, peer_did))


def create_peer_did_numalgo_0(inception_key: PublicKeyAuthentication) -> PEER_DID:
    """
    Generates peer_did according to the zero algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param inception_key: the key that creates the DID and authenticates when exchanging it with the first peer
    :return: generated peer_did
    """
    peer_did = 'did:peer:0z' + inception_key.encoded_value
    if is_peer_did(peer_did):
        return peer_did
    else:
        raise ValueError("Wrong Peer DID")


def create_peer_did_numalgo_2(encryption_keys: List[PublicKeyAgreement], signing_keys: List[PublicKeyAuthentication],
                              service: JSON) -> PEER_DID:
    """
    Generates peer_did according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param encryption_keys: list of encryption keys
    :param signing_keys: list of signing keys
    :param service: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: generated peer_did
    """
    encryption_keys_str = '.E' + ''.join(key.encoded_value for key in encryption_keys)
    signing_keys_str = '.V' + ''.join(key.encoded_value for key in signing_keys)
    service = '.S' + encode_service(service)

    peer_did = 'did:peer:2' + encryption_keys_str + signing_keys_str + service
    if is_peer_did(peer_did):
        return peer_did
    else:
        raise ValueError("Wrong Peer DID")


def encode_service(service: JSON) -> str:
    service_to_encode = re.sub(r"[\n\t\s]*", "", service) \
        .replace("type", "t") \
        .replace("serviceEndpoint", "s") \
        .replace("didcommmessaging", 'dm') \
        .replace("routingKeys", 'r') \
        .encode('ascii')
    return base64.b64encode(service_to_encode).decode("utf-8")


def resolve_peer_did(peer_did: PEER_DID, version_id=None) -> JSON:
    """
    Resolves did_doc from peer_did
    :param peer_did: peer_did to resolve
    :param version_id: a specific version of a DID doc. If value is default, version of DID doc will be latest.
    version_id is not used for now, as we support only static layer where did doc never changes
    :return: resolved did_doc as a JSON string
    """
    if is_peer_did(peer_did):
        if peer_did[9] == '0':
            inception_key = peer_did[9:]
            pass
        if peer_did[9] == '2':
            pass
    else:
        raise ValueError('Wrong Peer DID')


def save_peer_did(peer_did: PEER_DID, storage: Optional[Storage] = None):
    """
    Saves peer_did to a storage (FileStorage by default)
    :param peer_did: peer_did to save
    :param storage: repository responsible for peer_did saving
    :raise ValueError: raises if peer_did parameter does not match peer_did spec
    """
    if is_peer_did(peer_did=peer_did):
        storage = storage or FileStorage(peer_did_filename='new peerDID')
        storage.save(data=peer_did.encode())
    else:
        raise ValueError("Wrong Peer DID")
