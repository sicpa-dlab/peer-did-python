import json
import re
from typing import List, Optional

from peerdid.peer_did_utils import encode_service, create_encnumbasis, encode_filename, decode_encnumbasis, \
    decode_service
from peerdid.storage import Storage, FileStorage
from peerdid.types import PEER_DID, PublicKeyAgreement, PublicKeyAuthentication, JSON, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication


def is_peer_did(peer_did: PEER_DID) -> bool:
    """
    Checks if peer_did parameter matches Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#matching-regex)
    :param peer_did: peer_did to check
    :return: true if peer_did matches spec, otherwise false
    """
    if peer_did is None:
        return False
    peer_did_pattern = re.compile(
        r"^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+"
        r"(\.(S)[0-9a-zA-Z=].*)+)))$")
    return bool(re.match(peer_did_pattern, peer_did))


def create_peer_did_numalgo_0(inception_key: PublicKeyAuthentication) -> PEER_DID:
    """
    Generates peer_did according to the zero algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param inception_key: the key that creates the DID and authenticates when exchanging it with the first peer
    :raises ValueError: raises if the resulting peer_did does not match peer_did spec
    :return: generated peer_did
    """
    peer_did = 'did:peer:0z' + create_encnumbasis(inception_key)
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
    :raises ValueError: raises if the resulting peer_did does not match peer_did spec
    :return: generated peer_did
    """
    encryption_keys_str = '.Ez' + '.Ez'.join(create_encnumbasis(key) for key in encryption_keys)
    signing_keys_str = '.Vz' + '.Vz'.join(create_encnumbasis(key) for key in signing_keys)
    service = encode_service(service)

    peer_did = 'did:peer:2' + encryption_keys_str + signing_keys_str + service
    if is_peer_did(peer_did):
        return peer_did
    else:
        raise ValueError("Wrong Peer DID")


def resolve_peer_did(peer_did: PEER_DID, version_id=None) -> JSON:
    """
    Resolves did_doc from peer_did
    :param peer_did: peer_did to resolve
    :param version_id: a specific version of a DID doc. If value is default, version of DID doc will be latest.
    version_id is not used for now, as we support only static layer where did doc never changes
    :raises ValueError: raises if peer_did parameter does not match peer_did spec
    :return: resolved did_doc as a JSON string
    """
    if not is_peer_did(peer_did):
        raise ValueError('Wrong Peer DID')
    if peer_did[9] == '0':
        inception_key = peer_did[11:]
        decoded_encnumbasis = decode_encnumbasis(inception_key, peer_did)
        did_doc = {
            'id': peer_did,
            'authentication': decoded_encnumbasis
        }
        return json.dumps(did_doc, indent=4)
    if peer_did[9] == '2':
        keys = peer_did[11:]
        keys = keys.split('.')
        services = []
        keys_without_purpose_code = []
        for key in keys:
            if key[0] != 'S':
                keys_without_purpose_code.append(key[2:])
            else:
                services.append(key[1:])
        decoded_encnumbasises = [decode_encnumbasis(key, peer_did) for key in keys_without_purpose_code]
        decoded_service = [decode_service(service, peer_did) for service in services]
        did_doc = {
            'id': peer_did,
            'authentication': [encnumbasis for encnumbasis in decoded_encnumbasises if
                               encnumbasis['type'] in PublicKeyTypeAuthentication.__members__],
            'keyAgreement': [encnumbasis for encnumbasis in decoded_encnumbasises if
                             encnumbasis['type'] in PublicKeyTypeAgreement.__members__],
            'service': decoded_service
        }
        return json.dumps(did_doc, indent=4)


def save_peer_did(peer_did: PEER_DID, storage: Optional[Storage] = None):
    """
    Saves peer_did to a storage (FileStorage by default)
    :param peer_did: peer_did to save
    :param storage: repository responsible for peer_did saving
    :raises ValueError: raises if peer_did parameter does not match peer_did spec
    """
    if is_peer_did(peer_did=peer_did):
        storage = storage or FileStorage(peer_did_filename=encode_filename(peer_did))
        storage.save(data=peer_did.encode())
    else:
        raise ValueError("Wrong Peer DID")
