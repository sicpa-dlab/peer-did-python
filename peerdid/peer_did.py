import json
import re
from typing import List

from peerdid.peer_did_utils import _encode_service, _create_encnumbasis, \
    _build_did_doc_numalgo_0, _build_did_doc_numalgo_2, _check_key_encoding
from peerdid.types import PEER_DID, PublicKeyAgreement, PublicKeyAuthentication, JSON


def is_peer_did(peer_did: PEER_DID) -> bool:
    """
    Checks if peer_did parameter matches Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#matching-regex)
    :param peer_did: peer_did to check
    :return: True if peer_did matches spec, otherwise False
    """
    if peer_did is None:
        return False
    peer_did_pattern = re.compile(
        r"^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+"
        r"(\.(S)[0-9a-zA-Z=].*)*)))$")
    return bool(re.match(peer_did_pattern, peer_did))


def create_peer_did_numalgo_0(inception_key: PublicKeyAuthentication) -> PEER_DID:
    """
    Generates peer_did according to the zero algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param inception_key: the key that creates the DID and authenticates when exchanging it with the first peer
    :raises TypeError: if the inception_key is not instance of PublicKeyAuthentication
    :raises ValueError: if the inception_key is not instance correctly encoded
    :return: generated peer_did
    """
    if not isinstance(inception_key, PublicKeyAuthentication):
        raise TypeError(f"Wrong type of inception_key: {str(type(inception_key))}. Expected: PublicKeyAuthentication")
    if not _check_key_encoding(inception_key.encoded_value, inception_key.encoding_type):
        raise ValueError(f"Inception key is not correctly encoded")
    peer_did = 'did:peer:0z' + _create_encnumbasis(inception_key)
    return peer_did


def create_peer_did_numalgo_2(encryption_keys: List[PublicKeyAgreement], signing_keys: List[PublicKeyAuthentication],
                              services: JSON) -> PEER_DID:
    """
    Generates peer_did according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param encryption_keys: list of encryption keys
    :param signing_keys: list of signing keys
    :param services: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :raises TypeError:If at least one of encryption keys is not instance of PublicKeyAgreement
        or at least one of signing keys is not instance of PublicKeyAuthentication
    :raises ValueError: if at least one of keys is not properly encoded
    :return: generated peer_did
    """
    for key in encryption_keys:
        if not isinstance(key, PublicKeyAgreement):
            raise TypeError(f'Wrong type of encryption_key {key}: {str(type(key))}')
        if not _check_key_encoding(key.encoded_value, key.encoding_type):
            raise ValueError(f"Encryption key: {key} is not correctly encoded")
    for key in signing_keys:
        if not isinstance(key, PublicKeyAuthentication):
            raise TypeError(f'Wrong type of signing_key {key}: {str(type(key))}')
        if not _check_key_encoding(key.encoded_value, key.encoding_type):
            raise ValueError(f"Signing key: {key} is not correctly encoded")
    services = json.loads(services)
    encryption_keys_str = ''
    if encryption_keys:
        encryption_keys_str = '.Ez' + '.Ez'.join(_create_encnumbasis(key) for key in encryption_keys)
    signing_keys_str = ''
    if signing_keys:
        signing_keys_str = '.Vz' + '.Vz'.join(_create_encnumbasis(key) for key in signing_keys)
    services_str = ''
    if services:
        services_str = _encode_service(str(services))

    peer_did = 'did:peer:2' + encryption_keys_str + signing_keys_str + services_str
    return peer_did


def resolve_peer_did(peer_did: PEER_DID, version_id=None) -> JSON:
    """
    Resolves did_doc from peer_did
    :param peer_did: peer_did to resolve
    :param version_id: a specific version of a DID doc. If value is default, version of DID doc will be latest.
    version_id is not used for now, as we support only static layer where did doc never changes
    :raises ValueError: if peer_did parameter does not match peer_did spec
    :return: resolved did_doc as a JSON string
    """
    if not is_peer_did(peer_did):
        raise ValueError('Invalid Peer DID')
    if peer_did[9] == '0':
        return json.dumps(_build_did_doc_numalgo_0(peer_did=peer_did), indent=4)
    if peer_did[9] == '2':
        return json.dumps(_build_did_doc_numalgo_2(peer_did=peer_did), indent=4)
