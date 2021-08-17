import base64
import hashlib
import json
import re
from typing import Union

import base58
import varint

from peerdid.types import JSON, PublicKeyAgreement, PublicKeyAuthentication, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication, PEER_DID


def _encode_service(service: JSON) -> str:
    """
    Generates encoded service according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param service: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: encoded service
    """
    service_to_encode = re.sub(r"[\n\t\s]*", "", service) \
        .replace("type", "t") \
        .replace("serviceEndpoint", "s") \
        .replace("didcommmessaging", 'dm') \
        .replace("routingKeys", 'r') \
        .encode('ascii')
    return '.S' + base64.b64encode(service_to_encode).decode("utf-8")


def _decode_service(service: str, peer_did: PEER_DID) -> dict:
    """
    Decodes service according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids)
    :param service: service to decode
    :param peer_did: peer_did which will be used as an ID
    :raises ValueError: if peer_did parameter is not valid
    :return: decoded service
    """
    from peerdid.peer_did import is_peer_did
    if not is_peer_did(peer_did):
        raise ValueError('Invalid peer_did')
    decoded_service = base64.b64decode(service)
    service_dict = json.loads(decoded_service)
    type = service_dict.pop('t').replace("dm", 'didcommmessaging')
    service_dict['id'] = peer_did + f'#{type}'
    service_dict['type'] = type
    service_dict['serviceEndpoint'] = service_dict.pop('s')
    service_dict['routingKeys'] = service_dict.pop('r')
    return service_dict


def _create_encnumbasis(key: Union[PublicKeyAgreement, PublicKeyAuthentication]) -> str:
    """
    Creates encnumbasis according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#method-specific-identifier)
    :param key: public key
    :return: encnumbasis
    """
    decoded_key = base58.b58decode(key.encoded_value)
    prefixed_decoded_key = _add_prefix(key.type, decoded_key)
    encnumbasis = base58.b58encode(prefixed_decoded_key)
    return encnumbasis.decode('utf-8')


def _decode_encnumbasis(encnumbasis: str, peer_did: PEER_DID) -> dict:
    """
    Decodes encnumbasis
    :param encnumbasis: encnumbasis to decode
    :param peer_did: peer_did which will be used as an ID
    :return: decoded encnumbasis
    """
    decoded_encnumbasis = base58.b58decode(encnumbasis)
    codec = _get_codec(data=bytes(decoded_encnumbasis))
    decoded_encnumbasis_without_prefix = _remove_prefix(decoded_encnumbasis)
    public_key = base58.b58encode(decoded_encnumbasis_without_prefix).decode('utf-8')
    return {'id': peer_did + '#' + encnumbasis, 'type': codec, 'controller': peer_did, 'publicKeyBase58': public_key}


def _remove_prefix(data: bytes) -> bytes:
    """
    Removes prefix from data
    :param data: prefixed data
    :return: data without prefix
    """
    prefix_int = _extract_prefix(data)
    prefix = varint.encode(prefix_int)
    return data[len(prefix):]


def _get_codec(data: bytes) -> str:
    """
    Gets codec from data
    :param data: prefixed data
    :raises ValueError: if prefix is not supported
    :return: codec name
    """
    prefix = _extract_prefix(data)
    if prefix in set(item.value for item in PublicKeyTypeAuthentication):
        return PublicKeyTypeAuthentication(prefix).name
    elif prefix in set(item.value for item in PublicKeyTypeAgreement):
        return PublicKeyTypeAgreement(prefix).name
    else:
        raise ValueError('Prefix {} not present in the lookup table'.format(prefix))


def _extract_prefix(data: bytes) -> int:
    """
    Extracts prefix from data
    :param data: prefixed data
    :raises ValueError: if invalid varint provided
    :return: prefix
    """
    try:
        return varint.decode_bytes(data)
    except TypeError:
        raise ValueError('incorrect varint provided')


def _add_prefix(key_type: Union[PublicKeyTypeAgreement, PublicKeyTypeAuthentication], data: bytes) -> bytes:
    """
    Adds prefix to a data
    :param key_type: type of key
    :param data: data to be prefixed
    :return: prefixed data
    """
    prefix = varint.encode(key_type.value)
    return b''.join([prefix, data])


def encode_filename(filename: str) -> str:
    """
    Encodes filename to SHA256 string
    :param filename: name of file
    :return: encoded filename as SHA256 string
    """
    return hashlib.sha256(filename.encode()).hexdigest()


def _build_did_doc_numalgo_0(peer_did: PEER_DID) -> dict:
    """
    Helper method to create did_doc according to numalgo 0
    :param peer_did: peer_did to resolve
    :raises ValueError: if peer_did contains encryption key instead of signing
    :return: did_doc
    """
    inception_key = peer_did[11:]
    decoded_encnumbasis = _decode_encnumbasis(inception_key, peer_did)
    if not decoded_encnumbasis['type'] in PublicKeyTypeAuthentication.__members__:
        raise ValueError('Invalid key type (encryption instead of signing)')
    did_doc = {
        'id': peer_did,
        'authentication': decoded_encnumbasis
    }
    return did_doc


def _build_did_doc_numalgo_2(peer_did: PEER_DID) -> dict:
    """
    Helper method to create did_doc according to numalgo 2
    :param peer_did: peer_did to resolve
    :return: did_doc
    """
    keys = peer_did[11:]
    keys = keys.split('.')
    services = []
    keys_without_purpose_code = []
    for key in keys:
        if key[0] != 'S':
            keys_without_purpose_code.append(key[2:])
        else:
            services.append(key[1:])
    decoded_encnumbasises = [_decode_encnumbasis(key, peer_did) for key in keys_without_purpose_code]
    decoded_services = [_decode_service(service, peer_did) for service in services]

    authentication = []
    key_agreement = []
    for i in range(len(decoded_encnumbasises)):
        if decoded_encnumbasises[i]['type'] in PublicKeyTypeAuthentication.__members__ and keys[i][0] == 'V':
            authentication.append(decoded_encnumbasises[i])
        elif decoded_encnumbasises[i]['type'] in PublicKeyTypeAgreement.__members__ and keys[i][0] == 'E':
            key_agreement.append(decoded_encnumbasises[i])
        else:
            raise ValueError(f'Invalid key type of: {keys[i]}')
    did_doc = {
        'id': peer_did,
        'authentication': authentication,
        'keyAgreement': key_agreement,
        'service': decoded_services
    }
    return did_doc


def _check_if_base58_encoded(key: str) -> bool:
    """
    Checks if key base58 encoded
    :param key: any string
    :return: true if key base58 encoded, otherwise false
    """
    base58_pattern = re.compile(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$")
    return bool(re.match(base58_pattern, key))
