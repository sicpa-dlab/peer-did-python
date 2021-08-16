import base64
import hashlib
import json
import re
import base58
import varint

from typing import Union

from peerdid.types import JSON, PublicKeyAgreement, PublicKeyAuthentication, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication, PEER_DID


def encode_service(service: JSON) -> str:
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


def decode_service(service: str, peer_did: PEER_DID) -> dict:
    """
    Decodes service according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids)
    :param service: service to decode
    :param peer_did: peer_did which will be used as an ID
    :return: decoded service
    """
    decoded_service = base64.b64decode(service)
    service_dict = json.loads(decoded_service)
    service_dict.pop('t')
    service_dict['id'] = peer_did + '#didcommmessaging'
    service_dict['type'] = 'didcommmessaging'
    service_dict['serviceEndpoint'] = service_dict.pop('s')
    service_dict['routingKeys'] = service_dict.pop('r')
    return service_dict


def create_encnumbasis(key: Union[PublicKeyAgreement, PublicKeyAuthentication]) -> str:
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


def decode_encnumbasis(encnumbasis: str, peer_did: PEER_DID) -> dict:
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
    try:
        if prefix in set(item.value for item in PublicKeyTypeAuthentication):
            return PublicKeyTypeAuthentication(prefix).name
        elif prefix in set(item.value for item in PublicKeyTypeAgreement):
            return PublicKeyTypeAgreement(prefix).name
    except KeyError:
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
    Encodes filename to SHA-1 string
    :param filename: name of file
    :return: encoded filename as SHA-1 string
    """
    return hashlib.sha1(filename.encode()).hexdigest()
