import base64
import hashlib
import re
import json
from typing import Union, List

import base58
import varint

from peerdid.types import (
    JSON,
    PublicKeyAgreement,
    PublicKeyAuthentication,
    PublicKeyTypeAgreement,
    PublicKeyTypeAuthentication,
    PEER_DID,
    EncodingType,
)


def _encode_service(service: JSON) -> str:
    """
    Generates encoded service according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param service: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: encoded service
    """
    service_to_encode = (
        re.sub(r"[\n\t\s]*", "", service)
        .replace("'", '"')
        .replace("type", "t")
        .replace("serviceEndpoint", "s")
        .replace("didcommmessaging", "dm")
        .replace("routingKeys", "r")
        .encode("ascii")
    )
    return ".S" + base64.b64encode(service_to_encode).decode("utf-8")


def _decode_service(service: str, peer_did: PEER_DID) -> List[dict]:
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
        raise ValueError("Invalid peer_did")
    decoded_service = base64.b64decode(service)
    list_of_service_dict = json.loads(decoded_service.decode("utf-8"))
    if not isinstance(list_of_service_dict, list):
        list_of_service_dict = [list_of_service_dict]
    for service in list_of_service_dict:
        service_type = service.pop("t").replace("dm", "didcommmessaging")
        service["id"] = peer_did + "#" + service_type
        service["type"] = service_type
        service["serviceEndpoint"] = service.pop("s")
        service["routingKeys"] = service.pop("r")
    return list_of_service_dict


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
    return encnumbasis.decode("utf-8")


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
    public_key = base58.b58encode(decoded_encnumbasis_without_prefix).decode("utf-8")
    return {
        "id": peer_did + "#" + encnumbasis,
        "type": codec,
        "controller": peer_did,
        "publicKeyBase58": public_key,
    }


def _remove_prefix(data: bytes) -> bytes:
    """
    Removes prefix from data
    :param data: prefixed data
    :return: data without prefix
    """
    prefix_int = _extract_prefix(data)
    prefix = varint.encode(prefix_int)
    return data[len(prefix) :]


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
        raise ValueError("Prefix {} not present in the lookup table".format(prefix))


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
        raise ValueError("incorrect varint provided")


def _add_prefix(
    key_type: Union[PublicKeyTypeAgreement, PublicKeyTypeAuthentication], data: bytes
) -> bytes:
    """
    Adds prefix to a data
    :param key_type: type of key
    :param data: data to be prefixed
    :return: prefixed data
    """
    prefix = varint.encode(key_type.value)
    return b"".join([prefix, data])


def _encode_filename(filename: str) -> str:
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
    :raises ValueError:
        1) if peer_did contains encryption key instead of signing
        2) if peer_did contains unsupported transform part
    :return: did_doc
    """
    inception_key = peer_did[11:]
    encoding_algorithm = peer_did[10]
    if not encoding_algorithm == "z":
        raise ValueError("Unsupported encoding algorithm of key: " + encoding_algorithm)
    decoded_encnumbasis = _decode_encnumbasis(inception_key, peer_did)
    if not decoded_encnumbasis["type"] in PublicKeyTypeAuthentication.__members__:
        raise ValueError("Invalid key type (encryption instead of signing)")
    did_doc = {"id": peer_did, "authentication": decoded_encnumbasis}
    return did_doc


def _build_did_doc_numalgo_2(peer_did: PEER_DID) -> dict:
    """
    Helper method to create did_doc according to numalgo 2
    :param peer_did: peer_did to resolve
    :return: did_doc
    """
    keys = peer_did[11:]
    keys = keys.split(".")
    service = ""
    keys_without_purpose_code = []
    for key in keys:
        if key[0] != "S":
            transform = key[1]
            if not transform == "z":
                raise ValueError("Unsupported transform part of peer_did: " + transform)
            keys_without_purpose_code.append(key[2:])
        else:
            service = key[1:]
    decoded_encnumbasises = [
        _decode_encnumbasis(key, peer_did) for key in keys_without_purpose_code
    ]
    decoded_service = _decode_service(service, peer_did)

    authentication = []
    key_agreement = []
    for i in range(len(decoded_encnumbasises)):
        if (
            decoded_encnumbasises[i]["type"] in PublicKeyTypeAuthentication.__members__
            and keys[i][0] == "V"
        ):
            authentication.append(decoded_encnumbasises[i])
        elif (
            decoded_encnumbasises[i]["type"] in PublicKeyTypeAgreement.__members__
            and keys[i][0] == "E"
        ):
            key_agreement.append(decoded_encnumbasises[i])
        else:
            raise ValueError("Invalid key type of: " + keys[i])
    did_doc = {
        "id": peer_did,
        "authentication": authentication,
        "keyAgreement": key_agreement,
        "service": decoded_service,
    }
    return did_doc


def _check_key_correctly_encoded(key: str, encoding_type: EncodingType) -> bool:
    """
    Checks if key correctly encoded
    :param key: any string
    :param encoding_type: encoding type
    :return: true if key correctly encoded, otherwise false
    """
    if not encoding_type == EncodingType.BASE58:
        return False
    alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    byte_lengths = (32,)
    invalid_chars = set(key) - alphabet
    if invalid_chars:
        return False
    b58len = len(base58.b58decode(key))
    if b58len not in byte_lengths:
        return False
    return True


def _is_json(str_to_check: str) -> bool:
    """
    Checks if str is JSON
    :param str_to_check: sting to check
    :return: true if str is JSON, otherwise raises ValueError or TypeError
    :raises TypeError: if str_to_check is not str type
    :raises ValueError: if str_to_check is not valid JSON
    """
    json.loads(str_to_check)
    return True
