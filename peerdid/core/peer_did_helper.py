import hashlib
import json
import re
from enum import Enum
from typing import Union, List, Optional

import base58
import varint

from peerdid.core.did_doc import (
    VerificationMaterial,
    PublicKeyField,
    VerificationMaterialTypeAgreement,
    VerificationMaterialTypeAuthentication,
    JWK_OKP,
)
from peerdid.core.utils import _urlsafe_b64encode, _urlsafe_b64decode
from peerdid.types import (
    JSON,
    PublicKeyAgreement,
    PublicKeyAuthentication,
    PublicKeyTypeAgreement,
    PublicKeyTypeAuthentication,
    PEER_DID,
    EncodingType,
    DIDDocVerMaterialFormat,
)


class Numalgo2Prefix(Enum):
    AUTHENTICATION = "V"
    KEY_AGREEMENT = "E"
    SERVICE = "S"


class MultibasePrefix(Enum):
    BASE58 = "z"


PublicKeyType = Union[PublicKeyTypeAgreement, PublicKeyTypeAuthentication]


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
        .replace("type", "t")
        .replace("serviceEndpoint", "s")
        .replace("DIDCommMessaging", "dm")
        .replace("routingKeys", "r")
        .replace("accept", "a")
        .encode("utf-8")
    )
    return (
        "."
        + Numalgo2Prefix.SERVICE.value
        + _urlsafe_b64encode(service_to_encode).decode("utf-8")
    )


def _decode_service(service: str, peer_did: PEER_DID) -> Optional[List[dict]]:
    """
    Decodes service according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids)
    :param service: service to decode
    :param peer_did: peer_did which will be used as an ID
    :raises ValueError: if peer_did parameter is not valid
    :return: decoded service
    """
    if not service:
        return None
    decoded_service = _urlsafe_b64decode(service.encode())
    list_of_service_dict = json.loads(decoded_service.decode("utf-8"))
    if not isinstance(list_of_service_dict, list):
        list_of_service_dict = [list_of_service_dict]

    for i in range(len(list_of_service_dict)):
        service = list_of_service_dict[i]
        if "t" not in service:
            raise ValueError("service doesn't contain a type")
        service_type = service.pop("t").replace("dm", "DIDCommMessaging")
        service["id"] = peer_did + "#" + service_type.lower() + "-" + str(i)
        service["type"] = service_type
        if "s" in service:
            service["serviceEndpoint"] = service.pop("s")
        if "r" in service:
            service["routingKeys"] = service.pop("r")
        if "a" in service:
            service["accept"] = service.pop("a")
    return list_of_service_dict


def _create_multibase_encnumbasis(
    key: Union[PublicKeyAgreement, PublicKeyAuthentication]
) -> str:
    """
    Creates multibased encnumbasis according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#method-specific-identifier)
    :param key: public key
    :return: transform+encnumbasis
    """
    decoded_key = base58.b58decode(key.encoded_value)
    return _to_base58_multibase(_add_prefix(key.type, decoded_key))


def _decode_multibase_encnumbasis(
    multibase: str,
    ver_material_format: DIDDocVerMaterialFormat,
) -> VerificationMaterial:
    """
    Decodes multibased encnumbasis to a verification material for DID DOC
    :param multibase: transform+encnumbasis to decode
    :param ver_material_format: the format of public keys in the DID DOC
    :return: decoded encnumbasis as verification material for DID DOC
    """
    transform = multibase[0]
    if not transform == MultibasePrefix.BASE58.value:
        raise ValueError("Unsupported transform part of peer_did: " + transform)
    encnumbasis = multibase[1:]
    decoded_encnumbasis = base58.b58decode(encnumbasis)
    decoded_encnumbasis_without_prefix = _remove_prefix(decoded_encnumbasis)

    if ver_material_format == DIDDocVerMaterialFormat.BASE58:
        return VerificationMaterial(
            field=PublicKeyField.BASE58,
            type=__get_2018_2019_ver_material_type(decoded_encnumbasis),
            value=base58.b58encode(decoded_encnumbasis_without_prefix).decode("utf-8"),
            encnumbasis=encnumbasis,
        )

    if ver_material_format == DIDDocVerMaterialFormat.MULTIBASE:
        return VerificationMaterial(
            field=PublicKeyField.MULTIBASE,
            type=__get_2020_ver_material_type(decoded_encnumbasis),
            value=_to_base58_multibase(decoded_encnumbasis_without_prefix),
            encnumbasis=encnumbasis,
        )

    if ver_material_format == DIDDocVerMaterialFormat.JWK:
        ver_material_type = __get_jwk_ver_material_type(decoded_encnumbasis)
        return VerificationMaterial(
            field=PublicKeyField.JWK,
            type=ver_material_type,
            value=JWK_OKP(
                ver_material_type, decoded_encnumbasis_without_prefix
            ).to_dict(),
            encnumbasis=encnumbasis,
        )
    raise ValueError("Unknown format {}".format(ver_material_format))


def __get_2018_2019_ver_material_type(decoded_encnumbasis):
    public_key_type = __get_public_key_type(decoded_encnumbasis)
    if public_key_type == PublicKeyTypeAgreement.X25519:
        return VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019
    elif public_key_type == PublicKeyTypeAuthentication.ED25519:
        return VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2018
    raise ValueError("Unknown public key type {}".format(public_key_type))


def __get_2020_ver_material_type(decoded_encnumbasis):
    public_key_type = __get_public_key_type(decoded_encnumbasis)
    if public_key_type == PublicKeyTypeAgreement.X25519:
        return VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020
    elif public_key_type == PublicKeyTypeAuthentication.ED25519:
        return VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2020
    raise ValueError("Unknown public key type {}".format(public_key_type))


def __get_jwk_ver_material_type(decoded_encnumbasis):
    public_key_type = __get_public_key_type(decoded_encnumbasis)
    if public_key_type == PublicKeyTypeAgreement.X25519:
        return VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020
    elif public_key_type == PublicKeyTypeAuthentication.ED25519:
        return VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020
    raise ValueError("Unknown public key type {}".format(type))


def __get_public_key_type(data: bytes) -> PublicKeyType:
    prefix = _extract_prefix(data)
    if prefix in set(item.value for item in PublicKeyTypeAuthentication):
        return PublicKeyTypeAuthentication(prefix)
    elif prefix in set(item.value for item in PublicKeyTypeAgreement):
        return PublicKeyTypeAgreement(prefix)
    else:
        raise ValueError("Prefix {} not present in the lookup table".format(prefix))


def _remove_prefix(data: bytes) -> bytes:
    """
    Removes prefix from data
    :param data: prefixed data
    :return: data without prefix
    """
    prefix_int = _extract_prefix(data)
    prefix = varint.encode(prefix_int)
    return data[len(prefix) :]


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


def _to_base58_multibase(value: bytes) -> str:
    return MultibasePrefix.BASE58.value + base58.b58encode(value).decode("utf-8")


def _encode_filename(filename: str) -> str:
    """
    Encodes filename to SHA256 string
    :param filename: name of file
    :return: encoded filename as SHA256 string
    """
    return hashlib.sha256(filename.encode()).hexdigest()


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
