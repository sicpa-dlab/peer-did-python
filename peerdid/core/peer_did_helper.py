import json
import re
from enum import Enum
from typing import List, Optional, NamedTuple

from peerdid.core.did_doc_types import (
    VerificationMethodTypeAgreement,
    VerificationMethodTypeAuthentication,
    SERVICE_DIDCOMM_MESSAGING,
    SERVICE_ENDPOINT,
    SERVICE_TYPE,
    SERVICE_ROUTING_KEYS,
    SERVICE_ACCEPT,
    SERVICE_ID,
    VerificationMethodPeerDID,
)
from peerdid.core.jwk_okp import jwk_key_to_bytes, public_key_to_jwk_dict
from peerdid.core.multibase import (
    from_base58_multibase,
    from_base58,
    to_base58_multibase,
    to_base58,
)
from peerdid.core.multicodec import to_multicodec, from_multicodec, Codec
from peerdid.core.utils import urlsafe_b64encode, urlsafe_b64decode
from peerdid.core.validation import validate_raw_key_length
from peerdid.types import (
    JSON,
    PEER_DID,
    VerificationMaterialPeerDID,
    VerificationMaterialFormatPeerDID,
    VerificationMaterialAgreement,
    VerificationMaterialAuthentication,
)


class Numalgo2Prefix(Enum):
    AUTHENTICATION = "V"
    KEY_AGREEMENT = "E"
    SERVICE = "S"


ServicePrefix = {
    SERVICE_TYPE: "t",
    SERVICE_ENDPOINT: "s",
    SERVICE_DIDCOMM_MESSAGING: "dm",
    SERVICE_ROUTING_KEYS: "r",
    SERVICE_ACCEPT: "a",
}


def encode_service(service: JSON) -> str:
    """
    Generates encoded service according to the second algorithm
    (https://identity.foundation/peer-did-method-spec/index.html#generation-method)
    For this type of algorithm did_doc can be obtained from peer_did
    :param service: JSON string conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: encoded service
    """
    service_to_encode = (
        re.sub(r"[\n\t\s]*", "", service)
        .replace(SERVICE_TYPE, ServicePrefix[SERVICE_TYPE])
        .replace(SERVICE_ENDPOINT, ServicePrefix[SERVICE_ENDPOINT])
        .replace(SERVICE_DIDCOMM_MESSAGING, ServicePrefix[SERVICE_DIDCOMM_MESSAGING])
        .replace(SERVICE_ROUTING_KEYS, ServicePrefix[SERVICE_ROUTING_KEYS])
        .replace(SERVICE_ACCEPT, ServicePrefix[SERVICE_ACCEPT])
        .encode("utf-8")
    )
    return (
        "."
        + Numalgo2Prefix.SERVICE.value
        + urlsafe_b64encode(service_to_encode).decode("utf-8")
    )


def decode_service(service: str, peer_did: PEER_DID) -> Optional[List[dict]]:
    """
    Decodes service according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids)
    :param service: service to decode
    :param peer_did: peer_did which will be used as an ID
    :raises ValueError: if peer_did parameter is not valid
    :return: decoded service (list of dict)
    """
    if not service:
        return None
    decoded_service = urlsafe_b64decode(service.encode())
    list_of_service_dict = json.loads(decoded_service.decode("utf-8"))

    if not isinstance(list_of_service_dict, list):
        list_of_service_dict = [list_of_service_dict]

    for i in range(len(list_of_service_dict)):
        service = list_of_service_dict[i]
        if ServicePrefix[SERVICE_TYPE] not in service:
            raise ValueError("service doesn't contain a type")
        service_type = service.pop(ServicePrefix[SERVICE_TYPE]).replace(
            ServicePrefix[SERVICE_DIDCOMM_MESSAGING], SERVICE_DIDCOMM_MESSAGING
        )
        service[SERVICE_ID] = peer_did + "#" + service_type.lower() + "-" + str(i)
        service[SERVICE_TYPE] = service_type
        if ServicePrefix[SERVICE_ENDPOINT] in service:
            service[SERVICE_ENDPOINT] = service.pop(ServicePrefix[SERVICE_ENDPOINT])
        if ServicePrefix[SERVICE_ROUTING_KEYS] in service:
            service[SERVICE_ROUTING_KEYS] = service.pop(
                ServicePrefix[SERVICE_ROUTING_KEYS]
            )
        if ServicePrefix[SERVICE_ACCEPT] in service:
            service[SERVICE_ACCEPT] = service.pop(ServicePrefix[SERVICE_ACCEPT])

    return list_of_service_dict


def create_multibase_encnumbasis(key: VerificationMaterialPeerDID) -> str:
    """
    Creates multibased encnumbasis according to Peer DID spec
    (https://identity.foundation/peer-did-method-spec/index.html#method-specific-identifier)
    :param key: public key
    :return: transform+encnumbasis
    """
    if key.format == VerificationMaterialFormatPeerDID.BASE58:
        decoded_key = from_base58(key.value)
    elif key.format == VerificationMaterialFormatPeerDID.MULTIBASE:
        decoded_key = from_multicodec(from_base58_multibase(key.value)[1])[0]
    elif key.format == VerificationMaterialFormatPeerDID.JWK:
        decoded_key = jwk_key_to_bytes(key)
    else:
        raise ValueError("Unknown key format " + key.format)
    validate_raw_key_length(decoded_key)
    return to_base58_multibase(to_multicodec(decoded_key, key.type))


DecodedEncnumbasis = NamedTuple(
    "DecodedEncnumbasis",
    [
        ("encnumbasis", str),
        ("ver_material", VerificationMaterialPeerDID),
    ],
)


def decode_multibase_encnumbasis(
    multibase: str,
    ver_material_format: VerificationMaterialFormatPeerDID,
) -> DecodedEncnumbasis:
    """
    Decodes multibased encnumbasis to a verification material for DID DOC
    :param multibase: transform+encnumbasis to decode
    :param ver_material_format: the format of public keys in the DID DOC
    :return: decoded encnumbasis as verification method for DID DOC
    """
    encnumbasis, decoded_encnumbasis = from_base58_multibase(multibase)
    decoded_encnumbasis_without_prefix, codec = from_multicodec(decoded_encnumbasis)
    validate_raw_key_length(decoded_encnumbasis_without_prefix)

    ver_material_cls = (
        VerificationMaterialAgreement
        if codec == Codec.X25519
        else VerificationMaterialAuthentication
    )
    if ver_material_format == VerificationMaterialFormatPeerDID.BASE58:
        ver_material = ver_material_cls(
            format=ver_material_format,
            type=__get_2018_2019_ver_material_type(codec),
            value=to_base58(decoded_encnumbasis_without_prefix),
        )
    elif ver_material_format == VerificationMaterialFormatPeerDID.MULTIBASE:
        ver_material = ver_material_cls(
            format=ver_material_format,
            type=__get_2020_ver_material_type(codec),
            value=to_base58_multibase(
                to_multicodec(
                    decoded_encnumbasis_without_prefix,
                    __get_2020_ver_material_type(codec),
                ),
            ),
        )
    elif ver_material_format == VerificationMaterialFormatPeerDID.JWK:
        ver_material_type = __get_jwk_ver_material_type(codec)
        ver_material = ver_material_cls(
            format=ver_material_format,
            type=ver_material_type,
            value=public_key_to_jwk_dict(
                decoded_encnumbasis_without_prefix, ver_material_type
            ),
        )
    else:
        raise ValueError("Unknown format {}".format(ver_material_format))

    return DecodedEncnumbasis(encnumbasis=encnumbasis, ver_material=ver_material)


def get_verification_method(
    did: PEER_DID, decoded_encnumbasis: DecodedEncnumbasis
) -> VerificationMethodPeerDID:
    return VerificationMethodPeerDID(
        id=did + "#" + decoded_encnumbasis.encnumbasis,
        controller=did,
        ver_material=decoded_encnumbasis.ver_material,
    )


def __get_2018_2019_ver_material_type(codec: Codec):
    if codec == Codec.X25519:
        return VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019
    elif codec == Codec.ED25519:
        return VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018
    raise ValueError("Unknown multicodec {}".format(codec.value))


def __get_2020_ver_material_type(codec: Codec):
    if codec == Codec.X25519:
        return VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020
    elif codec == Codec.ED25519:
        return VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020
    raise ValueError("Unknown multicodec {}".format(codec.value))


def __get_jwk_ver_material_type(codec: Codec):
    if codec == Codec.X25519:
        return VerificationMethodTypeAgreement.JSON_WEB_KEY_2020
    elif codec == Codec.ED25519:
        return VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
    raise ValueError("Unknown multicodec {}".format(codec.value))
