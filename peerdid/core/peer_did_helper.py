"""Peer DID helper methods."""

import json

from enum import Enum
from typing import List, Optional, Union

from pydid import Service

from ..core.utils import urlsafe_b64encode, urlsafe_b64decode
from ..errors import MalformedPeerDIDError
from ..keys import KeyFormat, BaseKey

SERVICE_ID = "id"
SERVICE_TYPE = "type"
SERVICE_ENDPOINT = "serviceEndpoint"
SERVICE_DIDCOMM_MESSAGING = "DIDCommMessaging"
SERVICE_ROUTING_KEYS = "routingKeys"
SERVICE_ACCEPT = "accept"

ServiceJson = Union[str, dict, list]


class Numalgo2Prefix(Enum):
    """Numalgo prefix values."""

    AUTHENTICATION = "V"
    KEY_AGREEMENT = "E"
    SERVICE = "S"


class ServicePrefix(Enum):
    """Service short forms."""

    SERVICE_TYPE = "t"
    SERVICE_ENDPOINT = "s"
    SERVICE_DIDCOMM_MESSAGING = "dm"
    SERVICE_ROUTING_KEYS = "r"
    SERVICE_ACCEPT = "a"


def encode_service(service: ServiceJson) -> str:
    """
    Generate encoded service according to the second algorithm.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#generation-method>
    For this type of algorithm the DID Document can be obtained from the Peer DID.

    :param service: JSON conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
    :return: encoded service
    """
    if service is None or service == "" or service == []:
        return ""

    if isinstance(service, str):
        try:
            service = json.loads(service)
        except json.JSONDecodeError:
            pass

    if isinstance(service, list):
        service = list(map(_encode_service_entry, service))
    elif isinstance(service, dict):
        service = _encode_service_entry(service)
    else:
        raise ValueError("Service is not valid JSON")

    return (
        "."
        + Numalgo2Prefix.SERVICE.value
        + urlsafe_b64encode(json.dumps(service, separators=(",", ":"))).decode("utf-8")
    )


def _encode_service_entry(service: dict) -> dict:
    result = {}
    for k, v in service.items():
        if k == SERVICE_TYPE:
            k = ServicePrefix.SERVICE_TYPE.value
        elif k == SERVICE_ENDPOINT:
            k = ServicePrefix.SERVICE_ENDPOINT.value
        elif k == SERVICE_ROUTING_KEYS:
            k = ServicePrefix.SERVICE_ROUTING_KEYS.value
        elif k == SERVICE_ACCEPT:
            k = ServicePrefix.SERVICE_ACCEPT.value

        if v == SERVICE_DIDCOMM_MESSAGING:
            v = ServicePrefix.SERVICE_DIDCOMM_MESSAGING.value

        result[k] = v
    return result


def decode_service(service: str) -> Optional[List[Service]]:
    """
    Decode service according to Peer DID spec.

    Reference: https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids

    :param service: service to decode
    :param peer_did: peer_did which will be used as an ID
    :raises ValueError: if peer_did parameter is not valid
    :return: decoded service (list of dict)
    """
    if not service:
        return None
    try:
        decoded_service = urlsafe_b64decode(service.encode())
        list_of_service_dict = json.loads(decoded_service.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as e:
        raise MalformedPeerDIDError("Invalid service") from e

    if not isinstance(list_of_service_dict, list):
        list_of_service_dict = [list_of_service_dict]
    result = []

    for i, svc_def in enumerate(list_of_service_dict):
        if not isinstance(svc_def, dict):
            raise MalformedPeerDIDError("Service entry is not an object")
        service_type = svc_def.pop(ServicePrefix.SERVICE_TYPE.value, "").replace(
            ServicePrefix.SERVICE_DIDCOMM_MESSAGING.value, SERVICE_DIDCOMM_MESSAGING
        )
        if not service_type:
            raise MalformedPeerDIDError("Service doesn't contain a type")
        ident = "#" + service_type.lower() + "-" + str(i)
        endpoint = svc_def.pop(ServicePrefix.SERVICE_ENDPOINT.value, None)
        extra = {}
        for k, v in svc_def.items():
            if k == ServicePrefix.SERVICE_ACCEPT.value:
                k = SERVICE_ACCEPT
            elif k == ServicePrefix.SERVICE_ROUTING_KEYS.value:
                k = SERVICE_ROUTING_KEYS
            extra[k] = v
        service = Service.make(
            id=ident, type=service_type, service_endpoint=endpoint, **extra
        )
        result.append(service)

    return result


def decode_multibase_numbasis(
    multibase: str,
    key_format: KeyFormat,
) -> BaseKey:
    """
    Decode multibase-encoded numeric basis to a verification method for DID Document.

    :param multibase: multibase-encoded numeric basis to decode
    :param key_format: the format of public keys in the DID Document
    :return: decoded numeric basis as verification method for DID Document
    """
    try:
        return BaseKey.from_multibase(multibase, format=key_format)
    except (ValueError, TypeError) as e:
        raise MalformedPeerDIDError("Invalid key: {}".format(multibase)) from e
