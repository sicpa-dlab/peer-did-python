"""Peer DID document generation and resolution."""

import re

from typing import Optional, Sequence, Union

from pydid import DID, DIDDocument, DIDDocumentBuilder, DIDUrl, InvalidDIDError

from .core.peer_did_helper import (
    Numalgo2Prefix,
    ServiceJson,
    encode_service,
    decode_multibase_numbasis,
    decode_service,
)
from .errors import MalformedPeerDIDError
from .keys import KeyFormat, KeyRelationshipType, BaseKey

PEER_DID_PATTERN = re.compile(
    r"^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]+))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]+))+"
    r"(\.(S)[0-9a-zA-Z]*)?)))$"
)


def is_peer_did(peer_did: Union[str, DID]) -> bool:
    """
    Check if peer_did parameter matches the Peer DID spec.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#matching-regex>

    :param peer_did: peer_did to check
    :return: True if peer_did matches spec, otherwise False
    """
    if peer_did is None:
        return False
    return bool(PEER_DID_PATTERN.match(peer_did))


def create_peer_did_numalgo_0(
    inception_key: BaseKey,
) -> str:
    """
    Generate a Peer DID according to the zeroth algorithm.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#generation-method>
    For this type of algorithm the DID Document is synthesized from the key material.

    :param inception_key: the key that creates the DID and authenticates when exchanging it with the first peer
    :raises ValueError: the inception key is not a BaseKey supporting authentication
    :return: generated Peer DID
    """
    if KeyRelationshipType.AUTHENTICATION not in inception_key.relationships:
        raise ValueError(
            "Authentication not supported for key: {}.".format(inception_key)
        )
    return "did:peer:0" + inception_key.to_multibase()


def create_peer_did_numalgo_2(
    encryption_keys: Sequence[BaseKey],
    signing_keys: Sequence[BaseKey],
    service: Optional[ServiceJson],
) -> DID:
    """
    Generate a Peer DID according to the second algorithm.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#generation-method>
    For this type of algorithm the DID Document is synthesized from the key material.

    :param encryption_keys: list of encryption keys
    :param signing_keys: list of signing keys
    :param service: JSON conforming to the DID specification (https://www.w3.org/TR/did-core/#services)
        or None if there is no services expected for this DID
    :raises ValueError:
        1. if at least one of signing keys is not a BaseKey supporting authentication
        2. if at least one of encryption keys is not a BaseKey supporting key agreement
        3. if service is not valid JSON
    :return: generated Peer DID
    """
    for k in encryption_keys:
        if KeyRelationshipType.KEY_AGREEMENT not in k.relationships:
            raise ValueError("Key agreement not supported for key: {}.".format(k))
    for k in signing_keys:
        if KeyRelationshipType.AUTHENTICATION not in k.relationships:
            raise ValueError("Authentication not supported for key: {}.".format(k))

    enc_sep = "." + Numalgo2Prefix.KEY_AGREEMENT.value
    auth_sep = "." + Numalgo2Prefix.AUTHENTICATION.value
    encryption_keys_str = (
        enc_sep + enc_sep.join(key.to_multibase() for key in encryption_keys)
        if encryption_keys
        else ""
    )
    auth_keys_str = (
        auth_sep + auth_sep.join(key.to_multibase() for key in signing_keys)
        if signing_keys
        else ""
    )
    service_str = encode_service(service)

    peer_did = DID("did:peer:2" + encryption_keys_str + auth_keys_str + service_str)
    return peer_did


def resolve_peer_did(
    peer_did: Union[str, DID],
    format: KeyFormat = KeyFormat.MULTIBASE,
) -> DIDDocument:
    """
    Resolve a DID Document from a Peer DID.

    :param peer_did: Peer DID to resolve
    :param format: the format of public keys in the DID Document. Default format is multibase.
    :raises MalformedPeerDIDError: if peer_did parameter does not match Peer DID spec
    :return: resolved DID Document as a JSON string
    """
    if not is_peer_did(peer_did):
        raise MalformedPeerDIDError("Does not match peer DID regexp")
    if peer_did[9] == "0":
        did_doc = _build_did_doc_numalgo_0(peer_did, format)
    else:
        did_doc = _build_did_doc_numalgo_2(peer_did, format)
    return did_doc


def _did_document_builder(peer_did: Union[str, DID]) -> DIDDocumentBuilder:
    try:
        return DIDDocumentBuilder(
            peer_did, context=DIDDocumentBuilder.DEFAULT_CONTEXT.copy()
        )
    except InvalidDIDError as e:
        raise MalformedPeerDIDError("Invalid peer DID") from e


def _add_key_to_document(builder: DIDDocumentBuilder, key: BaseKey):
    ver_method_result = key.verification_method(builder.id)
    builder.verification_method.methods.append(ver_method_result.method)
    ver_ident = DIDUrl.parse(ver_method_result.method.id)
    if ver_method_result.context and ver_method_result.context not in builder.context:
        builder.context.append(ver_method_result.context)
    for rel in key.relationships:
        if rel == KeyRelationshipType.AUTHENTICATION:
            builder.authentication.reference(ver_ident)
            builder.assertion_method.reference(ver_ident)
            builder.capability_delegation.reference(ver_ident)
            builder.capability_invocation.reference(ver_ident)
        elif rel == KeyRelationshipType.KEY_AGREEMENT:
            builder.key_agreement.reference(ver_ident)


def _build_did_doc_numalgo_0(
    peer_did: Union[str, DID], format: KeyFormat
) -> DIDDocument:
    decoded_key = decode_multibase_numbasis(peer_did[10:], format)
    builder = _did_document_builder(peer_did)
    _add_key_to_document(builder, decoded_key)
    return builder.build()


def _build_did_doc_numalgo_2(
    peer_did: Union[str, DID], format: KeyFormat
) -> DIDDocument:
    keys = peer_did[11:]
    keys = keys.split(".")
    builder = _did_document_builder(peer_did)

    for key in keys:
        if not key:
            raise MalformedPeerDIDError("Blank key entry")
        prefix = key[0]
        if prefix == Numalgo2Prefix.SERVICE.value:
            for svc in decode_service(key[1:]):
                builder.service.services.append(svc)
        elif prefix == Numalgo2Prefix.AUTHENTICATION.value:
            decoded_key = decode_multibase_numbasis(key[1:], format)
            if KeyRelationshipType.AUTHENTICATION not in decoded_key.relationships:
                raise MalformedPeerDIDError(
                    "Authentication not supported for key: {}.".format(key)
                )
            _add_key_to_document(builder, decoded_key)
        elif prefix == Numalgo2Prefix.KEY_AGREEMENT.value:
            decoded_key = decode_multibase_numbasis(key[1:], format)
            if KeyRelationshipType.KEY_AGREEMENT not in decoded_key.relationships:
                raise MalformedPeerDIDError(
                    "Key agreement not supported for key: {}.".format(key)
                )
            _add_key_to_document(builder, decoded_key)
        else:
            raise MalformedPeerDIDError("Unknown prefix: {}.".format(prefix))

    return builder.build()
