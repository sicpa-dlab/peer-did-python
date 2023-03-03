"""Peer DID document generation and resolution."""

import json
import re

from enum import Enum
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Union

from pydid import (
    deserialize_document,
    BaseDIDDocument,
    DID,
    DIDDocumentBuilder,
    DIDUrl,
    InvalidDIDError,
    Service,
    VerificationMethod,
)

from .core.multibase import MultibaseFormat, to_multibase
from .core.multicodec import Codec
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
    r"^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]+))"
    r"|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]+))+(\.(S)[0-9a-zA-Z]*)?)))$"
)


class InceptionMethod(Enum):
    """Supported peer DID inception methods."""

    SingleKey = 0
    GenesisDocument = 1
    MultipleKeys = 2


class ResolvedBasis:
    """The resolved basis for a peer DID derived using methods 0 or 2.

    This includes the keys and potentially service information defined by the peer DID.

    Reference: <https://identity.foundation/peer-did-method-spec/#generation-method>
    """

    did: DID
    method: InceptionMethod
    keys: List[BaseKey]
    services: List[Service]
    genesis: Optional[BaseDIDDocument]
    stored: Optional["StoredDIDDocument"]

    def __init__(
        self,
        did: Union[str, DID],
        keys: List[BaseKey] = None,
        services: List[dict] = None,
    ):
        """Initializer."""
        self.did = DID(did)
        self.keys = keys or []
        self.services = services or []
        self.genesis = None
        self.stored = None

    def did_doc(self) -> BaseDIDDocument:
        """Convert this resolved basis into a DID Document."""
        if self.genesis:
            return self.genesis

        try:
            builder = DIDDocumentBuilder(
                self.did, context=DIDDocumentBuilder.DEFAULT_CONTEXT.copy()
            )
        except InvalidDIDError as e:
            raise MalformedPeerDIDError("Invalid peer DID") from e

        for key in self.keys:
            ver_method_result = key.verification_method(builder.id)
            builder.verification_method.methods.append(ver_method_result.method)
            ver_ident = DIDUrl.parse(ver_method_result.method.id)
            if (
                ver_method_result.context
                and ver_method_result.context not in builder.context
            ):
                builder.context.append(ver_method_result.context)
            if KeyRelationshipType.AUTHENTICATION in key.relationships:
                builder.authentication.reference(ver_ident)
                builder.assertion_method.reference(ver_ident)
                builder.capability_delegation.reference(ver_ident)
                builder.capability_invocation.reference(ver_ident)
            if KeyRelationshipType.KEY_AGREEMENT in key.relationships:
                builder.key_agreement.reference(ver_ident)

        builder.service.services.extend(self.services)

        return builder.build()

    @property
    def encryption_keys(self) -> List[BaseKey]:
        """Accessor for the keys supporting key exchange."""
        return [
            key
            for key in self.keys
            if KeyRelationshipType.KEY_AGREEMENT in key.relationships
        ]

    @property
    def signing_keys(self) -> List[BaseKey]:
        """Accessor for the keys supporting authentication."""
        return [
            key
            for key in self.keys
            if KeyRelationshipType.AUTHENTICATION in key.relationships
        ]

    def _populate_numalgo_0(self, basis: str, key_format: KeyFormat = None):
        decoded_key = decode_multibase_numbasis(basis, key_format)
        self.keys.append(decoded_key)

    def _populate_numalgo_1(
        self,
        genesis: Union[BaseDIDDocument, dict, str, bytes],
        key_format: KeyFormat = None,
        stored: "StoredDIDDocument" = None,
    ):
        if not stored:
            stored = StoredDIDDocument.create(genesis)
        self.stored = stored

        if self.did != "did:peer:1" + stored.encoded_numbasis:
            raise MalformedPeerDIDError(
                "Calculated numeric basis does not correspond with peer DID"
            )

        if not isinstance(genesis, BaseDIDDocument):
            genesis = deserialize_document(_load_did_document(genesis))
        self.genesis = genesis

        idents = set()

        if genesis.authentication:
            for keyref in genesis.authentication:
                try:
                    key = _resolve_verification_method(genesis, keyref, key_format)
                except ValueError as e:
                    # skip unrecognized keys
                    continue
                if key.ident and key.ident not in idents:
                    self.keys.append(key)
                    idents.add(key.ident)

        if genesis.key_agreement:
            for keyref in genesis.key_agreement:
                try:
                    key = _resolve_verification_method(genesis, keyref, key_format)
                except ValueError as e:
                    # skip unrecognized keys
                    continue
                if key.ident and key.ident not in idents:
                    self.keys.append(key)
                    idents.add(key.ident)

        if genesis.service:
            for svc in genesis.service:
                if isinstance(svc, Service):
                    self.services.append(svc)
                else:
                    self.services.append(Service.make(**svc))

    def _populate_numalgo_2(
        self, basis: str, key_format: KeyFormat = None
    ) -> BaseDIDDocument:
        keys = basis[1:].split(".")

        for key in keys:
            if not key:
                raise MalformedPeerDIDError("Blank key entry")
            prefix = key[0]
            if prefix == Numalgo2Prefix.SERVICE.value:
                for svc in decode_service(key[1:]):
                    self.services.append(svc)
            elif prefix == Numalgo2Prefix.AUTHENTICATION.value:
                decoded_key = decode_multibase_numbasis(key[1:], key_format)
                if KeyRelationshipType.AUTHENTICATION not in decoded_key.relationships:
                    raise MalformedPeerDIDError(
                        "Authentication not supported for key: {}.".format(key)
                    )
                self.keys.append(decoded_key)
            elif prefix == Numalgo2Prefix.KEY_AGREEMENT.value:
                decoded_key = decode_multibase_numbasis(key[1:], key_format)
                if KeyRelationshipType.KEY_AGREEMENT not in decoded_key.relationships:
                    raise MalformedPeerDIDError(
                        "Key agreement not supported for key: {}.".format(key)
                    )
                self.keys.append(decoded_key)
            else:
                raise MalformedPeerDIDError("Unknown prefix: {}.".format(prefix))

    def __repr__(self) -> str:
        """Generate printable representation."""
        return "<{} did={}>".format(self.__class__.__name__, self.did)


class StoredDIDDocument(bytes):
    """The stored variant of a DID Document.

    Reference: <https://identity.foundation/peer-did-method-spec/#generation-method>
    """

    @staticmethod
    def __new__(cls, stored: Union["StoredDIDDocument", bytes]) -> "StoredDIDDocument":
        """Class constructor."""
        if isinstance(stored, StoredDIDDocument):
            return stored
        elif isinstance(stored, bytes):
            inst = super().__new__(cls, stored)
            inst.__init__(stored)
            return inst
        else:
            raise TypeError("Expected bytes for stored document")

    @classmethod
    def create(
        cls, did_doc: Union[BaseDIDDocument, dict, str, bytes]
    ) -> "StoredDIDDocument":
        """
        Create the stored variant of a DID Document.

        This format is used in generating the numeric basis for a peer DID using method 1.
        Reference: <https://identity.foundation/peer-did-method-spec/index.html#generation-method>

        :param did_doc: the genesis DID Document
        :raises TypeError: if did_doc is of an unsupported type
        :raises ValueError: if the DID Document cannot be processed
        :return: a tuple of the generated Peer DID and the stored variant of the DID Document
        """
        if isinstance(did_doc, BaseDIDDocument):
            did_doc = did_doc.serialize()
        else:
            did_doc = _load_did_document(did_doc)
        ident = did_doc.pop("id", None)
        if ident:
            # remove any references to the DID (in controller attributes for example)
            pass
        did_doc_bytes = json.dumps(did_doc, separators=(",", ":")).encode("utf-8")
        return cls(did_doc_bytes)

    def expand(self, did: DID) -> BaseDIDDocument:
        """Expand the stored DID document, populating the DID."""
        doc_dict = _load_did_document(self)
        doc_dict["id"] = str(did)
        return deserialize_document(doc_dict)

    @property
    def encoded_numbasis(self) -> bytes:
        """Calculate the encoded numeric basis of the prepared document."""
        doc_hash = sha256(self).digest()
        numbasis = Codec.SHA256.encode_multicodec_with_length(doc_hash)
        return to_multibase(numbasis, MultibaseFormat.BASE58)


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


def split_peer_did(peer_did: Union[str, DID]) -> Tuple[InceptionMethod, str]:
    """
    Split a peer DID into its inception method and encoded numeric basis.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#matching-regex>

    :param peer_did: peer_did to split
    :return: a tuple of the InceptionMethod and encoded numeric basis (including the transform)
    """
    match = PEER_DID_PATTERN.match(peer_did or "")
    if not match:
        raise MalformedPeerDIDError("Not a recognizable peer DID")
    body = match[1]
    return (InceptionMethod(int(body[0])), body[1:])


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


def create_peer_did_numalgo_1(
    did_doc: Union[BaseDIDDocument, StoredDIDDocument, dict, str, bytes],
) -> str:
    """
    Generate a Peer DID according to the first algorithm.

    Reference: <https://identity.foundation/peer-did-method-spec/index.html#generation-method>
    For this type of algorithm the DID is derived from a genesis DID Document.

    :param did_doc: the genesis DID Document
    :raises ValueError: if the DID Document cannot be processed
    :return: a tuple of the generated Peer DID and the stored variant of the DID Document
    """
    if not isinstance(did_doc, StoredDIDDocument):
        did_doc = StoredDIDDocument.create(did_doc)
    return "did:peer:1" + did_doc.encoded_numbasis


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
    key_format: KeyFormat = KeyFormat.MULTIBASE,
    genesis: Union[BaseDIDDocument, StoredDIDDocument, dict, str, bytes] = None,
) -> BaseDIDDocument:
    """
    Resolve and verify a DID Document from a Peer DID.

    :param peer_did: Peer DID to resolve
    :param key_format: the format of public keys in the DID Document. Default format is multibase.
    :param genesis: a genesis DID document or stored variant representing the basis.
    :raises MalformedPeerDIDError: if peer_did parameter does not match Peer DID spec
    :return: resolved DID Document as a JSON string
    """
    resolved = resolve_peer_did_basis(peer_did, key_format=key_format, genesis=genesis)
    return resolved.did_doc()


def resolve_peer_did_basis(
    peer_did: Union[str, DID],
    key_format: KeyFormat = KeyFormat.MULTIBASE,
    genesis: Union[BaseDIDDocument, StoredDIDDocument, dict, str, bytes] = None,
) -> ResolvedBasis:
    """
    Resolve a Peer DID to its keys and service entries.

    :param peer_did: Peer DID to resolve
    :param key_format: the format of public keys in the DID Document. Default format is multibase.
    :param genesis: a genesis DID document or stored variant representing the basis.
    :raises MalformedPeerDIDError: if peer_did parameter does not match Peer DID spec
    :return: resolved DID Document basis as a ResolvedBasis instance
    """
    method, basis = split_peer_did(peer_did)
    resolved = ResolvedBasis(peer_did)
    if method == InceptionMethod.SingleKey:
        resolved._populate_numalgo_0(basis, key_format)
    elif method == InceptionMethod.GenesisDocument:
        if genesis is None:
            raise MalformedPeerDIDError(
                "DID document is required for resolving peer DID method 1"
            )
        if isinstance(genesis, StoredDIDDocument):
            stored = genesis
            genesis = StoredDIDDocument.expand(peer_did)
        else:
            stored = StoredDIDDocument.create(genesis)
        resolved._populate_numalgo_1(genesis, key_format, stored)
    elif method == InceptionMethod.MultipleKeys:
        resolved._populate_numalgo_2(basis, key_format)
    else:
        # should not be reachable
        raise MalformedPeerDIDError("Unsupported inception method")
    return resolved


def _load_did_document(did_doc: Union[dict, str, bytes]) -> dict:
    if isinstance(did_doc, BaseDIDDocument):
        return did_doc

    if isinstance(did_doc, (str, bytes)):
        try:
            did_doc = json.loads(did_doc)
        except json.JSONDecodeError as err:
            raise ValueError("DID Document is not valid JSON") from err
    if not isinstance(did_doc, dict):
        raise TypeError("DID Document is not of a supported type")

    return did_doc


def _resolve_verification_method(
    doc: BaseDIDDocument,
    keyref: Union[DIDUrl, VerificationMethod, dict],
    key_format: KeyFormat = None,
) -> Optional[BaseKey]:
    if isinstance(keyref, DIDUrl):
        # may raise ValueError
        method = doc.dereference_as(VerificationMethod, keyref)
    elif isinstance(keyref, (dict, VerificationMethod)):
        method = keyref
    # may raise ValueError
    return BaseKey.from_verification_method(method, format=key_format)
