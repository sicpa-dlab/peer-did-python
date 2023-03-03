import pytest

from pydid import Service

from peerdid.errors import MalformedPeerDIDError
from peerdid.dids import resolve_peer_did, resolve_peer_did_basis
from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey

from tests.test_vectors import (
    PEER_DID_NUMALGO_1,
    DID_DOC_NUMALGO_1,
)


def test_resolve_numalgo_1_basis():
    basis = resolve_peer_did_basis(
        peer_did=PEER_DID_NUMALGO_1, genesis=DID_DOC_NUMALGO_1
    )
    assert len(basis.encryption_keys) == 1 and all(
        isinstance(k, X25519KeyAgreementKey) for k in basis.encryption_keys
    )
    assert len(basis.signing_keys) == 2 and all(
        isinstance(k, Ed25519VerificationKey) for k in basis.signing_keys
    )
    assert len(basis.services) == 1 and isinstance(basis.services[0], Service)


def test_resolve_numalgo_1_doc():
    doc = resolve_peer_did(peer_did=PEER_DID_NUMALGO_1, genesis=DID_DOC_NUMALGO_1)
    assert doc.id == PEER_DID_NUMALGO_1


def test_resolve_numalgo_1_numbasis_mismatch():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*numeric basis does not correspond",
    ):
        resolve_peer_did(
            peer_did="did:peer:1z6666RYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            genesis=DID_DOC_NUMALGO_1,
        )


def test_resolve_numalgo_1_missing_document():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"DID document is required for resolving",
    ):
        resolve_peer_did(
            peer_did=PEER_DID_NUMALGO_1,
        )


def test_resolve_numalgo_1_malformed_base58_encoding():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:1z6MkqRYqQiSgvZQd0Bytw86Qbs2ZWUkGv22od935YF4s8M7V",
            genesis=DID_DOC_NUMALGO_1,
        )


def test_resolve_numalgo_1_unsupported_transform_code():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:1a6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            genesis=DID_DOC_NUMALGO_1,
        )
