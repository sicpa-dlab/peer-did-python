import pytest

from peerdid import DIDDocument
from peerdid.errors import MalformedPeerDIDError
from peerdid.dids import resolve_peer_did, resolve_peer_did_basis
from peerdid.keys import Ed25519VerificationKey, KeyFormat

from tests.test_vectors import (
    PEER_DID_NUMALGO_0,
    DID_DOC_NUMALGO_O_BASE58,
    DID_DOC_NUMALGO_O_MULTIBASE,
    DID_DOC_NUMALGO_O_JWK,
)


def test_resolve_numalgo_0_positive_default():
    did_doc = resolve_peer_did(peer_did=PEER_DID_NUMALGO_0)
    assert did_doc == DIDDocument.from_json(DID_DOC_NUMALGO_O_MULTIBASE)


def test_resolve_numalgo_0_basis():
    basis = resolve_peer_did_basis(peer_did=PEER_DID_NUMALGO_0)
    assert not basis.encryption_keys
    assert len(basis.signing_keys) == 1 and all(
        isinstance(k, Ed25519VerificationKey) for k in basis.signing_keys
    )
    assert not basis.services


def test_resolve_numalgo_0_positive_base58():
    did_doc = resolve_peer_did(peer_did=PEER_DID_NUMALGO_0, key_format=KeyFormat.BASE58)
    assert did_doc == DIDDocument.from_json(DID_DOC_NUMALGO_O_BASE58)


def test_resolve_numalgo_0_positive_multibase():
    did_doc = resolve_peer_did(
        peer_did=PEER_DID_NUMALGO_0, key_format=KeyFormat.MULTIBASE
    )
    assert did_doc == DIDDocument.from_json(DID_DOC_NUMALGO_O_MULTIBASE)


def test_resolve_numalgo_0_positive_jwk():
    did_doc = resolve_peer_did(peer_did=PEER_DID_NUMALGO_0, key_format=KeyFormat.JWK)
    assert did_doc == DIDDocument.from_json(DID_DOC_NUMALGO_O_JWK)


def test_resolve_unsupported_did_method():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:key:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        )


def test_resolve_invalid_peer_did():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:0z6MkqRYqQiSBytw86Qbs2ZWUkGv22od935YF4s8M7V!"
        )


def test_resolve_unsupported_numalgo_code():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:4z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        )


def test_resolve_numalgo_0_malformed_base58_encoding():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:0z6MkqRYqQiSgvZQd0Bytw86Qbs2ZWUkGv22od935YF4s8M7V"
        )


def test_resolve_numalgo_0_unsupported_transform_code():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Not a recognizable peer DID",
    ):
        resolve_peer_did(
            peer_did="did:peer:0a6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        )


def test_resolve_numalgo_0_malformed_multicodec_encoding():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            peer_did="did:peer:0z6666RYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        )


def test_resolve_numalgo_0_invalid_key_type():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            peer_did="did:peer:0z6QSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        )


def test_resolve_numalgo_0_short_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Invalid key",
    ):
        resolve_peer_did(peer_did="did:peer:0z6LSbysY2xc")


def test_resolve_numalgo_0_long_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Invalid key",
    ):
        resolve_peer_did(
            peer_did="did:peer:0z6LSbysY2xcccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        )
