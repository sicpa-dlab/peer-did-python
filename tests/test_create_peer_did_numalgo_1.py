import json

from peerdid.dids import StoredDIDDocument, create_peer_did_numalgo_1, is_peer_did

from .test_vectors import (
    DID_DOC_NUMALGO_1,
    DID_DOC_NUMALGO_1_STORED,
    PEER_DID_NUMALGO_1,
)


def test_stored_did_document_from_str():
    stored = StoredDIDDocument.create(DID_DOC_NUMALGO_1)
    assert stored == DID_DOC_NUMALGO_1_STORED


def test_stored_did_document_from_bytes():
    stored = StoredDIDDocument.create(DID_DOC_NUMALGO_1.encode("utf-8"))
    assert stored == DID_DOC_NUMALGO_1_STORED


def test_stored_did_document_from_dict():
    stored = StoredDIDDocument.create(json.loads(DID_DOC_NUMALGO_1))
    assert stored == DID_DOC_NUMALGO_1_STORED


def test_stored_did_document_from_doc():
    from pydid import deserialize_document

    did_doc = deserialize_document(json.loads(DID_DOC_NUMALGO_1))
    stored = StoredDIDDocument.create(did_doc)
    assert stored == DID_DOC_NUMALGO_1_STORED


def test_create_numalgo_1_positive():
    peer_did_algo_1 = create_peer_did_numalgo_1(did_doc=DID_DOC_NUMALGO_1)
    assert peer_did_algo_1 == PEER_DID_NUMALGO_1
    assert is_peer_did(peer_did_algo_1)
