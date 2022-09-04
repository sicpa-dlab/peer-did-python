import json

from peerdid.dids import create_peer_did_numalgo_1, is_peer_did

from .test_vectors import (
    DID_DOC_NUMALGO_1,
    DID_DOC_NUMALGO_1_STORED,
    PEER_DID_NUMALGO_1,
)


def test_create_numalgo_1_from_str():
    (peer_did_algo_1, stored_doc) = create_peer_did_numalgo_1(did_doc=DID_DOC_NUMALGO_1)
    assert peer_did_algo_1 == PEER_DID_NUMALGO_1
    assert stored_doc == DID_DOC_NUMALGO_1_STORED
    assert is_peer_did(peer_did_algo_1)


def test_create_numalgo_1_from_dict():
    did_doc = json.loads(DID_DOC_NUMALGO_1)
    (peer_did_algo_1, stored_doc) = create_peer_did_numalgo_1(did_doc=did_doc)
    assert peer_did_algo_1 == PEER_DID_NUMALGO_1
    assert stored_doc == DID_DOC_NUMALGO_1_STORED
    assert is_peer_did(peer_did_algo_1)


def test_create_numalgo_1_from_doc():
    from pydid import deserialize_document

    did_doc = deserialize_document(json.loads(DID_DOC_NUMALGO_1))
    (peer_did_algo_1, stored_doc) = create_peer_did_numalgo_1(did_doc=did_doc)
    assert peer_did_algo_1 == PEER_DID_NUMALGO_1
    assert stored_doc == DID_DOC_NUMALGO_1_STORED
    assert is_peer_did(peer_did_algo_1)
