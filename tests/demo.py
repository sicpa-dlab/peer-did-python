import pytest
from peerdid.peer_did import create_peer_did_numalgo_0, create_peer_did_numalgo_2, resolve_peer_did, save_peer_did
from peerdid.storage import FileStorage
from peerdid.types import PublicKeyAuthentication, PublicKeyAgreement, KeyTypeAgreement, KeyTypeAuthentication


def test_create_save_resolve_peer_did():
    encryption_keys = [PublicKeyAgreement(encoded_value="Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=KeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
        type=KeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys,
                                                signing_keys=signing_keys,
                                                service_endpoint="https://example.com/endpoint")

    file_storage = FileStorage()
    save_peer_did(peer_did=peer_did_algo_0, storage=file_storage)
    save_peer_did(peer_did=peer_did_algo_2, storage=file_storage)

    did_doc_algo_0 = resolve_peer_did(peer_did=peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2)
