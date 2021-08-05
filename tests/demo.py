from peerdid.peer_did_creator import create_peer_did_numalgo_0, create_peer_did_numalgo_2
from peerdid.peer_did_resolver import resolve_peer_did
from peerdid.storage import FileStorage
from peerdid.types import PublicKey, KeyType


def demo_create_save_resolve_peer_did():
    encryption_keys = [PublicKey(encoded_value="Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                 type=KeyType.X25519)]
    signing_keys = [PublicKey(
        encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
        type=KeyType.X25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=encryption_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys,
                                                signing_keys=signing_keys,
                                                service_endpoint="https://example.com/endpoint")

    file_storage = FileStorage()
    file_storage.save_peer_did(peer_did_algo_0)
    file_storage.save_peer_did(peer_did_algo_2)

    did_doc_algo_0 = resolve_peer_did(peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2, version_id=1)
