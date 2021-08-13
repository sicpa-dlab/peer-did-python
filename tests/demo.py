import pytest
from peerdid.peer_did import create_peer_did_numalgo_0, create_peer_did_numalgo_2, resolve_peer_did, save_peer_did
from peerdid.peer_did_utils import encode_filename
from peerdid.storage import FileStorage
from peerdid.types import PublicKeyAuthentication, PublicKeyAgreement, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication


def test_create_save_resolve_peer_did():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys,
                                                signing_keys=signing_keys,
                                                service='''{
                    "type": "didcommmessaging",
                    "serviceEndpoint": "https://example.com/endpoint",
                    "routingKeys": ["did:example:somemediator#somekey"]
                }
                    ''')

    file_storage = FileStorage(peer_did_filename=encode_filename(peer_did_algo_2))
    save_peer_did(
        peer_did=peer_did_algo_2,
        storage=file_storage)

    did_doc_algo_0 = resolve_peer_did(peer_did=peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2)
