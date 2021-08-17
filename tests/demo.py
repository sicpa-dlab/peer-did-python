import pytest
from peerdid.peer_did import create_peer_did_numalgo_0, create_peer_did_numalgo_2, resolve_peer_did
from peerdid.peer_did_utils import encode_filename
from peerdid.storage import FileStorage
from peerdid.types import PublicKeyAuthentication, PublicKeyAgreement, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication


def test_create_save_resolve_peer_did():
    encryption_keys = [PublicKeyAgreement(encoded_value="DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys,
                                                signing_keys=signing_keys,
                                                services=[
                                                    '''
                                                        {
                                                            "type": "didcommmessaging",
                                                            "serviceEndpoint": "https://example.com/endpoint",
                                                            "routingKeys": ["did:example:somemediator#somekey"]
                                                        }
                                                    ''',
                                                    '''
                                                        {
                                                          "type": "didcommmessaging",
                                                          "serviceEndpoint": "https://example.com/endpoint2",
                                                          "routingKeys": ["did:example:somemediator#somekey2"]
                                                        }
                                                    '''
                                                ])

    print('peer_did_algo_0:' + peer_did_algo_0)
    print('==================================')
    print('peer_did_algo_2:' + peer_did_algo_2)
    print('==================================')

    file_storage = FileStorage(peer_did_filename=encode_filename(peer_did_algo_2))
    file_storage.save(bytes(peer_did_algo_2, encoding='utf-8'))

    did_doc_algo_0 = resolve_peer_did(peer_did=peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2)
    print('did_doc_algo_0:' + did_doc_algo_0)
    print('==================================')
    print('did_doc_algo_2:' + did_doc_algo_2)
