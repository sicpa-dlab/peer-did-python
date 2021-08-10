import pytest

from peerdid.peer_did import create_peer_did_numalgo_0, create_peer_did_numalgo_2, resolve_peer_did
from peerdid.types import PublicKeyAgreement, PublicKeyAuthentication, KeyTypeAgreement, KeyTypeAuthentication


def test_create_numalgo_0_positive():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
        type=KeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])


def test_create_numalgo_0_wrong_inception_key():
    inception_key = PublicKeyAuthentication(
        encoded_value="zx8xB2pv7cw8q1PdDacS",
        type=KeyTypeAuthentication.ED25519)

    with pytest.raises(ValueError):
        peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=inception_key)


def test_create_numalgo_2_positive():
    encryption_keys = [PublicKeyAgreement(encoded_value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=KeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMypp",
            type=KeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=KeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                service=service)


def test_create_numalgo_2_wrong_encryption_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="....",
                                          type=KeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMypp",
            type=KeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=KeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    service=service)


def test_create_numalgo_2_wrong_signing_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=KeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value=".......",
            type=KeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=KeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    service=service)


def test_create_numalgo_2_wrong_service():
    encryption_keys = [PublicKeyAgreement(encoded_value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=KeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value=".......",
            type=KeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=KeyTypeAuthentication.ED25519)]
    service = '.......'

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    service=service)


def test_resolve():
    resolve_peer_did(
        'did:peer:2.E6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH.VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0=')
