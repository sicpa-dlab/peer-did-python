import pytest

from peerdid.peer_did import create_peer_did_numalgo_0, create_peer_did_numalgo_2, is_peer_did
from peerdid.peer_did_utils import encode_service
from peerdid.types import PublicKeyAgreement, PublicKeyAuthentication, PublicKeyTypeAgreement, \
    PublicKeyTypeAuthentication


def test_create_numalgo_0_positive():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    assert peer_did_algo_0 == "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    assert is_peer_did(peer_did_algo_0)


def test_create_numalgo_0_wrong_inception_key():
    inception_key = PublicKeyAuthentication(
        encoded_value="zx8xB2pv7cw8q1PdDacS",
        type=PublicKeyTypeAuthentication.ED25519)

    peer_did = create_peer_did_numalgo_0(inception_key=inception_key)
    assert not is_peer_did(peer_did)


def test_create_numalgo_2_positive():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                service=service)
    assert peer_did_algo_2 == 'did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc' \
                              '.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V' \
                              '.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg' \
                              '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0='
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_without_encryption_keys():
    encryption_keys = []
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                service=service)
    assert peer_did_algo_2 == 'did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V' \
                              '.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg' \
                              '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0='
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_without_signing_keys():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = []
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                service=service)
    assert peer_did_algo_2 == 'did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc' \
                              '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0='
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_wrong_encryption_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="....",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMypp",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=PublicKeyTypeAuthentication.ED25519)]
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
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value=".......",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=PublicKeyTypeAuthentication.ED25519)]
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
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value=".......",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=PublicKeyTypeAuthentication.ED25519)]
    service = '.......'

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    service=service)


def test_create_numalgo_2_encryption_key_as_signing():
    encryption_keys = [PublicKeyAgreement(encoded_value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=PublicKeyTypeAgreement.X25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''
    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=encryption_keys,
                                                    service=service)


def test_create_numalgo_2_signing_key_as_encryption():
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMypp",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=PublicKeyTypeAuthentication.ED25519)]
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''
    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=signing_keys, signing_keys=signing_keys,
                                                    service=service)


def test_encode_service():
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    assert encode_service(
        service) == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
