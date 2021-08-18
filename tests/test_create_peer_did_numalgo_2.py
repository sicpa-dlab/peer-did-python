import pytest

from peerdid.peer_did import create_peer_did_numalgo_2, is_peer_did
from peerdid.types import PublicKeyAgreement, PublicKeyTypeAgreement, PublicKeyAuthentication, \
    PublicKeyTypeAuthentication


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
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
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
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert peer_did_algo_2 == 'did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V' \
                              '.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg' \
                              '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0='
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_without_signing_keys():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = []
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
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
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


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
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


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
    services = ['.......']

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_encryption_key_as_signing():
    encryption_keys = [PublicKeyAgreement(encoded_value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                                          type=PublicKeyTypeAgreement.X25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']
    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=encryption_keys,
                                                    services=services)


def test_create_numalgo_2_signing_key_as_encryption():
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="zXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMypp",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']
    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=signing_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_service_is_an_array():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''
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
                ]

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_encryption_and_signing_keys_are_1_element_array():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
        type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_encryption_and_signing_keys_are_more_than_1_element_array():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519),
                       PublicKeyAgreement(
                           encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                           type=PublicKeyTypeAgreement.X25519)
                       ]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_has_more_fields_than_in_conversion_table():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        "example1": "myExample1"
        "example2": "myExample2"
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_not_didcommmessaging():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "example1",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_empty_string():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_empty_array():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = []

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_different_types_of_services():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''
              {
                  "type": "example1",
                  "serviceEndpoint": "https://example.com/endpoint",
                  "routingKeys": ["did:example:somemediator#somekey"]
              }
              ''',
                '''
            {
                "type": "example2",
                "serviceEndpoint": "https://example.com/endpoint2",
                "routingKeys": ["did:example:somemediator#somekey2"]
            }
            '''
                ]

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_services_str():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = '''[
              {
                  "type": "example1",
                  "serviceEndpoint": "https://example.com/endpoint",
                  "routingKeys": ["did:example:somemediator#somekey"]
              },
            {
                "type": "example2",
                "serviceEndpoint": "https://example.com/endpoint2",
                "routingKeys": ["did:example:somemediator#somekey2"]
            }
            ]
            '''

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_encryption_key_not_base58_encoded():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYcc0k7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            ''']
    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_malformed_short_encryption_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSV",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            ''']
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert not is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_long_encryption_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            ''']
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert not is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_encryption_key_empty():
    encryption_keys = [PublicKeyAgreement(encoded_value="",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            ''']
    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_invalid_encryption_key_type():
    encryption_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]
    signing_keys = [
        PublicKeyAuthentication(
            encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=PublicKeyTypeAuthentication.ED25519),
        PublicKeyAuthentication(
            encoded_value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_malformed_signing_key_not_base58_encoded():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="3M5RCDjPTWPkKSN3sxU0mMqHbmRPegYP1tjcKyrDbt9J",
        type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_2_malformed_short_signing_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCF",
        type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert not is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_long_signing_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="3M5RCDjxUmmMqHbmRPegYPPTWPkKSN3sxUmmMqHbmRPegYPxUmmMqHbmRPegYP1tjcKxUmmMqHbmRPegYPyrDbt9J",
        type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                services=services)
    assert not is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_empty_signing_key():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAuthentication(
        encoded_value="",
        type=PublicKeyTypeAuthentication.ED25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(ValueError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)


def test_create_numalgo_0_invalid_inception_key_type():
    encryption_keys = [PublicKeyAgreement(encoded_value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                                          type=PublicKeyTypeAgreement.X25519)]
    signing_keys = [PublicKeyAgreement(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAgreement.X25519)]
    services = ['''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        ''']

    with pytest.raises(TypeError):
        peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys, signing_keys=signing_keys,
                                                    services=services)
