import pytest

from peerdid.peer_did_utils import _encode_service


def test_encode_service():
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        '''

    assert _encode_service(
        service) == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="


def test_encode_service_without_routing_keys():
    service = '''{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        }
        '''
    assert _encode_service(
        service) == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsfQ=="


def test_encode_service_with_multiple_entries():
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

    encoded_services = [_encode_service(service[2:]) for service in services]
    assert encoded_services == [
        '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0=',
        '.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfQ==']
