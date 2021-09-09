from peerdid.peer_did_utils import _encode_service


def test_encode_service():
    service = """{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        """

    assert (
        _encode_service(service)
        == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
    )


def test_encode_service_without_routing_keys():
    service = """{
        "type": "didcommmessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        }
        """
    assert (
        _encode_service(service)
        == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsfQ=="
    )


def test_encode_service_with_multiple_entries_list():
    services = """
            [
                {
                    "type": "didcommmessaging",
                    "serviceEndpoint": "https://example.com/endpoint",
                    "routingKeys": ["did:example:somemediator#somekey"]
                },
                {
                    "type": "didcommmessaging",
                    "serviceEndpoint": "https://example.com/endpoint2",
                    "routingKeys": ["did:example:somemediator#somekey2"]
                }
            ]
            """

    encoded_services = _encode_service(services)
    assert (
        encoded_services
        == ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlO"
        "nNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9p"
        "bnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"
    )
