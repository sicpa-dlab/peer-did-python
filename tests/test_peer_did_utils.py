import pytest

from peerdid.peer_did_utils import _encode_service, _decode_encnumbasis
from peerdid.types import VerificationMaterialFormat


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


PEER_DID = "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"


@pytest.mark.parametrize(
    "test_value",
    [
        (
            "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "Ed25519VerificationKey2018",
            "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        ),
        (
            "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "X25519KeyAgreementKey2019",
            "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
        ),
    ],
)
def test_decode_encumbasis_base58(test_value):
    enc_num_bassis = test_value[0]
    res = _decode_encnumbasis(
        enc_num_bassis, PEER_DID, VerificationMaterialFormat.BASE58
    )
    assert res["id"] == PEER_DID + "#" + enc_num_bassis
    assert res["controller"] == PEER_DID
    assert res["type"] == test_value[1]
    assert "publicKeyBase58" in res
    assert res["publicKeyBase58"] == test_value[2]


@pytest.mark.parametrize(
    "test_value",
    [
        (
            "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "Ed25519VerificationKey2020",
            "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        ),
        (
            "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "X25519KeyAgreementKey2019",
            "zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
        ),
    ],
)
def test_decode_encumbasis_multibase(test_value):
    enc_num_bassis = test_value[0]
    res = _decode_encnumbasis(
        enc_num_bassis, PEER_DID, VerificationMaterialFormat.MULTIBASE
    )
    assert res["id"] == PEER_DID + "#" + enc_num_bassis
    assert res["controller"] == PEER_DID
    assert res["type"] == test_value[1]
    assert "publicKeyMultibase" in res
    assert res["publicKeyMultibase"] == test_value[2]


@pytest.mark.parametrize(
    "test_value",
    [
        (
            "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "Ed25519",
            "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA=",
        ),
        (
            "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "X25519",
            "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik=",
        ),
    ],
)
def test_decode_encumbasis_jwk(test_value):
    enc_num_bassis = test_value[0]
    res = _decode_encnumbasis(enc_num_bassis, PEER_DID, VerificationMaterialFormat.JWK)
    assert res["id"] == PEER_DID + "#" + enc_num_bassis
    assert res["controller"] == PEER_DID
    assert res["type"] == "JsonWebKey2020"
    assert "publicKeyJwk" in res
    jwk = res["publicKeyJwk"]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == test_value[1]
    assert jwk["x"] == test_value[2]
