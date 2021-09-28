import pytest

from peerdid.did_doc import (
    PublicKeyField,
    VerificationMaterial,
    VerificationMaterialType,
    VerificationMaterialTypeAgreement,
    VerificationMaterialTypeAuthentication,
)
from peerdid.peer_did_utils import _encode_service, _decode_multibase_encnumbasis
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


@pytest.mark.parametrize(
    "input_multibase,format,expected",
    [
        (
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormat.BASE58,
            VerificationMaterial(
                field=PublicKeyField.BASE58,
                type=VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
        ),
        (
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormat.BASE58,
            VerificationMaterial(
                field=PublicKeyField.BASE58,
                type=VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
        ),
        (
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormat.MULTIBASE,
            VerificationMaterial(
                field=PublicKeyField.MULTIBASE,
                type=VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                value="zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
        ),
        (
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormat.MULTIBASE,
            VerificationMaterial(
                field=PublicKeyField.MULTIBASE,
                type=VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                value="zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
        ),
        (
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormat.JWK,
            VerificationMaterial(
                field=PublicKeyField.JWK,
                type=VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020,
                value={
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA=",
                },
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
        ),
        (
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormat.JWK,
            VerificationMaterial(
                field=PublicKeyField.JWK,
                type=VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020,
                value={
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik=",
                },
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
        ),
    ],
)
def test_decode_encumbasis(input_multibase, format, expected):
    res = _decode_multibase_encnumbasis(input_multibase, format)
    assert res == expected
