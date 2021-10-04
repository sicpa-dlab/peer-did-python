import pytest

from peerdid.core.peer_did_helper import (
    encode_service,
    decode_service,
    decode_multibase_encnumbasis,
)
from peerdid.core.did_doc_types import (
    VerificationMaterialPeerDID,
    VerificationMethodTypeAgreement,
    VerificationMethodTypeAuthentication,
    VerificationMethodField,
)
from peerdid.types import VerificationMaterialFormatPeerDID
from tests.test_vectors import PEER_DID_NUMALGO_2


def test_encode_service():
    service = """{
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"],
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
        }
        """

    assert (
        encode_service(service)
        == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
    )


def test_decode_service():
    service = decode_service(
        service="eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
        peer_did=PEER_DID_NUMALGO_2,
    )
    expected = [
        {
            "id": PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"],
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
        }
    ]
    assert service == expected


def test_encode_service_minimal_fields():
    service = """{
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint"
        }
        """
    assert (
        encode_service(service)
        == ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9"
    )


def test_decode_service_minimal_fields():
    service = decode_service(
        service="eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
        peer_did=PEER_DID_NUMALGO_2,
    )
    expected = [
        {
            "id": PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
        }
    ]
    assert service == expected


def test_encode_service_with_multiple_entries_list():
    services = """
            [
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": "https://example.com/endpoint",
                    "routingKeys": ["did:example:somemediator#somekey"],
                    "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
                },
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": "https://example.com/endpoint2",
                    "routingKeys": ["did:example:somemediator#somekey2"]
                }
            ]
            """

    encoded_services = encode_service(services)
    assert (
        encoded_services
        == ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il0sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjNTg3Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"
    )


def test_decode_service_with_multiple_entries_list():
    service = decode_service(
        service="W3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il0sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjNTg3Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d",
        peer_did=PEER_DID_NUMALGO_2,
    )
    expected = [
        {
            "id": PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"],
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
        },
        {
            "id": PEER_DID_NUMALGO_2 + "#didcommmessaging-1",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint2",
            "routingKeys": ["did:example:somemediator#somekey2"],
        },
    ]
    assert service == expected


@pytest.mark.parametrize(
    "input_multibase,format,expected",
    [
        pytest.param(
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.BASE58,
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
                value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
            id="base58-ed25519",
        ),
        pytest.param(
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.BASE58,
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format=VerificationMaterialFormatPeerDID.BASE58,
                value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
            id="base58-x25519",
        ),
        pytest.param(
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.MULTIBASE,
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
                value="zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
            id="multibase-ed25519",
        ),
        pytest.param(
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.MULTIBASE,
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
                value="zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
            id="multibase-x25519",
        ),
        pytest.param(
            "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.JWK,
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
                value={
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                },
                encnumbasis="6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            ),
            id="jwk-ed25519",
        ),
        pytest.param(
            "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMaterialPeerDID(
                field=VerificationMethodField.JWK,
                type=VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
                value={
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
                },
                encnumbasis="6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
            id="jwk-x25519",
        ),
    ],
)
def test_decode_encumbasis(input_multibase, format, expected):
    res = decode_multibase_encnumbasis(input_multibase, format)
    assert res == expected
