import json

import pytest

from peerdid.peer_did import create_peer_did_numalgo_2, is_peer_did
from peerdid.types import (
    VerificationMaterialAgreement,
    VerificationMethodTypeAgreement,
    VerificationMaterialAuthentication,
    VerificationMaterialFormat,
    VerificationMethodTypeAuthentication,
)

VALID_X25519_KEY_AGREEMENT_KEY_2019 = VerificationMaterialAgreement(
    value="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
    type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
    format=VerificationMaterialFormat.BASE58,
)
VALID_X25519_KEY_AGREEMENT_KEY_2020 = VerificationMaterialAgreement(
    value="zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
    type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
    format=VerificationMaterialFormat.MULTIBASE,
)
VALID_AGREEM_JSON_WEB_KEY_2020_DICT = VerificationMaterialAgreement(
    value={
        "kty": "OKP",
        "crv": "X25519",
        "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
    },
    type=VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
    format=VerificationMaterialFormat.JWK,
)
VALID_AGREEM_JSON_WEB_KEY_2020_JSON = VerificationMaterialAgreement(
    value=json.dumps(
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
        }
    ),
    type=VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
    format=VerificationMaterialFormat.JWK,
)

VALID_ED25519_VERIFICATION_KEY_2018_1 = VerificationMaterialAuthentication(
    value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
    type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
    format=VerificationMaterialFormat.BASE58,
)
VALID_ED25519_VERIFICATION_KEY_2020_1 = VerificationMaterialAuthentication(
    value="zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
    type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
    format=VerificationMaterialFormat.MULTIBASE,
)
VALID_AUTH_JSON_WEB_KEY_2020_1 = VerificationMaterialAuthentication(
    value={
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
    },
    type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
    format=VerificationMaterialFormat.JWK,
)

VALID_ED25519_VERIFICATION_KEY_2018_2 = VerificationMaterialAuthentication(
    value="3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
    type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
    format=VerificationMaterialFormat.BASE58,
)
VALID_ED25519_VERIFICATION_KEY_2020_2 = VerificationMaterialAuthentication(
    value="z3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
    type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
    format=VerificationMaterialFormat.MULTIBASE,
)
VALID_AUTH_JSON_WEB_KEY_2020_2 = VerificationMaterialAuthentication(
    value=json.dumps(
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "Itv8B__b1-Jos3LCpUe8EdTFGTCa_Dza6_3848P3R70",
        }
    ),
    type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
    format=VerificationMaterialFormat.JWK,
)

VALID_SERVICE = """
    {
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
    }
    """


@pytest.mark.parametrize(
    "encryption_keys, signing_keys",
    [
        pytest.param(
            [VALID_X25519_KEY_AGREEMENT_KEY_2019],
            [
                VALID_ED25519_VERIFICATION_KEY_2018_1,
                VALID_ED25519_VERIFICATION_KEY_2018_2,
            ],
            id="BASE58",
        ),
        pytest.param(
            [VALID_X25519_KEY_AGREEMENT_KEY_2020],
            [
                VALID_ED25519_VERIFICATION_KEY_2020_1,
                VALID_ED25519_VERIFICATION_KEY_2020_2,
            ],
            id="MULTIBASE",
        ),
        pytest.param(
            [VALID_AGREEM_JSON_WEB_KEY_2020_JSON],
            [VALID_AUTH_JSON_WEB_KEY_2020_1, VALID_AUTH_JSON_WEB_KEY_2020_2],
            id="JWK_JSON",
        ),
        pytest.param(
            [VALID_AGREEM_JSON_WEB_KEY_2020_DICT],
            [VALID_AUTH_JSON_WEB_KEY_2020_1, VALID_AUTH_JSON_WEB_KEY_2020_2],
            id="JWK_DICT",
        ),
    ],
)
def test_create_numalgo_2_positive(encryption_keys, signing_keys):
    service = """[
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            },
            {
                "type": "example",
                "serviceEndpoint": "https://example.com/endpoint2",
                "routingKeys": ["did:example:somemediator#somekey2"],
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
            }
            ]
            """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert (
        peer_did_algo_2
        == "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0"
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_not_array():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            }
            """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_minimal_fields():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint"
            }
            """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_1_element_array():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            }
        ]
            """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


@pytest.mark.parametrize(
    "encryption_keys, signing_keys",
    [
        pytest.param(
            [],
            [
                VALID_ED25519_VERIFICATION_KEY_2018_1,
                VALID_ED25519_VERIFICATION_KEY_2018_2,
            ],
            id="BASE58",
        ),
        pytest.param(
            [],
            [
                VALID_ED25519_VERIFICATION_KEY_2020_1,
                VALID_ED25519_VERIFICATION_KEY_2020_2,
            ],
            id="MULTIBASE",
        ),
        pytest.param(
            [],
            [VALID_AUTH_JSON_WEB_KEY_2020_1, VALID_AUTH_JSON_WEB_KEY_2020_2],
            id="JWK",
        ),
    ],
)
def test_create_numalgo_2_without_encryption_keys(encryption_keys, signing_keys):
    service = VALID_SERVICE

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert (
        peer_did_algo_2
        == "did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
    )
    assert is_peer_did(peer_did_algo_2)


@pytest.mark.parametrize(
    "encryption_keys, signing_keys",
    [
        pytest.param([VALID_X25519_KEY_AGREEMENT_KEY_2019], [], id="BASE58"),
        pytest.param([VALID_X25519_KEY_AGREEMENT_KEY_2020], [], id="MULTIBASE"),
        pytest.param([VALID_AGREEM_JSON_WEB_KEY_2020_JSON], [], id="JWK"),
    ],
)
def test_create_numalgo_2_without_signing_keys(encryption_keys, signing_keys):
    service = VALID_SERVICE

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert (
        peer_did_algo_2
        == "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
    )
    assert is_peer_did(peer_did_algo_2)


@pytest.mark.parametrize(
    "encryption_keys, signing_keys",
    [
        pytest.param(
            [
                VerificationMaterialAgreement(
                    value="....",
                    type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                    format=VerificationMaterialFormat.BASE58,
                )
            ],
            [
                VALID_ED25519_VERIFICATION_KEY_2018_1,
                VALID_ED25519_VERIFICATION_KEY_2018_2,
            ],
            id="BASE58",
        ),
        pytest.param(
            [
                VerificationMaterialAgreement(
                    value="z....",
                    type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                    format=VerificationMaterialFormat.MULTIBASE,
                )
            ],
            [
                VALID_ED25519_VERIFICATION_KEY_2020_1,
                VALID_ED25519_VERIFICATION_KEY_2020_2,
            ],
            id="MULTIBASE",
        ),
    ],
)
def test_create_numalgo_2_wrong_encryption_key_base58(encryption_keys, signing_keys):
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid base58 encoding"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_wrong_jwk():
    encryption_keys = [
        VerificationMaterialAgreement(
            value={"kty": "OKP", "crv": "X25519", "x": "..."},
            type=VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
            format=VerificationMaterialFormat.JWK,
        )
    ]
    signing_keys = [VALID_AUTH_JSON_WEB_KEY_2020_1, VALID_AUTH_JSON_WEB_KEY_2020_2]
    service = VALID_SERVICE
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_wrong_signing_key():
    encryption_keys = [
        VerificationMaterialAgreement(
            value="6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    signing_keys = [
        VerificationMaterialAuthentication(
            value=".......",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        ),
        VerificationMaterialAuthentication(
            value="zx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        ),
    ]
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_wrong_service():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = "......."

    with pytest.raises(ValueError, match=r"Service is not a valid JSON"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_encryption_key_as_signing():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    service = VALID_SERVICE
    with pytest.raises(TypeError, match=r"Invalid verification material type"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys,
            signing_keys=encryption_keys,
            service=service,
        )


def test_create_numalgo_2_signing_key_as_encryption():
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = VALID_SERVICE
    with pytest.raises(TypeError, match=r"Invalid verification material type"):
        create_peer_did_numalgo_2(
            encryption_keys=signing_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_service_is_None():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = None

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert (
        peer_did_algo_2
        == "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_encryption_and_signing_keys_are_1_element_array():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [VALID_ED25519_VERIFICATION_KEY_2018_1]
    service = VALID_SERVICE

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_encryption_and_signing_keys_are_more_than_1_element_array():
    encryption_keys = [
        VALID_X25519_KEY_AGREEMENT_KEY_2019,
        VALID_X25519_KEY_AGREEMENT_KEY_2020,
        VALID_AGREEM_JSON_WEB_KEY_2020_DICT,
    ]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2020_2,
    ]
    service = VALID_SERVICE

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_has_more_fields_than_in_conversion_table():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        "example1": "myExample1",
        "example2": "myExample2"
        }
        """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_not_didcommmessaging():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
        "type": "example1",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_empty_string():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = ""

    with pytest.raises(ValueError, match=r"Service is not a valid JSON"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_service_is_empty_array():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = []

    with pytest.raises(ValueError, match=r"Service is not a valid JSON"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_different_types_of_service():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """
        [
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
        """

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_malformed_encryption_key_not_base58_encoded():
    encryption_keys = [
        VerificationMaterialAgreement(
            value="JhNWeSVLMYcc0k7iopQW4guaSJTojqpMEELgSLhKwRr",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            """
    with pytest.raises(ValueError, match=r"Invalid base58 encoding"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_short_encryption_key():
    encryption_keys = [
        VerificationMaterialAgreement(
            value="JhNWeSV",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            """
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_long_encryption_key():
    encryption_keys = [
        VerificationMaterialAgreement(
            value="JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            """
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_encryption_key_empty():
    encryption_keys = [
        VerificationMaterialAgreement(
            value="",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = """{
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
            }
            """
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_invalid_encryption_key_type():
    encryption_keys = [VALID_ED25519_VERIFICATION_KEY_2018_1]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = VALID_SERVICE

    with pytest.raises(TypeError, match=r"Invalid verification material type"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_signing_key_not_base58_encoded():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VerificationMaterialAuthentication(
            value="3M5RCDjPTWPkKSN3sxU0mMqHbmRPegYP1tjcKyrDbt9J",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid base58 encoding"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_short_signing_key():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VerificationMaterialAuthentication(
            value="ByHnpUCF",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_long_signing_key():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VerificationMaterialAuthentication(
            value="3M5RCDjxUmmMqHbmRPegYPPTWPkKSN3sxUmmMqHbmRPegYPxUmmMqHbmRPegYP1tjcKxUmmMqHbmRPegYPyrDbt9J",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_malformed_empty_signing_key():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VerificationMaterialAuthentication(
            value="",
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    service = VALID_SERVICE

    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_invalid_inception_key_type():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VerificationMaterialAgreement(
            value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
        )
    ]
    service = VALID_SERVICE

    with pytest.raises(TypeError, match=r"Invalid verification material type"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )
