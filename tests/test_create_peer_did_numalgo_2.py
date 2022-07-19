import pytest

from peerdid.peer_did import create_peer_did_numalgo_2, is_peer_did
from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey

VALID_X25519_KEY_AGREEMENT_KEY_2019 = X25519KeyAgreementKey.from_base58(
    "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
)
VALID_X25519_KEY_AGREEMENT_KEY_2020 = X25519KeyAgreementKey.from_multibase(
    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
)
VALID_X25519_KEY_AGREEMENT_KEY_JWK = X25519KeyAgreementKey.from_jwk(
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
    }
)

VALID_ED25519_VERIFICATION_KEY_2018_1 = Ed25519VerificationKey.from_base58(
    "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
)
VALID_ED25519_VERIFICATION_KEY_2020_1 = Ed25519VerificationKey.from_multibase(
    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
)
VALID_ED25519_VERIFICATION_KEY_JWK_1 = Ed25519VerificationKey.from_jwk(
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
    },
)

VALID_ED25519_VERIFICATION_KEY_2018_2 = Ed25519VerificationKey.from_base58(
    "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J"
)
VALID_ED25519_VERIFICATION_KEY_2020_2 = Ed25519VerificationKey.from_multibase(
    "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
)
VALID_ED25519_VERIFICATION_KEY_JWK_2 = Ed25519VerificationKey.from_jwk(
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "Itv8B__b1-Jos3LCpUe8EdTFGTCa_Dza6_3848P3R70",
    }
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
            [VALID_X25519_KEY_AGREEMENT_KEY_JWK],
            [
                VALID_ED25519_VERIFICATION_KEY_JWK_1,
                VALID_ED25519_VERIFICATION_KEY_JWK_2,
            ],
            id="JWK",
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
            [
                VALID_ED25519_VERIFICATION_KEY_JWK_1,
                VALID_ED25519_VERIFICATION_KEY_JWK_2,
            ],
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
        pytest.param([VALID_X25519_KEY_AGREEMENT_KEY_JWK], [], id="JWK"),
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


def test_create_numalgo_2_wrong_service():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = "......."

    with pytest.raises(ValueError, match=r"Service is not valid JSON"):
        create_peer_did_numalgo_2(
            encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_encryption_key_as_signing():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    service = VALID_SERVICE
    with pytest.raises(ValueError, match=r"Authentication not supported for key"):
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
    with pytest.raises(ValueError, match=r"Key agreement not supported for key"):
        create_peer_did_numalgo_2(
            encryption_keys=signing_keys, signing_keys=signing_keys, service=service
        )


def test_create_numalgo_2_service_is_none():
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
        VALID_X25519_KEY_AGREEMENT_KEY_JWK,
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

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


def test_create_numalgo_2_service_is_empty_array():
    encryption_keys = [VALID_X25519_KEY_AGREEMENT_KEY_2019]
    signing_keys = [
        VALID_ED25519_VERIFICATION_KEY_2018_1,
        VALID_ED25519_VERIFICATION_KEY_2018_2,
    ]
    service = []

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )
    assert is_peer_did(peer_did_algo_2)


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
