import json

import pytest

from peerdid.dids import create_peer_did_numalgo_0, is_peer_did
from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            Ed25519VerificationKey.from_base58(
                "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            Ed25519VerificationKey.from_multibase(
                "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ),
            id="ED25519_VERIFICATION_KEY_2020_MULTIBASE",
        ),
        pytest.param(
            Ed25519VerificationKey.from_jwk(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                },
            ),
            id="JSON_WEB_KEY_2020_JWK_DICT",
        ),
        pytest.param(
            Ed25519VerificationKey.from_jwk(
                json.dumps(
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                    }
                )
            ),
            id="JSON_WEB_KEY_2020_JWK_JSON",
        ),
    ],
)
def test_create_numalgo_0_positive(ver_material):
    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=ver_material)
    assert (
        peer_did_algo_0 == "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    )
    assert is_peer_did(peer_did_algo_0)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            X25519KeyAgreementKey.from_base58(
                "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            ),
            id="X25519_KEY_AGREEMENT_KEY_2019_BASE58",
        ),
        pytest.param(
            X25519KeyAgreementKey.from_multibase(
                "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            ),
            id="X25519_KEY_AGREEMENT_KEY_2019_MULTIBASE",
        ),
        pytest.param(
            X25519KeyAgreementKey.from_jwk(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                }
            ),
            id="JSON_WEB_KEY_2020_JWK",
        ),
    ],
)
def test_create_numalgo_0_invalid_inception_key_type(ver_material):
    with pytest.raises(ValueError, match=r"Authentication not supported for key"):
        create_peer_did_numalgo_0(inception_key=ver_material)
