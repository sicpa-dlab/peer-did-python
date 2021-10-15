import json

import pytest

from peerdid.peer_did import create_peer_did_numalgo_0, is_peer_did
from peerdid.types import (
    VerificationMaterialAuthentication,
    VerificationMethodTypeAuthentication,
    VerificationMaterialFormatPeerDID,
    VerificationMaterialAgreement,
    VerificationMethodTypeAgreement,
)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            VerificationMaterialAuthentication(
                value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value="z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
            ),
            id="ED25519_VERIFICATION_KEY_2020_MULTIBASE",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value={
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                },
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK_DICT",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value=json.dumps(
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                    }
                ),
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
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
            VerificationMaterialAuthentication(
                value="x8xB2pv7cw8q1Pd0DacS",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value="zx8xB2pv7cw8q1Pd0DacS",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
            ),
            id="ED25519_VERIFICATION_KEY_2020_MULTIBASE",
        ),
    ],
)
def test_create_numalgo_0_malformed_inception_key_not_base58_encoded(ver_material):
    with pytest.raises(ValueError, match=r"Invalid key: Invalid base58 encoding"):
        create_peer_did_numalgo_0(inception_key=ver_material)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            VerificationMaterialAuthentication(
                value="ByHnp",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value="zByHnp",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
            ),
            id="ED25519_VERIFICATION_KEY_2020_MULTIBASE",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value={"kty": "OKP", "crv": "Ed25519", "x": "owBhCbktDjkfS6"},
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK_DICT",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value=json.dumps({"kty": "OKP", "crv": "Ed25519", "x": "owBhCbktDjkf"}),
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK_JSON",
        ),
    ],
)
def test_create_numalgo_0_malformed_short_inception_key(ver_material):
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_0(inception_key=ver_material)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            VerificationMaterialAuthentication(
                value="ByHnpUCFb1vAfh9CFZ8ByHnpUCFbZkmUZguURW8HnpUCFbZkmUnByHnpUCFbSHnpUCFbZkmUw889hByHnpUCFby6rD8L7",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value="zByHnpUCFb1vAfh9CFZ8ByHnpUCFbZkmUZguURW8HnpUCFbZkmUnByHnpUCFbSHnpUCFbZkmUw889hByHnpUCFby6rD8L7",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
            ),
            id="ED25519_VERIFICATION_KEY_2020_MULTIBASE",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value={
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6",
                },
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK_DICT",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value=json.dumps(
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6owBhCbktDjkfS6",
                    }
                ),
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK_JSON",
        ),
    ],
)
def test_create_numalgo_0_malformed_long_inception_key(ver_material):
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_0(inception_key=ver_material)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            VerificationMaterialAuthentication(
                value="",
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="ED25519_VERIFICATION_KEY_2018_BASE58",
        ),
        pytest.param(
            VerificationMaterialAuthentication(
                value={"kty": "OKP", "crv": "Ed25519", "x": ""},
                type=VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK",
        ),
    ],
)
def test_create_numalgo_0_malformed_empty_inception_key(ver_material):
    with pytest.raises(ValueError, match=r"Invalid key"):
        create_peer_did_numalgo_0(inception_key=ver_material)


def test_create_numalgo_0_malformed_empty_inception_key_multibase():
    ver_material = VerificationMaterialAuthentication(
        value="",
        type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
        format=VerificationMaterialFormatPeerDID.MULTIBASE,
    )
    with pytest.raises(
        ValueError, match=r"Invalid key: No transform part in multibase encoding"
    ):
        create_peer_did_numalgo_0(inception_key=ver_material)


@pytest.mark.parametrize(
    "ver_material",
    [
        pytest.param(
            VerificationMaterialAgreement(
                value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format=VerificationMaterialFormatPeerDID.BASE58,
            ),
            id="X25519_KEY_AGREEMENT_KEY_2019_BASE58",
        ),
        pytest.param(
            VerificationMaterialAgreement(
                value="z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
            ),
            id="X25519_KEY_AGREEMENT_KEY_2019_MILTIBASE",
        ),
        pytest.param(
            VerificationMaterialAgreement(
                value={
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                },
                type=VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
                format=VerificationMaterialFormatPeerDID.JWK,
            ),
            id="JSON_WEB_KEY_2020_JWK",
        ),
    ],
)
def test_create_numalgo_0_invalid_inception_key_type(ver_material):
    with pytest.raises(TypeError, match=r"Invalid verification material type"):
        create_peer_did_numalgo_0(inception_key=ver_material)
