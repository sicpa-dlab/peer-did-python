import json
import pytest

from peerdid.peer_did import create_peer_did_numalgo_0, is_peer_did, resolve_peer_did
from peerdid.types import PublicKeyAuthentication, PublicKeyTypeAuthentication, PublicKeyAgreement, \
    PublicKeyTypeAgreement


def test_create_numalgo_0_positive():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    assert peer_did_algo_0 == "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    assert is_peer_did(peer_did_algo_0)


def test_create_numalgo_0_malformed_inception_key_not_base58_encoded():
    inception_key = PublicKeyAuthentication(
        encoded_value="zx8xB2pv7cw8q1Pd0DacS",
        type=PublicKeyTypeAuthentication.ED25519)

    with pytest.raises(ValueError):
        peer_did = create_peer_did_numalgo_0(inception_key=inception_key)


def test_create_numalgo_0_malformed_short_inception_key():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnp",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    assert not is_peer_did(peer_did_algo_0)


def test_create_numalgo_0_malformed_long_inception_key():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ByHnpUCFbZkmUZguURW8HnpUCFbZkmUnByHnpUCFbSHnpUCFbZkmUw889hByHnpUCFby6rD8L7",
        type=PublicKeyTypeAuthentication.ED25519)]

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    assert not is_peer_did(peer_did_algo_0)


def test_create_numalgo_0_malformed_empty_inception_key():
    signing_keys = [PublicKeyAuthentication(
        encoded_value="",
        type=PublicKeyTypeAuthentication.ED25519)]

    with pytest.raises(ValueError):
        peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])


def test_create_numalgo_0_invalid_inception_key_type():
    signing_keys = [PublicKeyAgreement(
        encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type=PublicKeyTypeAgreement.X25519)]

    with pytest.raises(TypeError):
        peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])


def test_resolve_numalgo_0_positive():
    assert json.loads(resolve_peer_did('did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V')) \
           == \
           json.loads('''{
    "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
    "authentication": {
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "type": "ED25519",
        "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
    }
}''')
