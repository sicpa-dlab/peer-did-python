import pytest

from peerdid.peer_did import resolve_peer_did


def test_resolve_unsupported_did_method():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:key:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V')


def test_resolve_invalid_peer_did():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:peer:0z6MkqRYqQiSBytw86Qbs2ZWUkGv22od935YF4s8M7V')


def test_resolve_unsupported_numalgo_code():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:peer:1z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V')


def test_resolve_numalgo_0_malformed_base58_encoding():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:peer:0z6MkqRYqQiSgvZQd0Bytw86Qbs2ZWUkGv22od935YF4s8M7V')


def test_resolve_numalgo_0_unsupported_transform_code():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:peer:0a6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V')


def test_resolve_numalgo_0_malformed_multicodec_encoding():
    with pytest.raises(ValueError):
        print(resolve_peer_did(peer_did='did:peer:0z6666RYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'))


def test_resolve_numalgo_0_invalid_key_type():
    with pytest.raises(ValueError):
        resolve_peer_did(peer_did='did:peer:0z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc')
