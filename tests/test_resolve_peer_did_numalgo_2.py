import json

import pytest

from peerdid.errors import MalformedPeerDIDError
from peerdid.peer_did import resolve_peer_did
from peerdid.types import VerificationMaterialFormatPeerDID
from tests.test_vectors import (
    DID_DOC_NUMALGO_2_BASE58,
    PEER_DID_NUMALGO_2,
    DID_DOC_NUMALGO_2_MULTIBASE,
    DID_DOC_NUMALGO_2_JWK,
    DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES,
    PEER_DID_NUMALGO_2_NO_SERVICES,
    DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES,
    PEER_DID_NUMALGO_2_2_SERVICES,
    DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES,
    PEER_DID_NUMALGO_2_MINIMAL_SERVICES,
)


def test_resolve_numalgo_2_positive_default():
    did_doc = resolve_peer_did(peer_did=PEER_DID_NUMALGO_2)
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_MULTIBASE)


def test_resolve_numalgo_2_positive_base58():
    did_doc = resolve_peer_did(
        peer_did=PEER_DID_NUMALGO_2, format=VerificationMaterialFormatPeerDID.BASE58
    )
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_BASE58)


def test_resolve_numalgo_2_positive_multibase():
    did_doc = resolve_peer_did(
        peer_did=PEER_DID_NUMALGO_2, format=VerificationMaterialFormatPeerDID.MULTIBASE
    )
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_MULTIBASE)


def test_resolve_numalgo_2_positive_jwk():
    did_doc = resolve_peer_did(
        peer_did=PEER_DID_NUMALGO_2, format=VerificationMaterialFormatPeerDID.JWK
    )
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_JWK)


def test_resolve_numalgo_2_positive_service_is_2_element_array():
    did_doc = resolve_peer_did(PEER_DID_NUMALGO_2_2_SERVICES)
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)


def test_resolve_numalgo_2_positive_no_service():
    did_doc = resolve_peer_did(PEER_DID_NUMALGO_2_NO_SERVICES)
    assert json.loads(did_doc) == json.loads(DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES)


def test_resolve_numalgo_2_positive_minimal_service():
    did_doc = resolve_peer_did(PEER_DID_NUMALGO_2_MINIMAL_SERVICES)
    assert json.loads(did_doc) == json.loads(
        DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES
    )


def test_resolve_numalgo_2_unsupported_transform_code():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2.Ea6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Va6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_signing_malformed_base58_encoding():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkqRYqQiSgvZQdnBytw86Qbs0ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_encryption_malformed_base58_encoding():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2.Ez6LSbysY2xFMRpG0hb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_signing_malformed_multicodec_encoding():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6666YqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_encryption_malformed_multicodec_encoding():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            "did:peer:2.Ez7777sY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_signing_invalid_key_type():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            "did:peer:2.Vz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_encryption_invalid_key_type():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid key"
    ):
        resolve_peer_did(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_malformed_service_encoding():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2"
            + ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            + ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly\\9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
        )


def test_resolve_numalgo_2_malformed_service():
    with pytest.raises(
        MalformedPeerDIDError, match=r"Invalid peer DID provided.*Invalid service"
    ):
        resolve_peer_did(
            "did:peer:2"
            + ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            + ".Sasdf123"
        )


def test_resolve_numalgo_2_invalid_prefix():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2"
            ".Cz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_short_signing_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            ".Vz6MkqRYqQiS"
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
        )


def test_resolve_numalgo_2_short_encryption_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2"
            + ".Ez6LSbysY2"
            + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            + ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0"
        )


def test_resolve_numalgo_2_long_signing_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2"
            + ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7Vcccccccccc"
            + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            + ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0"
        )


def test_resolve_numalgo_2_long_encryption_key():
    with pytest.raises(
        MalformedPeerDIDError,
        match=r"Invalid peer DID provided.*Does not match peer DID regexp",
    ):
        resolve_peer_did(
            "did:peer:2"
            + ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCcccccccc"
            + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            + ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0"
        )
