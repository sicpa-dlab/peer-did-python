import json

import pytest

from peerdid.did_doc import (
    DIDDocPeerDID,
    VerificationMethodField,
    DIDCommServicePeerDID,
)
from peerdid.types import VerificationMaterialFormatPeerDID
from tests.test_vectors import (
    DID_DOC_NUMALGO_O_BASE58,
    DID_DOC_NUMALGO_O_MULTIBASE,
    DID_DOC_NUMALGO_O_JWK,
    DID_DOC_NUMALGO_2_BASE58,
    DID_DOC_NUMALGO_2_MULTIBASE,
    DID_DOC_NUMALGO_2_JWK,
    PEER_DID_NUMALGO_0,
    PEER_DID_NUMALGO_2,
    DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES,
    PEER_DID_NUMALGO_2_2_SERVICES,
    DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES,
    PEER_DID_NUMALGO_2_NO_SERVICES,
    PEER_DID_NUMALGO_2_MINIMAL_SERVICES,
    DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES,
)


@pytest.mark.parametrize(
    "did_doc_json, expected_format, expected_field",
    [
        pytest.param(
            DID_DOC_NUMALGO_O_BASE58,
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMethodField.BASE58,
            id="numalgo_0_base58",
        ),
        pytest.param(
            DID_DOC_NUMALGO_O_MULTIBASE,
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMethodField.MULTIBASE,
            id="numalgo_0_multibase",
        ),
        pytest.param(
            DID_DOC_NUMALGO_O_JWK,
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMethodField.JWK,
            id="numalgo_0_jwk",
        ),
    ],
)
def test_did_doc_from_json_numalgo_0(did_doc_json, expected_format, expected_field):
    did_doc = DIDDocPeerDID.from_json(did_doc_json)

    assert isinstance(did_doc, DIDDocPeerDID)
    assert did_doc.did == PEER_DID_NUMALGO_0

    assert did_doc.key_agreement == []
    assert did_doc.service is None
    assert len(did_doc.authentication) == 1

    auth = did_doc.authentication[0]
    expected_auth = json.loads(did_doc_json)["authentication"][0]
    assert auth.id == expected_auth["id"]
    assert auth.controller == PEER_DID_NUMALGO_0
    assert auth.ver_material.format == expected_format
    assert auth.ver_material.field == expected_field
    assert auth.ver_material.value == expected_auth[expected_field.value]


@pytest.mark.parametrize(
    "did_doc_json, expected_format, expected_field",
    [
        pytest.param(
            DID_DOC_NUMALGO_2_BASE58,
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMethodField.BASE58,
            id="numalgo_2_base58",
        ),
        pytest.param(
            DID_DOC_NUMALGO_2_MULTIBASE,
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMethodField.MULTIBASE,
            id="numalgo_2_multibase",
        ),
        pytest.param(
            DID_DOC_NUMALGO_2_JWK,
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMethodField.JWK,
            id="numalgo_2_jwk",
        ),
    ],
)
def test_did_doc_from_json_numalgo_2(did_doc_json, expected_format, expected_field):
    did_doc = DIDDocPeerDID.from_json(did_doc_json)

    assert isinstance(did_doc, DIDDocPeerDID)
    assert did_doc.did == PEER_DID_NUMALGO_2

    assert len(did_doc.key_agreement) == 1
    assert len(did_doc.authentication) == 2

    auth = did_doc.authentication[0]
    expected_auth = json.loads(did_doc_json)["authentication"][0]
    assert auth.id == expected_auth["id"]
    assert auth.controller == PEER_DID_NUMALGO_2
    assert auth.ver_material.format == expected_format
    assert auth.ver_material.field == expected_field
    assert auth.ver_material.value == expected_auth[expected_field.value]

    agreement = did_doc.key_agreement[0]
    assert agreement.id == json.loads(did_doc_json)["keyAgreement"][0]["id"]
    assert agreement.controller == PEER_DID_NUMALGO_2
    assert agreement.ver_material.format == expected_format
    assert agreement.ver_material.field == expected_field
    assert (
        agreement.ver_material.value
        == json.loads(did_doc_json)["keyAgreement"][0][expected_field.value]
    )

    services = did_doc.service
    expected_service = json.loads(did_doc_json)["service"][0]
    assert services is not None
    assert len(services) == 1
    service = services[0]
    assert isinstance(service, DIDCommServicePeerDID)
    assert service.id == expected_service["id"]
    assert service.service_endpoint == expected_service["serviceEndpoint"]
    assert service.routing_keys == expected_service["routingKeys"]
    assert service.accept == expected_service["accept"]


def test_did_doc_from_json_numalgo_2_service_2_elements():
    did_doc = DIDDocPeerDID.from_json(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)

    assert isinstance(did_doc, DIDDocPeerDID)
    assert did_doc.did == PEER_DID_NUMALGO_2_2_SERVICES

    services = did_doc.service
    assert services is not None
    assert len(services) == 2

    service_1 = services[0]
    expected_service_1 = json.loads(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)["service"][
        0
    ]
    assert isinstance(service_1, DIDCommServicePeerDID)
    assert service_1.id == expected_service_1["id"]
    assert service_1.service_endpoint == expected_service_1["serviceEndpoint"]
    assert service_1.routing_keys == expected_service_1["routingKeys"]
    assert service_1.accept is None

    service_2 = services[1]
    expected_service_2 = json.loads(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)["service"][
        1
    ]
    assert isinstance(service_2, dict)
    assert service_2 == expected_service_2


def test_did_doc_from_json_numalgo_2_no_service():
    did_doc = DIDDocPeerDID.from_json(DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES)

    assert isinstance(did_doc, DIDDocPeerDID)
    assert did_doc.did == PEER_DID_NUMALGO_2_NO_SERVICES

    assert len(did_doc.key_agreement) == 1
    assert len(did_doc.authentication) == 1
    assert did_doc.service is None


def test_did_doc_from_json_numalgo_2_minimal_service():
    did_doc = DIDDocPeerDID.from_json(DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES)

    assert isinstance(did_doc, DIDDocPeerDID)
    assert did_doc.did == PEER_DID_NUMALGO_2_MINIMAL_SERVICES

    assert len(did_doc.key_agreement) == 1
    assert len(did_doc.authentication) == 2
    assert did_doc.service is not None
    assert len(did_doc.service) == 1

    service = did_doc.service[0]
    expected_service = json.loads(DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES)[
        "service"
    ][0]
    assert isinstance(service, DIDCommServicePeerDID)
    assert service.id == expected_service["id"]
    assert service.service_endpoint == expected_service["serviceEndpoint"]
    assert service.routing_keys is None
    assert service.accept is None
