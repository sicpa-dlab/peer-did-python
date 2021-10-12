import json

import pytest

from peerdid.core.did_doc_types import (
    VerificationMethodField,
    DIDCommServicePeerDID,
)
from peerdid.did_doc import DIDDocPeerDID
from peerdid.errors import MalformedPeerDIDDocError
from peerdid.types import (
    VerificationMaterialFormatPeerDID,
    VerificationMethodTypeAuthentication,
    VerificationMethodTypeAgreement,
)
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
    "did_doc_json, expected_format, expected_field, expected_type",
    [
        pytest.param(
            DID_DOC_NUMALGO_O_BASE58,
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMethodField.BASE58,
            VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            id="numalgo_0_base58",
        ),
        pytest.param(
            DID_DOC_NUMALGO_O_MULTIBASE,
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMethodField.MULTIBASE,
            VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
            id="numalgo_0_multibase",
        ),
        pytest.param(
            DID_DOC_NUMALGO_O_JWK,
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMethodField.JWK,
            VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
            id="numalgo_0_jwk",
        ),
    ],
)
def test_did_doc_from_json_numalgo_0(
    did_doc_json, expected_format, expected_field, expected_type
):
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
    assert auth.ver_material.type == expected_type
    assert auth.ver_material.value == expected_auth[expected_field.value]

    assert did_doc.auth_kids == [expected_auth["id"]]
    assert did_doc.agreement_kids == []


@pytest.mark.parametrize(
    "did_doc_json, expected_format, expected_field, expected_auth_type, expected_agreem_type",
    [
        pytest.param(
            DID_DOC_NUMALGO_2_BASE58,
            VerificationMaterialFormatPeerDID.BASE58,
            VerificationMethodField.BASE58,
            VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            id="numalgo_2_base58",
        ),
        pytest.param(
            DID_DOC_NUMALGO_2_MULTIBASE,
            VerificationMaterialFormatPeerDID.MULTIBASE,
            VerificationMethodField.MULTIBASE,
            VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
            VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
            id="numalgo_2_multibase",
        ),
        pytest.param(
            DID_DOC_NUMALGO_2_JWK,
            VerificationMaterialFormatPeerDID.JWK,
            VerificationMethodField.JWK,
            VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
            VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
            id="numalgo_2_jwk",
        ),
    ],
)
def test_did_doc_from_json_numalgo_2(
    did_doc_json,
    expected_format,
    expected_field,
    expected_auth_type,
    expected_agreem_type,
):
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
    assert auth.ver_material.type == expected_auth_type
    assert auth.ver_material.value == expected_auth[expected_field.value]

    agreement = did_doc.key_agreement[0]
    expected_agreement = json.loads(did_doc_json)["keyAgreement"][0]
    assert agreement.id == expected_agreement["id"]
    assert agreement.controller == PEER_DID_NUMALGO_2
    assert agreement.ver_material.format == expected_format
    assert agreement.ver_material.type == expected_agreem_type
    assert agreement.ver_material.value == expected_agreement[expected_field.value]

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

    assert did_doc.auth_kids == [
        v["id"] for v in json.loads(did_doc_json)["authentication"]
    ]
    assert did_doc.agreement_kids == [expected_agreement["id"]]


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


def test_did_doc_id_only():
    didDoc = DIDDocPeerDID.from_json(
        """
   {
       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
   }
            """
    )
    assert didDoc.did == "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"


def test_did_doc_invalid_json():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*Invalid JSON",
    ):
        DIDDocPeerDID.from_json(
            """
            sdfasdfsf{sdfsdfasdf...
            """
        )


def test_did_doc_from_invalid_json_no_id():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No 'id' field",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_no_id():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No 'id' field in method",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_no_type():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No 'type' field in method",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_no_controller():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No 'controller' field in method",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_no_value():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No public key field",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_invalid_type():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*Unknown verification method type",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Unkknown",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_invalid_field():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No public key field",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyJwk": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
                """
        )


def test_did_doc_from_invalid_ver_method_invalid_value_jwk():
    with pytest.raises(
        MalformedPeerDIDDocError,
        match=r"Invalid peer DID Doc.*No 'crv' field in JWK",
    ):
        DIDDocPeerDID.from_json(
            """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "JsonWebKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyJwk": "sdfsdf{sfsdfdf"
                           }
                       ]
                   }
                """
        )
