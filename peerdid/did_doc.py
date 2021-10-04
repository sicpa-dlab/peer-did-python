from __future__ import annotations

import json
from enum import Enum
from typing import List, Optional, Dict, Union, NamedTuple

from peerdid.core.utils import _urlsafe_b64encode
from peerdid.errors import MalformedPeerDIDDocError
from peerdid.types import VerificationMaterialFormatPeerDID, JSON


class DIDDocPeerDID:
    def __init__(
        self,
        did: str,
        authentication: List[VerificationMethodPeerDID],
        key_agreement: Optional[List[VerificationMethodPeerDID]] = None,
        service: Optional[List[ServicePeerDID]] = None,
    ):
        self.authentication = authentication
        self.did = did
        self.key_agreement = key_agreement
        self.service = service

    def to_dict(self) -> dict:
        res = {
            "id": self.did,
            "authentication": [a.to_dict() for a in self.authentication],
        }
        if self.key_agreement is not None:
            res["keyAgreement"] = [ka.to_dict() for ka in self.key_agreement]
        if self.service is not None:
            res["service"] = self.service
        return res

    def to_json(self) -> JSON:
        return json.dumps(self.to_dict(), indent=4)

    @classmethod
    def from_json(cls, value: JSON) -> DIDDocPeerDID:
        """
        Creates a new instance of DIDDocPeerDID from the given DID Doc JSON.
        :param value: DID doc as JSON
        :raises MalformedPeerDIDDocError: if the JSON can not be converted to a valid DID Doc object
        :return: a new instance of DIDDocPeerDID
        """
        did_doc_dict = json.loads(value)
        if "id" not in value:
            raise MalformedPeerDIDDocError("No 'id' field")
        if "authentication" not in value:
            raise MalformedPeerDIDDocError("No 'authentication' field")
        return cls(
            did=did_doc_dict["id"],
            authentication=[
                VerificationMethodPeerDID.from_dict(v)
                for v in did_doc_dict["authentication"]
            ],
            key_agreement=[
                VerificationMethodPeerDID.from_dict(v)
                for v in did_doc_dict.get("keyAgreement", [])
            ],
            service=DIDCommServicePeerDID.from_dict(did_doc_dict.get("service", None)),
        )


class VerificationMethodTypeAgreement(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    X25519_KEY_AGREEMENT_KEY_2019 = "X25519KeyAgreementKey2019"
    X25519_KEY_AGREEMENT_KEY_2020 = "X25519KeyAgreementKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


class VerificationMethodTypeAuthentication(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    ED25519_VERIFICATION_KEY_2018 = "Ed25519VerificationKey2018"
    ED25519_VERIFICATION_KEY_2020 = "Ed25519VerificationKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


VerificationMethodType = Union[
    VerificationMethodTypeAgreement, VerificationMethodTypeAuthentication
]


class VerificationMethodField(Enum):
    BASE58 = "publicKeyBase58"
    MULTIBASE = "publicKeyMultibase"
    JWK = "publicKeyJwk"


VerificationMaterialPeerDID = NamedTuple(
    "VerificationMaterialPeerDID",
    [
        ("format", VerificationMaterialFormatPeerDID),
        ("type", VerificationMethodType),
        ("field", VerificationMethodField),
        ("value", Union[str, Dict]),
        ("encnumbasis", str),
    ],
)

SERVICE_ID = "id"
SERVICE_TYPE = "type"
SERVICE_ENDPOINT = "serviceEndpoint"
SERVICE_DIDCOMM_MESSAGING = "DIDCommMessaging"
SERVICE_ROUTING_KEYS = "routingKeys"
SERVICE_ACCEPT = "accept"


class DIDCommServicePeerDID:
    def __init__(
        self,
        id: str,
        service_endpoint: Optional[str],
        routing_keys: Optional[List[str]],
        accept: Optional[List[str]],
    ) -> None:
        self.id = id
        self.service_endpoint = service_endpoint
        self.routing_keys = routing_keys
        self.accept = accept

    @classmethod
    def from_dict(cls, values: dict) -> List[ServicePeerDID]:
        if not values:
            return values
        if not isinstance(values, list):
            return values

        res = []
        for value in values:
            if SERVICE_ID not in value:
                res.append(value)
                continue
            if SERVICE_TYPE not in value:
                res.append(value)
                continue

            service_type = value[SERVICE_TYPE]
            if service_type != SERVICE_DIDCOMM_MESSAGING:
                res.append(value)
                continue

            res.append(
                DIDCommServicePeerDID(
                    id=value[SERVICE_ID],
                    service_endpoint=value.get(SERVICE_ENDPOINT, None),
                    routing_keys=value.get(SERVICE_ROUTING_KEYS, None),
                    accept=value.get(SERVICE_ACCEPT, None),
                )
            )
        return res


ServicePeerDID = Union[Dict, DIDCommServicePeerDID]


class VerificationMethodPeerDID:
    def __init__(self, did: str, ver_material: VerificationMaterialPeerDID):
        self.did = did
        self.ver_material = ver_material

    @property
    def id(self):
        return self.did + "#" + self.ver_material.encnumbasis

    @property
    def controller(self):
        return self.did

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.ver_material.type.value,
            "controller": self.controller,
            self.ver_material.field.value: self.ver_material.value,
        }

    @classmethod
    def from_dict(cls, value: dict) -> VerificationMethodPeerDID:
        if "id" not in value:
            raise MalformedPeerDIDDocError("No 'id' field in method {}".format(value))
        if "type" not in value:
            raise MalformedPeerDIDDocError("No 'type' field in method {}".format(value))
        ver_method_type = value["type"]
        encnumbasis = value["id"].split("#")[-1]
        did = value["id"].split("#")[0]

        if (
            ver_method_type
            == VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018.value
        ):
            ver_material = _get_ver_material(
                value=value,
                format=VerificationMaterialFormatPeerDID.BASE58,
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                field=VerificationMethodField.BASE58,
                encnumbasis=encnumbasis,
            )

        elif (
            ver_method_type
            == VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020.value
        ):
            ver_material = _get_ver_material(
                value=value,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
                type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                field=VerificationMethodField.MULTIBASE,
                encnumbasis=encnumbasis,
            )

        elif (
            ver_method_type
            == VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019.value
        ):
            ver_material = _get_ver_material(
                value=value,
                format=VerificationMaterialFormatPeerDID.BASE58,
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                field=VerificationMethodField.BASE58,
                encnumbasis=encnumbasis,
            )

        elif (
            ver_method_type
            == VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020.value
        ):
            ver_material = _get_ver_material(
                value=value,
                format=VerificationMaterialFormatPeerDID.MULTIBASE,
                type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                field=VerificationMethodField.MULTIBASE,
                encnumbasis=encnumbasis,
            )

        elif (
            ver_method_type == VerificationMethodTypeAgreement.JSON_WEB_KEY_2020.value
            or ver_method_type
            == VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020.value
        ):
            ver_material = _get_ver_material_jwk(
                value=value,
                format=VerificationMaterialFormatPeerDID.JWK,
                field=VerificationMethodField.JWK,
                encnumbasis=encnumbasis,
            )

        else:
            raise MalformedPeerDIDDocError("Unknown 'type' in method {}".format(value))

        return cls(did=did, ver_material=ver_material)


class JWK_OKP:
    def __init__(self, ver_method_type: VerificationMethodType, value: bytes):
        self.ver_method_type = ver_method_type
        self.value = value

    def to_dict(self):
        x = _urlsafe_b64encode(self.value).decode("utf-8")
        if self.ver_method_type == VerificationMethodTypeAgreement.JSON_WEB_KEY_2020:
            crv = "X25519"
        elif (
            self.ver_method_type
            == VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
        ):
            crv = "Ed25519"
        else:
            raise ValueError("Unsupported JWK type: " + self.ver_method_type.value)
        return {
            "kty": "OKP",
            "crv": crv,
            "x": x,
        }

    @classmethod
    def from_dict(cls, value: dict) -> JWK_OKP:
        if "crv" not in value:
            raise MalformedPeerDIDDocError("No 'crv' field in JWK {}".format(value))
        if "x" not in value:
            raise MalformedPeerDIDDocError("No 'x' field in JWK {}".format(value))
        crv = value["crv"]
        ver_method_type = (
            VerificationMethodTypeAgreement.JSON_WEB_KEY_2020
            if crv == "X25519"
            else VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
        )
        return JWK_OKP(ver_method_type, value["x"])


def _get_ver_material(
    value: dict,
    field: VerificationMethodField,
    format: VerificationMaterialFormatPeerDID,
    type: VerificationMethodType,
    encnumbasis: str,
) -> VerificationMaterialPeerDID:
    if field.value not in value:
        raise MalformedPeerDIDDocError(
            "{} not found in method {}".format(field.value, value)
        )
    return VerificationMaterialPeerDID(
        format=format,
        type=type,
        field=field,
        value=value[field.value],
        encnumbasis=encnumbasis,
    )


def _get_ver_material_jwk(
    value: dict,
    field: VerificationMethodField,
    format: VerificationMaterialFormatPeerDID,
    encnumbasis: str,
) -> VerificationMaterialPeerDID:
    if field.value not in value:
        raise MalformedPeerDIDDocError(
            "{} not found in method {}".format(field.value, value)
        )
    material_type = JWK_OKP.from_dict(value[field.value]).ver_method_type
    return VerificationMaterialPeerDID(
        format=format,
        type=material_type,
        field=field,
        value=value[field.value],
        encnumbasis=encnumbasis,
    )
