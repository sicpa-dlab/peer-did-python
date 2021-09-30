from enum import Enum
from typing import NamedTuple, Union, Dict, List, Optional

from peerdid.core.utils import _urlsafe_b64encode


class VerificationMaterialTypeAgreement(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    X25519_KEY_AGREEMENT_KEY_2019 = "X25519KeyAgreementKey2019"
    X25519_KEY_AGREEMENT_KEY_2020 = "X25519KeyAgreementKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


class VerificationMaterialTypeAuthentication(Enum):
    JSON_WEB_KEY_2020 = "JsonWebKey2020"
    ED25519_VERIFICATION_KEY_2018 = "Ed25519VerificationKey2018"
    ED25519_VERIFICATION_KEY_2020 = "Ed25519VerificationKey2020"

    @classmethod
    def values(cls):
        return [e.value for e in cls]


VerificationMaterialType = Union[
    VerificationMaterialTypeAgreement, VerificationMaterialTypeAuthentication
]


class PublicKeyField(Enum):
    BASE58 = "publicKeyBase58"
    MULTIBASE = "publicKeyMultibase"
    JWK = "publicKeyJwk"


VerificationMaterial = NamedTuple(
    "VerificationMaterial",
    [
        ("field", PublicKeyField),
        ("type", VerificationMaterialType),
        ("value", Union[str, Dict]),
        ("encnumbasis", str),
    ],
)


class VerificationMethod:
    def __init__(self, ver_material: VerificationMaterial, did: str):
        self.ver_material = ver_material
        self.did = did

    def to_dict(self):
        return {
            "id": self.did + "#" + self.ver_material.encnumbasis,
            "type": self.ver_material.type.value,
            "controller": self.did,
            self.ver_material.field.value: self.ver_material.value,
        }


class JWK_OKP:
    def __init__(self, ver_material_type: VerificationMaterialType, value: bytes):
        self.x = _urlsafe_b64encode(value).decode("utf-8")
        if ver_material_type == VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020:
            self.crv = "X25519"
        elif (
            ver_material_type
            == VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020
        ):
            self.crv = "Ed25519"
        else:
            raise ValueError("Unsupported JWK type: " + ver_material_type.value)

    def to_dict(self):
        return {
            "kty": "OKP",
            "crv": self.crv,
            "x": self.x,
        }


class DIDDoc:
    def __init__(
        self,
        did: str,
        authentication: List[VerificationMethod],
        key_agreement: Optional[List[VerificationMethod]] = None,
        service: Optional[List[Dict]] = None,
    ):
        self.authentication = authentication
        self.did = did
        self.key_agreement = key_agreement
        self.service = service

    def to_dict(self):
        res = {}
        res["id"] = self.did
        res["authentication"] = [a.to_dict() for a in self.authentication]
        if self.key_agreement is not None:
            res["keyAgreement"] = [ka.to_dict() for ka in self.key_agreement]
        if self.service is not None:
            res["service"] = self.service
        return res
