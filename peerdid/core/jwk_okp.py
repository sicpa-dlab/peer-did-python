import json

from peerdid.core.utils import urlsafe_b64encode, urlsafe_b64decode
from peerdid.errors import MalformedPeerDIDDocError
from peerdid.types import (
    VerificationMethodTypePeerDID,
    VerificationMethodTypeAgreement,
    VerificationMethodTypeAuthentication,
    VerificationMaterialPeerDID,
    VerificationMaterialAuthentication,
    VerificationMaterialAgreement,
)


def public_key_to_jwk_dict(
    public_key: bytes, ver_method_type: VerificationMethodTypePeerDID
):
    x = urlsafe_b64encode(public_key).decode("utf-8")

    if ver_method_type == VerificationMethodTypeAgreement.JSON_WEB_KEY_2020:
        crv = "X25519"
    elif ver_method_type == VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020:
        crv = "Ed25519"
    else:
        raise ValueError("Unsupported JWK type: " + ver_method_type.value)

    return {
        "kty": "OKP",
        "crv": crv,
        "x": x,
    }


def jwk_key_to_bytes(ver_material: VerificationMaterialPeerDID) -> bytes:
    jwk_dict = (
        json.loads(ver_material.value)
        if isinstance(ver_material.value, str)
        else ver_material.value
    )

    if "crv" not in jwk_dict:
        raise ValueError("Invalid JWK key - no 'crv' fields: " + ver_material.value)
    if "x" not in jwk_dict:
        raise ValueError("Invalid JWK key - no 'x' fields: " + ver_material.value)

    crv = jwk_dict["crv"]
    if (
        isinstance(ver_material, VerificationMaterialAuthentication)
        and crv != "Ed25519"
    ):
        raise TypeError(
            "Invalid JWK key type - authentication expected: " + ver_material.value
        )
    if isinstance(ver_material, VerificationMaterialAgreement) and crv != "X25519":
        raise TypeError(
            "Invalid JWK key type - key agreement expected: " + ver_material.value
        )

    value = jwk_dict["x"]
    return urlsafe_b64decode(value.encode())


def get_verification_method_type(jwk_dict: dict) -> VerificationMethodTypePeerDID:
    if "crv" not in jwk_dict:
        raise MalformedPeerDIDDocError("No 'crv' field in JWK {}".format(jwk_dict))
    crv = jwk_dict["crv"]
    return (
        VerificationMethodTypeAgreement.JSON_WEB_KEY_2020
        if crv == "X25519"
        else VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
    )
