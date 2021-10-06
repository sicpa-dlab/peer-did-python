import json

from peerdid.types import (
    VerificationMaterialAuthentication,
    VerificationMaterialAgreement,
)


def validate_verification_material_authentication(ver_material):
    if not isinstance(ver_material, VerificationMaterialAuthentication):
        raise TypeError(
            "Invalid verification material type: {} instead of VerificationMaterialAuthentication".format(
                str(type(ver_material))
            )
        )


def validate_verification_material_agreement(ver_material):
    if not isinstance(ver_material, VerificationMaterialAgreement):
        raise TypeError(
            "Invalid verification material type: {} instead of VerificationMaterialAgreement".format(
                str(type(ver_material))
            )
        )


def validate_service_json(str_to_check: str):
    """
    Checks if str is JSON
    :param str_to_check: string to check
    :raises ValueError: if str_to_check is not valid JSON
    """
    try:
        if str_to_check is not None:
            json.loads(str_to_check)
    except (TypeError, ValueError) as ex:
        raise ValueError("Service is not a valid JSON") from ex


def validate_raw_key_length(key: bytes):
    # for all supported key types now (ED25519 and X25510) the expected size is 32
    if len(key) != 32:
        raise ValueError("Invalid key " + str(key))
