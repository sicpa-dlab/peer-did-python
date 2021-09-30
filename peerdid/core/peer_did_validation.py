from typing import List, Optional

from peerdid.core.peer_did_helper import _check_key_correctly_encoded
from peerdid.core.utils import _validate_json
from peerdid.types import PublicKeyAuthentication, PublicKeyAgreement, JSON


def _validate_create_peer_did_numalgo_0_input(inception_key):
    if not isinstance(inception_key, PublicKeyAuthentication):
        raise TypeError(
            "Wrong type of inception_key: {}. Expected: PublicKeyAuthentication".format(
                str(type(inception_key))
            )
        )
    if not _check_key_correctly_encoded(
        inception_key.encoded_value, inception_key.encoding_type
    ):
        raise ValueError("Inception key is not correctly encoded")


def _validate_create_peer_did_numalgo_2_input(
    encryption_keys: List[PublicKeyAgreement],
    signing_keys: List[PublicKeyAuthentication],
    service: Optional[JSON],
):
    for key in encryption_keys:
        if not isinstance(key, PublicKeyAgreement):
            raise TypeError(
                "Wrong type of encryption_key {}: {} ".format(
                    key.encoded_value, str(type(key))
                )
            )
        if not _check_key_correctly_encoded(key.encoded_value, key.encoding_type):
            raise ValueError(
                "Encryption key {}: is not correctly encoded".format(key.encoded_value)
            )
    for key in signing_keys:
        if not isinstance(key, PublicKeyAuthentication):
            raise TypeError(
                "Wrong type of signing_key {}: {} ".format(
                    key.encoded_value, str(type(key))
                )
            )
        if not _check_key_correctly_encoded(key.encoded_value, key.encoding_type):
            raise ValueError(
                "Signing key {}: is not correctly encoded".format(key.encoded_value)
            )
    try:
        if service is not None:
            _validate_json(service)
    except TypeError as exte:
        raise TypeError("Service is not JSON type") from exte
    except ValueError as exve:
        raise ValueError("Service is not valid JSON") from exve
