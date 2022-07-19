"""JWK utility methods."""

import json

from typing import Tuple, Union

from .multicodec import Codec
from .utils import urlsafe_b64encode, urlsafe_b64decode


def public_key_to_jwk(public_key: bytes, codec: Codec) -> dict:
    x = urlsafe_b64encode(public_key).decode("utf-8")

    if codec == Codec.ED25519:
        crv = "Ed25519"
    elif codec == Codec.X25519:
        crv = "X25519"
    else:
        raise ValueError("Unsupported JWK codec: {}".format(codec))

    return {
        "kty": "OKP",
        "crv": crv,
        "x": x,
    }


def jwk_to_public_key(jwk: Union[str, dict]) -> Tuple[bytes, Codec]:
    parts = {}
    try:
        if isinstance(jwk, str):
            parts = json.loads(jwk)
        elif isinstance(jwk, dict):
            parts = jwk
    except json.JSONDecodeError:
        pass

    kty = parts.pop("kty", None)
    crv = parts.pop("crv", None)
    x = parts.pop("x", None)
    if not (
        kty
        and isinstance(kty, str)
        and crv
        and isinstance(crv, str)
        and x
        and isinstance(x, str)
    ):
        raise ValueError("Invalid JWK: {}".format(jwk))

    try:
        public_key = urlsafe_b64decode(x)
    except ValueError as e:
        raise ValueError("Invalid JWK: {}".format(jwk)) from e

    if crv == "Ed25519":
        codec = Codec.ED25519
    elif crv == "X25519":
        codec = Codec.X25519
    else:
        raise ValueError("Unsupported JWK codec: {}".format(crv))

    return public_key, codec
