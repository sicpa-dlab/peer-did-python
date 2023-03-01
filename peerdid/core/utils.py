"""Utility methods."""

import base64

from typing import Union


def urlsafe_b64encode(s: Union[str, bytes]) -> bytes:
    """
    Base64 URL-safe encoding with no padding.

    :param s: input str to be encoded
    :return: encoded bytes
    """
    if isinstance(s, str):
        s = s.encode("utf-8")
    try:
        return base64.urlsafe_b64encode(s).rstrip(b"=")
    except Exception as e:
        raise ValueError("Can not encode from base64 URL safe: " + str(s)) from e


def urlsafe_b64decode(s: Union[str, bytes]) -> bytes:
    """
    Base64 URL-safe decoding with no padding.

    :param s: input bytes to be decoded
    :return: decoded bytes
    """
    if isinstance(s, str):
        s = s.encode("utf-8")
    try:
        s += b"=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    except Exception as e:
        raise ValueError("Can not decode base64 URL safe: " + str(s)) from e
