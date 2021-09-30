import base64
import json


def _is_json(str_to_check: str) -> bool:
    """
    Checks if str is JSON
    :param str_to_check: sting to check
    :return: true if str is JSON, otherwise raises ValueError or TypeError
    :raises TypeError: if str_to_check is not str type
    :raises ValueError: if str_to_check is not valid JSON
    """
    json.loads(str_to_check)
    return True


def _urlsafe_b64encode(s: bytes):
    """
    Base 64 URL safe encoding with no padding.
    :param s: input str to be encoded
    :return: encoded bytes
    """
    return base64.urlsafe_b64encode(s).rstrip(b"=")


def _urlsafe_b64decode(s: bytes):
    """
    Base 64 URL safe decoding with no padding.
    :param s: input bytes to be decoded
    :return: decoded bytes
    """
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
