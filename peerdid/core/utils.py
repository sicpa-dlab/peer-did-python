import base64
import hashlib


def urlsafe_b64encode(s: bytes) -> bytes:
    """
    Base 64 URL safe encoding with no padding.
    :param s: input str to be encoded
    :return: encoded bytes
    """
    try:
        return base64.urlsafe_b64encode(s).rstrip(b"=")
    except Exception as e:
        raise ValueError("Can not encode from base64 URL safe: " + str(s)) from e


def urlsafe_b64decode(s: bytes) -> bytes:
    """
    Base 64 URL safe decoding with no padding.
    :param s: input bytes to be decoded
    :return: decoded bytes
    """
    try:
        s += b"=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    except Exception as e:
        raise ValueError("Can not decode base64 URL safe: " + str(s)) from e


def encode_filename(filename: str) -> str:
    """
    Encodes filename to SHA256 string
    :param filename: name of file
    :return: encoded filename as SHA256 string
    """
    return hashlib.sha256(filename.encode()).hexdigest()
