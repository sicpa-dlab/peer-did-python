"""Peer DID key handling."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, NamedTuple, Type, Union
from uuid import uuid4

from pydid import DID, DIDUrl, VerificationMethod
from pydid.verification_method import (
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
)

from .core.jwk_okp import jwk_to_public_key, public_key_to_jwk
from .core.multibase import (
    MultibaseFormat,
    from_base58,
    from_multibase,
    to_base58,
    to_multibase,
)
from .core.multicodec import Codec, from_multicodec

ED25519_KEY_LENGTH = 32
ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"
X25519_KEY_LENGTH = 32
X25519_2020_CONTEXT = "https://w3id.org/security/suites/x25519-2020/v1"
JWS_2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"


class KeyFormat(Enum):
    """Supported key output formats."""

    JWK = 1
    BASE58 = 2
    MULTIBASE = 3


class KeyRelationshipType(Enum):
    """Supported key relationship types."""

    AUTHENTICATION = 1
    KEY_AGREEMENT = 2


VerificationMethodResult = NamedTuple(
    "VerificationMethodResult",
    [
        ("context", Optional[str]),
        ("method", VerificationMethod),
    ],
)


class BaseKey(ABC):
    """Base class for key types."""

    codec: Codec
    format: KeyFormat
    ident: Optional[Union[str, DIDUrl]] = None
    key_length: Optional[int] = None
    public_key: bytes
    relationships: List[KeyRelationshipType]

    @classmethod
    def for_codec(cls, codec: Codec) -> Type["BaseKey"]:
        """Get the BaseKey subclass for a specific codec and key format."""
        cls_codec = getattr(cls, "codec", None)
        if cls_codec:
            if cls_codec != codec:
                raise ValueError(
                    "Codec mismatch: expected {}, found {}".format(cls_codec, codec)
                )
            return cls

        if codec == Codec.ED25519:
            return Ed25519VerificationKey
        elif codec == Codec.X25519:
            return X25519KeyAgreementKey
        raise ValueError("Unsupported codec")

    @classmethod
    def from_base58(
        cls,
        enc_key: str,
        codec: Codec = None,
        ident: Union[str, DIDUrl] = None,
        format: KeyFormat = None,
    ) -> "BaseKey":
        """Load a base58-encoded key."""
        codec = codec or getattr(cls, "codec", None)
        if not codec:
            raise ValueError("Unspecified codec")
        public_key = from_base58(enc_key)
        key_type_cls = cls.for_codec(codec)
        return key_type_cls(public_key, ident=ident, format=format or KeyFormat.BASE58)

    @classmethod
    def from_multibase(
        cls, multibase: str, ident: Union[str, DIDUrl] = None, format: KeyFormat = None
    ) -> "BaseKey":
        """Load a multibase, multicodec-encoded key."""
        encnumbasis, multicodec = from_multibase(multibase)
        ident = ident or "#" + encnumbasis[:8]
        public_key, codec = from_multicodec(multicodec)
        key_type_cls = cls.for_codec(codec)
        return key_type_cls(
            public_key, ident=ident, format=format or KeyFormat.MULTIBASE
        )

    @classmethod
    def from_jwk(
        cls,
        jwk: Union[str, dict],
        ident: Union[str, DIDUrl] = None,
        format: KeyFormat = None,
    ) -> "BaseKey":
        """Load a JWK key."""
        public_key, codec = jwk_to_public_key(jwk)
        key_type_cls = cls.for_codec(codec)
        return key_type_cls(public_key, ident=ident, format=format or KeyFormat.JWK)

    def __init__(
        self,
        public_key: bytes,
        ident: Union[str, DIDUrl] = None,
        format: KeyFormat = None,
    ):
        """Initializer."""
        self.public_key = public_key
        self.ident = ident or "#" + str(uuid4)
        self.format = format or KeyFormat.MULTIBASE
        self.validate()

    def validate(self):
        """Validate the key.

        :raises ValueError: if the public key is invalid
        """
        if self.key_length and len(self.public_key) != self.key_length:
            raise ValueError(
                "Invalid public key, expected {} bytes".format(self.key_length)
            )

    @abstractmethod
    def verification_method(
        self, controller: Union[str, DID], format: KeyFormat = None, **extra
    ) -> VerificationMethodResult:
        """Generate a VerificationMethod entry for this key."""

    def to_multibase(self, format: MultibaseFormat = None) -> str:
        """Encode this key in multibase format."""
        return to_multibase(self.codec.encode_multicodec(self.public_key), format)

    def __eq__(self, other: object) -> bool:
        """Compare to another key for equality."""
        if self.__class__ is not other.__class__:
            return False
        return self.public_key == other.public_key

    def __repr__(self) -> str:
        """Key representation."""
        return "<{} {}>".format(self.__class__.__name__, self.to_multibase())


class Ed25519VerificationKey(BaseKey):
    """Ed25519 verification key."""

    codec = Codec.ED25519
    key_length = ED25519_KEY_LENGTH
    relationships = [KeyRelationshipType.AUTHENTICATION]

    def verification_method(
        self, controller: Union[str, DID], format: KeyFormat = None, **extra
    ) -> VerificationMethodResult:
        """Generate a VerificationMethod entry for this key."""
        method = None
        context = None

        format = format or self.format
        if format == KeyFormat.BASE58:
            method = Ed25519VerificationKey2018.make(
                id=self.ident,
                controller=controller,
                public_key_base58=to_base58(self.public_key),
                **extra
            )
        elif format == KeyFormat.MULTIBASE:
            context = ED25519_2020_CONTEXT
            method = Ed25519VerificationKey2020.make(
                id=self.ident,
                controller=controller,
                public_key_multibase=to_multibase(
                    self.codec.encode_multicodec(self.public_key)
                ),
                **extra
            )
        elif format == KeyFormat.JWK:
            context = JWS_2020_CONTEXT
            jwk = public_key_to_jwk(self.public_key, self.codec)
            method = JsonWebKey2020.make(
                id=self.ident, controller=controller, public_key_jwk=jwk, **extra
            )

        if not method:
            raise ValueError("Unsupported key format for export")
        return VerificationMethodResult(context, method)


class X25519KeyAgreementKey(BaseKey):
    """X25519 public encryption key."""

    codec = Codec.X25519
    key_length = X25519_KEY_LENGTH
    relationships = [KeyRelationshipType.KEY_AGREEMENT]

    def verification_method(
        self, controller: Union[str, DID], format: KeyFormat = None, **extra
    ) -> VerificationMethodResult:
        """Generate a VerificationMethod entry for this key."""
        method = None
        context = None

        format = format or self.format
        if format == KeyFormat.BASE58:
            method = X25519KeyAgreementKey2019.make(
                id=self.ident,
                controller=controller,
                public_key_base58=to_base58(self.public_key),
                **extra
            )
        elif format == KeyFormat.MULTIBASE:
            context = X25519_2020_CONTEXT
            method = X25519KeyAgreementKey2020.make(
                id=self.ident,
                controller=controller,
                public_key_multibase=to_multibase(
                    self.codec.encode_multicodec(self.public_key)
                ),
                **extra
            )
        elif format == KeyFormat.JWK:
            context = JWS_2020_CONTEXT
            jwk = public_key_to_jwk(self.public_key, self.codec)
            method = JsonWebKey2020.make(
                id=self.ident, controller=controller, public_key_jwk=jwk, **extra
            )

        if not method:
            raise ValueError("Unsupported key format for export")
        return VerificationMethodResult(context, method)
