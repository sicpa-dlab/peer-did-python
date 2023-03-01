"""Peer DID document generation and resolution."""

from . import core, dids, errors, keys

from pydid import DID, DIDDocument

__version__ = "0.5.1"

__all__ = ["__version__", "core", "errors", "dids", "keys", "DID", "DIDDocument"]
