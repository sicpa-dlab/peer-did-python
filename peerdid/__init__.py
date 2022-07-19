"""Peer DID document generation and resolution."""

from . import core, errors, keys, peer_did

from pydid import DID, DIDDocument

__version__ = "0.4.0"

__all__ = ["__version__", "core", "errors", "keys", "peer_did", "DID", "DIDDocument"]
