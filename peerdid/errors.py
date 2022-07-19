"""Error classes."""


class PeerDIDError(Exception):
    """Base class for Peer DID exceptions."""


class MalformedPeerDIDError(PeerDIDError):
    """An invalid peer DID was provided."""

    def __init__(self, msg: str) -> None:
        """Initializer."""
        super().__init__("Invalid peer DID provided. {}.".format(msg))
