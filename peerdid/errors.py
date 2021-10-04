class PeerDIDError(Exception):
    pass


class MalformedPeerDIDError(PeerDIDError):
    def __init__(self, msg: str) -> None:
        super().__init__("Invalid peer DID provided. {}.".format(msg))
