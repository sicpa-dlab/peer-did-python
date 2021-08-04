from peerdid.types import JSON


class PeerDIDResolver:
    @staticmethod
    def resolve(self, peer_did: str, version_id=None) -> JSON:
        pass

    @staticmethod
    def save(self, peer_did: str, did_doc: JSON, version_id):
        pass
