import re


class PeerDIDCreator:
    PEER_DID_PATTERN = re.compile(r'^did:peer:[01](z)([1-9a-km-zA-HJ-NP-Z]{46,47})$')

    @staticmethod
    def create_numalgo_0(inception_key) -> str:
        pass

    @staticmethod
    def create_numalgo_1(inception_key, genesis_doc) -> str:
        pass

    @staticmethod
    def create_numalgo_2(inception_key, encryption_keys: list, signing_keys: list, endpoint) -> str:
        pass
