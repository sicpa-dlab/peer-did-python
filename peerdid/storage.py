import os
from abc import ABC, abstractmethod

from peerdid.types import PEER_DID


class Storage(ABC):
    @abstractmethod
    def save_peer_did(self, peer_did: PEER_DID):
        pass

    @abstractmethod
    def load(self):
        pass


class FileStorage(Storage):
    def __init__(self, peer_did_storage_folder=None,
                 did_doc_file_extension=None):
        self.peer_did_storage_folder = peer_did_storage_folder or os.path.expanduser('~/.peerdids')
        self.did_doc_file_extension = did_doc_file_extension or '.diddoc'

    def save_peer_did(self, peer_did: PEER_DID):
        pass

    def load(self):
        pass
