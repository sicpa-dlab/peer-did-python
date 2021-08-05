import os
from abc import ABC, abstractmethod


class Storage(ABC):
    @abstractmethod
    def save(self, data: bytes):
        """
        Saves data to a storage
        """
        pass

    @abstractmethod
    def load(self):
        """
        Loads data from a storage
        """
        pass


class FileStorage(Storage):
    def __init__(self, peer_did_storage_folder=None,
                 did_doc_file_extension=None):
        self.peer_did_storage_folder = peer_did_storage_folder or os.path.expanduser('~/.peerdids')
        self.did_doc_file_extension = did_doc_file_extension or '.diddoc'

    def save(self, data: bytes):
        """
        Saves data to a storage
        """
        pass

    def load(self):
        """
        Loads data from a storage
        """
        pass
