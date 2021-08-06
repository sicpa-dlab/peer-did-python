from abc import ABC, abstractmethod
from pathlib import Path


class Storage(ABC):
    @abstractmethod
    def save(self, data: bytes):
        """
        Saves data to a storage
        """
        pass

    @abstractmethod
    def load(self) -> bytes:
        """
        Loads data from a storage
        """
        pass


class FileStorage(Storage):
    DEFAULT_PEERDID_FOLDER_PATH = str(Path.home() / '.peerdids')
    DEFAULT_PEERDID_FILE_EXTENSION = '.diddoc'

    def __init__(self, peer_did_storage_folder=None,
                 did_doc_file_extension=None):
        self.peer_did_storage_folder = peer_did_storage_folder or self.DEFAULT_PEERDID_FOLDER_PATH
        self.did_doc_file_extension = did_doc_file_extension or self.DEFAULT_PEERDID_FILE_EXTENSION

    def save(self, data: bytes):
        """
        Saves data to a storage
        """
        pass

    def load(self) -> bytes:
        """
        Loads data from a storage
        """
        pass
