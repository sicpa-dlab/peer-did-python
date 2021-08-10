import os.path
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

    def __init__(self, peer_did_filename: str, peer_did_storage_folder: str = None,
                 did_doc_file_extension: str = None):
        self.peer_did_storage_folder = peer_did_storage_folder or self.DEFAULT_PEERDID_FOLDER_PATH
        self.peer_did_filename = peer_did_filename
        self.did_doc_file_extension = did_doc_file_extension or self.DEFAULT_PEERDID_FILE_EXTENSION

    def save(self, data: bytes):
        """
        Saves data to a storage
        """
        file_path = os.path.join(self.peer_did_storage_folder, self.peer_did_filename + self.did_doc_file_extension)
        f = open(file_path, "bw+")
        f.write(data)
        f.close()

    def load(self) -> bytes:
        """
        Loads data from a storage
        """
        file_path = os.path.join(self.peer_did_storage_folder, self.peer_did_filename + self.did_doc_file_extension)
        f = open(file_path, "rb")
        data = f.read()
        f.close()
        return data
