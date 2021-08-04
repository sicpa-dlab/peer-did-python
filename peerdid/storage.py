import os
from abc import ABC, abstractmethod


class Storage(ABC):
    @abstractmethod
    def save(self):
        pass

    @abstractmethod
    def load(self):
        pass


class FileStorage(Storage):
    def __init__(self, peer_did_storage_folder=os.path.expanduser('~/.peerdids'),
                 did_doc_file_extension='.diddoc'):
        self.peer_did_storage_folder = peer_did_storage_folder
        self.did_doc_file_extension = did_doc_file_extension

    def save(self):
        pass

    def load(self):
        pass
