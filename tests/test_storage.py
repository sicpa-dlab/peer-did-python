import pytest

from peerdid.peer_did import save_peer_did
from peerdid.peer_did_utils import encode_filename
from peerdid.storage import FileStorage


def test_save_positive():
    peer_did = 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
    file_storage = FileStorage(peer_did_filename=encode_filename(peer_did))
    save_peer_did(
        peer_did=peer_did,
        storage=file_storage)


def test_save_wrong_peer_did():
    peer_did = '0000000'
    file_storage = FileStorage(peer_did_filename=encode_filename(peer_did))
    with pytest.raises(ValueError):
        save_peer_did(
            peer_did=peer_did,
            storage=file_storage)


def test_load():
    peer_did = 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
    file_storage = FileStorage(peer_did_filename=encode_filename(peer_did))
    save_peer_did(
        peer_did=peer_did,
        storage=file_storage)
    assert file_storage.load().decode() == peer_did
