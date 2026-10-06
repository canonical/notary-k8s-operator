from pathlib import Path
from unittest.mock import ANY, Mock, patch

from machine import NotarySnap


def test_install_uses_requested_snap_channel_without_starting_daemon():
    notary_snap = Mock()
    notary_snap.state = Mock()
    cache = {"notary": notary_snap}

    with patch("machine.snap.SnapCache", return_value=cache):
        NotarySnap().install("latest/edge")

    notary_snap.ensure.assert_called_once_with(ANY, channel="latest/edge")
    notary_snap.start.assert_not_called()


def test_write_text_creates_parent_directories_and_read_text_reads_file(tmp_path: Path):
    path = tmp_path / "config" / "notary.yaml"

    NotarySnap().write_text(str(path), "port: 2111\n")

    assert NotarySnap().read_text(str(path)) == "port: 2111\n"
