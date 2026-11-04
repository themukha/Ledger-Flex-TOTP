import argparse
import struct

import pytest

from ledger_otp import cli
from ledger_otp import protocol as p


def blob_of(n: int) -> bytes:
    payload = bytes([3]) + bytes(12) + b"abc"
    return struct.pack(">4sBB", p.BACKUP_MAGIC, p.BACKUP_VERSION, n) + payload * n


class FakeDev:
    def __init__(self, n: int):
        self.blob = blob_of(n)
        self.n = n

    def exchange(self, apdu: bytes):
        chunk = apdu[2]
        header = self.blob[:6]
        if chunk == 0:
            return p.Sw.OK, header
        size = 16
        pos = 6 + (chunk - 1) * size
        return p.Sw.OK, self.blob[pos:pos + size]


def run_backup(dev, path, force=False):
    return cli.cmd_backup(dev, argparse.Namespace(file=str(path), force=force))


def test_backup_writes_new_file_atomically(tmp_path, capsys):
    f = tmp_path / "b.lotp"
    assert run_backup(FakeDev(2), f) == 0
    assert f.read_bytes() == blob_of(2)
    assert not (tmp_path / "b.lotp.tmp").exists()
    assert "2 accounts" in capsys.readouterr().out


def test_backup_refuses_existing_file(tmp_path, capsys):
    f = tmp_path / "b.lotp"
    f.write_bytes(blob_of(3))
    assert run_backup(FakeDev(2), f) == 1
    assert f.read_bytes() == blob_of(3)
    assert "--force" in capsys.readouterr().err


def test_backup_force_overwrites_existing(tmp_path):
    f = tmp_path / "b.lotp"
    f.write_bytes(blob_of(3))
    assert run_backup(FakeDev(2), f, force=True) == 0
    assert f.read_bytes() == blob_of(2)


def test_backup_refuses_empty_device(tmp_path, capsys):
    f = tmp_path / "b.lotp"
    assert run_backup(FakeDev(0), f) == 1
    assert not f.exists() and not (tmp_path / "b.lotp.tmp").exists()
    assert "no accounts" in capsys.readouterr().err


def test_backup_force_allows_empty(tmp_path):
    f = tmp_path / "b.lotp"
    assert run_backup(FakeDev(0), f, force=True) == 0
    assert f.read_bytes() == blob_of(0)


def test_backup_keeps_old_file_when_device_rejects(tmp_path):
    f = tmp_path / "b.lotp"
    f.write_bytes(blob_of(3))

    class Rejecting:
        def exchange(self, apdu):
            return p.Sw.DENIED, b""

    with pytest.raises(p.DeviceError):
        run_backup(Rejecting(), f, force=True)
    assert f.read_bytes() == blob_of(3)


def test_sync_time_sends_next_whole_second(monkeypatch):
    sent = []
    slept = []
    monkeypatch.setattr(cli.time, "time", lambda: 1000.25)
    monkeypatch.setattr(cli.time, "sleep", slept.append)
    dev = cli.Device.__new__(cli.Device)
    dev.call = lambda apdu: sent.append(apdu) or b""
    dev.sync_time()
    assert slept == [pytest.approx(0.75)]
    assert sent[0][5:13] == struct.pack(">Q", 1001)


def test_list_pages_from_last_index(monkeypatch, capsys):
    pages = {
        0: (3, [(0, "A", "a"), (2, "B", "b")]),
        3: (3, [(3, "C", "c")]),
    }
    asked = []

    class Dev:
        def call(self, apdu):
            asked.append(apdu[2])
            return apdu[2]

    monkeypatch.setattr(p, "parse_list", lambda start: pages[start])
    assert cli.cmd_list(Dev(), argparse.Namespace()) == 0
    assert asked == [0, 3]
    assert "C · c" in capsys.readouterr().out


def test_info_prints_device_local_time(capsys):
    data = struct.pack(">BBBBBBQh", 0, 1, 0, 1, 64, 1, 1_700_000_000, 120)

    class Dev:
        def call(self, apdu):
            return data

    cli.cmd_info(Dev(), argparse.Namespace())
    assert "2023-11-15 00:13:20 (device local time, UTC+02:00)" in capsys.readouterr().out


class StatusDev:
    def __init__(self, sw: int):
        self.sw = sw

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise p.DeviceError(self.sw)

        return fail


@pytest.mark.parametrize(
    "sw, message",
    [
        (p.Sw.DEVICE_LOCKED, "Ledger is locked"),
        (p.Sw.APP_NOT_OPEN, "Authenticator is not open"),
        (p.Sw.WRONG_CLA, "Another app is open"),
        (p.Sw.DENIED, "Rejected on device"),
    ],
)
def test_known_status_prints_hint(monkeypatch, capsys, sw, message):
    monkeypatch.setattr(cli, "Device", lambda speculos: StatusDev(sw))
    assert cli.main(["info"]) == 1
    err = capsys.readouterr().err
    assert message in err
    assert "0x" not in err


def test_unknown_status_prints_code(monkeypatch, capsys):
    unknown_sw = 0x6F42
    monkeypatch.setattr(cli, "Device", lambda speculos: StatusDev(unknown_sw))
    assert cli.main(["info"]) == 1
    assert "Device error: device returned status 0x6F42" in capsys.readouterr().err
