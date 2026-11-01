import struct

import pytest
from ragger.error import ExceptionRAPDU

from ledger_otp import protocol as p
from test_codes_ui import FOOTER_TEXT, HOLD_BUTTON, hold, info, listed, snapshot, tap
from test_import import (
    BATCH_A,
    BATCH_B,
    SECRET_PAD_A,
    SECRET_PAD_B,
    begin_and_add,
    commit_approve,
)
from test_info_time import send

COUNT = 3
HEADER_LEN = 6
BACKUP_VERSION = 1
MAX_PAYLOAD = 195
PAYLOAD_PREFIX = 13
CONFIRM_TITLE = "backup\\?"
CONFIRM_SUBTITLE = "recovery phrase can read it."


def export_chunk0_approve(backend):
    with backend.exchange_async_raw(p.export_backup(0)):
        backend.wait_for_text_on_screen(CONFIRM_TITLE)
        hold(backend, HOLD_BUTTON)
    return backend.last_async_response


def exchange(backend):
    chunk_offset = 2

    def call(apdu: bytes):
        if apdu[chunk_offset] == 0:
            rapdu = export_chunk0_approve(backend)
        else:
            rapdu = send(backend, apdu)
        return rapdu.status, rapdu.data

    return call


def import_three(backend, navigator):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    assert commit_approve(backend, navigator, BATCH_A).status == p.Sw.OK


def delete_all(backend):
    backend.wait_for_text_on_screen("Sync time from iPhone")
    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete all accounts")
    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete all accounts\\?")
    hold(backend, HOLD_BUTTON)
    backend.wait_for_text_on_screen("Sync time from iPhone")
    assert info(backend).count == 0


def restore(backend, payloads, batch_id=BATCH_B):
    assert send(backend, p.import_begin(batch_id, len(payloads))).status == p.Sw.OK
    for payload in payloads:
        assert send(backend, p.restore_account(payload)).status == p.Sw.OK


def test_export_reject(backend, navigator):
    import_three(backend, navigator)
    with pytest.raises(ExceptionRAPDU) as rejected:
        with backend.exchange_async_raw(p.export_backup(0)):
            backend.wait_for_text_on_screen(CONFIRM_TITLE)
            tap(backend, FOOTER_TEXT)
    assert rejected.value.status == p.Sw.DENIED
    assert send(backend, p.export_backup(1)).status == p.Sw.EXPORT_NOT_APPROVED


def test_export_confirm_snapshot(backend, navigator, golden_run, default_screenshot_path):
    import_three(backend, navigator)
    with backend.exchange_async_raw(p.export_backup(0)):
        backend.wait_for_text_on_screen(CONFIRM_TITLE)
        assert backend.compare_screen_with_text("Export encrypted")
        assert backend.compare_screen_with_text("Only a device with the same")
        assert backend.compare_screen_with_text(CONFIRM_SUBTITLE)
        snapshot(backend, golden_run, default_screenshot_path, "export_confirm")
        hold(backend, HOLD_BUTTON)
    assert backend.last_async_response.status == p.Sw.OK


def test_export_chunk_without_approval(backend, navigator):
    import_three(backend, navigator)
    assert send(backend, p.export_backup(1)).status == p.Sw.EXPORT_NOT_APPROVED


def test_export_approval_reset_by_other_command(backend, navigator):
    import_three(backend, navigator)
    assert export_chunk0_approve(backend).status == p.Sw.OK
    assert send(backend, p.export_backup(1)).status == p.Sw.OK
    assert send(backend, p.get_info()).status == p.Sw.OK
    assert send(backend, p.export_backup(1)).status == p.Sw.EXPORT_NOT_APPROVED


def test_export_chunk_out_of_range(backend, navigator):
    import_three(backend, navigator)
    assert export_chunk0_approve(backend).status == p.Sw.OK
    assert send(backend, p.export_backup(COUNT + 1)).status == p.Sw.WRONG_P1P2


def test_export_header_and_payloads_encrypted(backend, navigator):
    import_three(backend, navigator)
    blob = p.read_backup(exchange(backend))
    magic = b"LOTP"
    assert blob[:HEADER_LEN] == magic + struct.pack(">BB", BACKUP_VERSION, COUNT)
    version, payloads = p.iter_backup(blob)
    assert version == BACKUP_VERSION
    assert len(payloads) == COUNT
    for n, payload in zip((1, 2, 3), payloads):
        assert len(payload) <= MAX_PAYLOAD
        assert len(payload) == PAYLOAD_PREFIX + payload[0]
        assert f"Issuer{n}".encode() not in payload
        assert f"user{n}@example.com".encode() not in payload
        assert struct.pack(">BBB", n, SECRET_PAD_A, SECRET_PAD_B) + bytes(range(8)) not in payload


def test_export_roundtrip(backend, navigator):
    import_three(backend, navigator)
    before = listed(backend)
    assert before[0] == COUNT
    blob = p.read_backup(exchange(backend))
    _, payloads = p.iter_backup(blob)

    delete_all(backend)
    assert listed(backend) == (0, [])

    restore(backend, payloads)
    rapdu = commit_approve(backend, navigator, BATCH_B)
    assert rapdu.status == p.Sw.OK
    assert rapdu.data == struct.pack(">BBB", 0, 0, 0)
    assert listed(backend) == before


def test_restore_tampered(backend, navigator):
    import_three(backend, navigator)
    _, payloads = p.iter_backup(p.read_backup(exchange(backend)))
    delete_all(backend)

    tampered = bytearray(payloads[1])
    flip_at = PAYLOAD_PREFIX + 2
    tampered[flip_at] ^= 1
    assert send(backend, p.import_begin(BATCH_B, COUNT)).status == p.Sw.OK
    assert send(backend, p.restore_account(payloads[0])).status == p.Sw.OK
    assert send(backend, p.restore_account(bytes(tampered))).status == p.Sw.DECRYPT_FAILED
    assert send(backend, p.import_commit(BATCH_B)).status == p.Sw.NO_BATCH
    assert info(backend).count == 0


def test_restore_duplicates(backend, navigator):
    import_three(backend, navigator)
    _, payloads = p.iter_backup(p.read_backup(exchange(backend)))
    restore(backend, payloads)
    rapdu = commit_approve(backend, navigator, BATCH_B)
    assert rapdu.status == p.Sw.OK
    assert rapdu.data == struct.pack(">BBB", 1, 1, 1)
    assert info(backend).count == COUNT


def test_restore_without_begin(backend):
    assert send(backend, p.restore_account(bytes(range(40)))).status == p.Sw.NO_BATCH
