import struct

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from ledger_otp import protocol as p
from test_info_time import send

ALGO_SHA1 = 0
DIGITS = 6
PERIOD = 30
SECRET_PAD_A = 165
SECRET_PAD_B = 90
HOLD_TEXT = "Hold to save"
BATCH_A = bytes(range(16))
BATCH_B = bytes(reversed(range(16)))


def record(n: int) -> bytes:
    secret = struct.pack(">BBB", n, SECRET_PAD_A, SECRET_PAD_B) + bytes(range(8))
    return p.encode_record(ALGO_SHA1, DIGITS, PERIOD, f"Issuer{n}", f"user{n}@example.com", secret)


def begin_and_add(backend, batch_id: bytes, numbers) -> None:
    numbers = list(numbers)
    assert send(backend, p.import_begin(batch_id, len(numbers))).status == p.Sw.OK
    for n in numbers:
        assert send(backend, p.import_account(record(n))).status == p.Sw.OK


def commit_approve(backend, navigator, batch_id: bytes, path=None, name=None):
    with backend.exchange_async_raw(p.import_commit(batch_id)):
        navigator.navigate_until_text_and_compare(
            NavInsID.USE_CASE_REVIEW_TAP, [NavInsID.USE_CASE_REVIEW_CONFIRM], HOLD_TEXT, path, name
        )
    return backend.last_async_response


def commit_reject(backend, navigator, batch_id: bytes, path=None, name=None):
    with pytest.raises(ExceptionRAPDU) as rejected:
        with backend.exchange_async_raw(p.import_commit(batch_id)):
            navigator.navigate_and_compare(
                path, name, [NavInsID.USE_CASE_REVIEW_REJECT]
            )
    return rejected.value


def listed(backend):
    start = 0
    total, entries = p.parse_list(send(backend, p.list_accounts(start)).data)
    return total, entries


def test_import_approve(backend, navigator):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    rapdu = commit_approve(backend, navigator, BATCH_A)
    assert rapdu.status == p.Sw.OK
    assert rapdu.data == struct.pack(">BBB", 0, 0, 0)
    total, entries = listed(backend)
    assert total == 3
    assert [(i, iss, acc) for i, iss, acc in entries] == [
        (n - 1, f"Issuer{n}", f"user{n}@example.com") for n in (1, 2, 3)
    ]
    assert p.parse_info(send(backend, p.get_info()).data).count == 3


def test_import_reject(backend, navigator):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    rapdu = commit_reject(backend, navigator, BATCH_A)
    assert rapdu.status == p.Sw.DENIED
    assert listed(backend) == (0, [])
    assert send(backend, p.get_info()).status == p.Sw.OK


def test_import_same_batch_twice(backend, navigator):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    assert commit_approve(backend, navigator, BATCH_A).data == struct.pack(">BBB", 0, 0, 0)
    begin_and_add(backend, BATCH_B, [1, 2, 3])
    rapdu = commit_approve(backend, navigator, BATCH_B)
    assert rapdu.data == struct.pack(">BBB", 1, 1, 1)
    assert listed(backend)[0] == 3


def test_import_status_after_approve(backend, navigator):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    commit_approve(backend, navigator, BATCH_A)
    rapdu = send(backend, p.import_status(BATCH_A))
    assert rapdu.status == p.Sw.OK
    assert rapdu.data == struct.pack(">BBBB", 1, 0, 0, 0)
    assert send(backend, p.import_status(BATCH_B)).data == struct.pack(">B", 0)


def test_import_status_after_reject(backend, navigator):
    begin_and_add(backend, BATCH_A, [1])
    commit_reject(backend, navigator, BATCH_A)
    assert send(backend, p.import_status(BATCH_A)).data == struct.pack(">B", 2)


def test_commit_wrong_batch_id(backend):
    begin_and_add(backend, BATCH_A, [1])
    assert send(backend, p.import_commit(BATCH_B)).status == p.Sw.NO_BATCH


def test_commit_without_begin(backend):
    assert send(backend, p.import_commit(BATCH_A)).status == p.Sw.NO_BATCH


def test_import_account_without_begin(backend):
    assert send(backend, p.import_account(record(1))).status == p.Sw.NO_BATCH


def test_import_account_beyond_expected(backend):
    begin_and_add(backend, BATCH_A, [1])
    assert send(backend, p.import_account(record(2))).status == p.Sw.BATCH_FULL


def test_import_begin_invalid_count(backend):
    for expected in (0, 65):
        assert send(backend, p.import_begin(BATCH_A, expected)).status == p.Sw.INVALID_DATA


def test_import_account_invalid_record(backend):
    assert send(backend, p.import_begin(BATCH_A, 1)).status == p.Sw.OK
    garbage = struct.pack(">BBB", 9, 9, 9)
    assert send(backend, p.import_account(garbage)).status == p.Sw.INVALID_DATA


def test_commit_before_all_records(backend):
    assert send(backend, p.import_begin(BATCH_A, 2)).status == p.Sw.OK
    assert send(backend, p.import_account(record(1))).status == p.Sw.OK
    assert send(backend, p.import_commit(BATCH_A)).status == p.Sw.INVALID_DATA


def test_fill_to_64_then_no_space(backend, navigator):
    capacity = 64
    begin_and_add(backend, BATCH_A, range(1, capacity + 1))
    rapdu = commit_approve(backend, navigator, BATCH_A)
    assert rapdu.data == bytes(capacity)
    assert listed(backend)[0] == capacity
    assert p.parse_info(send(backend, p.get_info()).data).count == capacity
    begin_and_add(backend, BATCH_B, [capacity + 1])
    rapdu = commit_approve(backend, navigator, BATCH_B)
    assert rapdu.data == struct.pack(">B", 2)
    assert p.parse_info(send(backend, p.get_info()).data).count == capacity


def test_import_review_snapshots(backend, navigator, default_screenshot_path):
    begin_and_add(backend, BATCH_A, [1, 2, 3])
    rapdu = commit_approve(backend, navigator, BATCH_A, default_screenshot_path, "import_approve")
    assert rapdu.status == p.Sw.OK
    begin_and_add(backend, BATCH_B, [4, 5])
    rapdu = commit_reject(backend, navigator, BATCH_B, default_screenshot_path, "import_reject")
    assert rapdu.status == p.Sw.DENIED


@pytest.mark.parametrize("approve", [True, False])
def test_review_drops_time_sync(backend, navigator, approve):
    unix, tz = 1_800_000_000, 0
    assert send(backend, p.set_time(unix, tz)).status == p.Sw.OK
    assert p.parse_info(send(backend, p.get_info()).data).synced == 1
    begin_and_add(backend, BATCH_A, [1])
    (commit_approve if approve else commit_reject)(backend, navigator, BATCH_A)
    assert p.parse_info(send(backend, p.get_info()).data).synced == 0
    assert send(backend, p.set_time(unix, tz)).status == p.Sw.OK
    assert p.parse_info(send(backend, p.get_info()).data).synced == 1
