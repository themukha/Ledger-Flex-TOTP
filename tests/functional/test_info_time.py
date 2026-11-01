import struct

from ragger.error import ExceptionRAPDU

from ledger_otp import protocol as p

CLA = 0xE0


def send(backend, apdu: bytes):
    try:
        return backend.exchange_raw(apdu)
    except ExceptionRAPDU as e:
        return e


def test_info_unsynced_after_start(backend):
    rapdu = send(backend, p.get_info())
    assert rapdu.status == p.Sw.OK
    info = p.parse_info(rapdu.data)
    assert info.synced == 0
    assert info.count == 0
    assert info.capacity == 64


def test_set_time_then_info(backend):
    unix = 1_800_000_000
    tz = 180
    rapdu = send(backend, p.set_time(unix, tz))
    assert rapdu.status == p.Sw.OK
    info = p.parse_info(send(backend, p.get_info()).data)
    assert info.synced == 1
    assert unix <= info.now_unix <= unix + 2
    assert info.tz_offset_min == tz


def test_list_empty(backend):
    start = 0
    rapdu = send(backend, p.list_accounts(start))
    assert rapdu.status == p.Sw.OK
    total, entries = p.parse_list(rapdu.data)
    assert total == 0
    assert entries == []


def test_wrong_cla(backend):
    bad_cla, ins, p1, p2, lc = 0xE1, p.Ins.GET_INFO, 0, 0, 0
    rapdu = send(backend, struct.pack(">BBBBB", bad_cla, ins, p1, p2, lc))
    assert rapdu.status == p.Sw.WRONG_CLA


def test_unknown_ins(backend):
    ins, p1, p2, lc = 0x99, 0, 0, 0
    rapdu = send(backend, struct.pack(">BBBBB", CLA, ins, p1, p2, lc))
    assert rapdu.status == p.Sw.INS_NOT_SUPPORTED
