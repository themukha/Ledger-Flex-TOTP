import struct

from ledger_otp import protocol as p


def test_set_time_apdu():
    unix = 1_700_000_000
    tz = -120
    cla, ins, p1, p2, lc = 0xE0, 0x02, 0, 0, 10
    expected = struct.pack(">BBBBBQh", cla, ins, p1, p2, lc, unix, tz)
    assert p.set_time(unix, tz) == expected


def test_parse_info():
    major, minor, patch, count, capacity, synced = 0, 1, 2, 5, 64, 1
    now, tz = 1_800_000_001, 180
    data = struct.pack(">BBBBBBQh", major, minor, patch, count, capacity, synced, now, tz)
    info = p.parse_info(data)
    assert (info.ver_major, info.ver_minor, info.ver_patch) == (major, minor, patch)
    assert info.count == count
    assert info.capacity == capacity
    assert info.synced == synced
    assert info.now_unix == now
    assert info.tz_offset_min == tz


def test_encode_record_layout():
    algo, digits, period = 1, 8, 60
    issuer, account = "GitHub", "alice@example.com"
    secret = bytes(range(1, 11))
    issuer_b, account_b = issuer.encode(), account.encode()
    expected = (
        struct.pack(">BBBB", algo, digits, period, len(issuer_b)) + issuer_b
        + struct.pack(">B", len(account_b)) + account_b
        + struct.pack(">B", len(secret)) + secret
    )
    assert p.encode_record(algo, digits, period, issuer, account, secret) == expected


def test_parse_list_two_entries():
    total = 2
    i0, a0 = b"GitHub", b"alice"
    i1, a1 = b"AWS", b"bob"
    data = struct.pack(">B", total)
    data += struct.pack(">BB", 0, len(i0)) + i0 + struct.pack(">B", len(a0)) + a0
    data += struct.pack(">BB", 1, len(i1)) + i1 + struct.pack(">B", len(a1)) + a1
    assert p.parse_list(data) == (total, [(0, "GitHub", "alice"), (1, "AWS", "bob")])


def test_simple_apdus():
    cla = 0xE0
    assert p.get_info() == struct.pack(">BBBBB", cla, p.Ins.GET_INFO, 0, 0, 0)
    start = 7
    assert p.list_accounts(start) == struct.pack(">BBBBB", cla, p.Ins.LIST_ACCOUNTS, start, 0, 0)
    chunk = 3
    assert p.export_backup(chunk) == struct.pack(">BBBBB", cla, p.Ins.EXPORT_BACKUP, chunk, 0, 0)


def test_import_apdus():
    cla = 0xE0
    batch_id = bytes(range(16))
    expected_n = 12
    assert p.import_begin(batch_id, expected_n) == (
        struct.pack(">BBBBB", cla, p.Ins.IMPORT_BEGIN, 0, 0, 17) + batch_id + struct.pack(">B", expected_n)
    )
    algo, digits, period = 0, 6, 30
    record = struct.pack(">BBB", algo, digits, period)
    assert p.import_account(record) == struct.pack(">BBBBB", cla, p.Ins.IMPORT_ACCOUNT, 0, 0, len(record)) + record
    assert p.import_commit(batch_id) == struct.pack(">BBBBB", cla, p.Ins.IMPORT_COMMIT, 0, 0, 16) + batch_id
    assert p.import_status(batch_id) == struct.pack(">BBBBB", cla, p.Ins.IMPORT_STATUS, 0, 0, 16) + batch_id
    version = 32
    payload = struct.pack(">B", version) + bytes(32)
    assert p.restore_account(payload) == struct.pack(">BBBBB", cla, p.Ins.RESTORE_ACCOUNT, 0, 0, len(payload)) + payload


def test_sw_values():
    assert [int(s) for s in (p.Sw.OK, p.Sw.DENIED, p.Sw.INVALID_DATA, p.Sw.WRONG_P1P2, p.Sw.INS_NOT_SUPPORTED,
                             p.Sw.WRONG_CLA, p.Sw.NO_BATCH, p.Sw.BATCH_FULL, p.Sw.DECRYPT_FAILED,
                             p.Sw.EXPORT_NOT_APPROVED)] == [
        0x9000, 0x6985, 0x6A80, 0x6A86, 0x6D00, 0x6E00, 0xB001, 0xB002, 0xB003, 0xB004]


def _fake_payload(n: int) -> bytes:
    ct_len = 20 + n
    nonce = bytes([n]) * 12
    return struct.pack(">B", ct_len) + nonce + bytes([n + 1]) * ct_len


def test_iter_backup_roundtrip():
    version, count = 1, 3
    payloads = [_fake_payload(n) for n in range(count)]
    blob = b"LOTP" + struct.pack(">BB", version, count) + b"".join(payloads)
    assert p.iter_backup(blob) == (version, payloads)


def test_iter_backup_rejects_bad_input():
    version, count = 1, 1
    payload = _fake_payload(0)
    good = b"LOTP" + struct.pack(">BB", version, count) + payload
    for bad in (
        b"XXXX" + good[4:],
        good[:4] + struct.pack(">B", 2) + good[5:],
        good[:-1],
        good + b"\x00",
        good[:5],
    ):
        try:
            p.iter_backup(bad)
        except ValueError:
            continue
        raise AssertionError("malformed backup accepted")


def test_read_backup_walks_chunks():
    version, count = 1, 2
    payloads = [_fake_payload(n) for n in range(count)]
    header = b"LOTP" + struct.pack(">BB", version, count)
    seen = []

    def exchange(apdu):
        seen.append(apdu)
        chunk = apdu[2]
        return 0x9000, [header, *payloads][chunk]

    blob = p.read_backup(exchange)
    assert blob == header + b"".join(payloads)
    assert seen == [p.export_backup(i) for i in range(count + 1)]


def test_read_backup_stops_on_error():
    denied = 0x6985

    def exchange(apdu):
        return denied, b""

    try:
        p.read_backup(exchange)
    except p.DeviceError as e:
        assert e.sw == denied
    else:
        raise AssertionError("error status ignored")
