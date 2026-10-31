import base64
from urllib.parse import quote

import pytest

from ledger_otp.uris import parse_migration, parse_otpauth, truncate_utf8


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field_varint(num, value):
    return _varint(num << 3) + _varint(value)


def _field_bytes(num, value):
    return _varint((num << 3) | 2) + _varint(len(value)) + value


def _params(secret, name, issuer, algorithm, digits, otp_type):
    return (
        _field_bytes(1, secret) + _field_bytes(2, name.encode()) + _field_bytes(3, issuer.encode())
        + _field_varint(4, algorithm) + _field_varint(5, digits) + _field_varint(6, otp_type)
    )


def _migration_uri(params_list, batch_size, batch_index, batch_id):
    payload = b"".join(_field_bytes(1, p) for p in params_list)
    payload += _field_varint(2, 1) + _field_varint(3, batch_size)
    payload += _field_varint(4, batch_index) + _field_varint(5, batch_id)
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


def test_otpauth_basic():
    acc = parse_otpauth("otpauth://totp/GitHub:user%40mail.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    assert acc.issuer == "GitHub"
    assert acc.account == "user@mail.com"
    assert acc.secret == b"Hello!\xde\xad\xbe\xef"
    assert (acc.algo, acc.digits, acc.period) == (0, 6, 30)
    assert acc.supported


def test_otpauth_lowercase_unpadded_secret():
    acc = parse_otpauth("otpauth://totp/me?secret=jbswy3dpehpk3pxp")
    assert acc.secret == b"Hello!\xde\xad\xbe\xef"
    assert acc.issuer == ""
    assert acc.account == "me"


def test_otpauth_sha256_8_60():
    acc = parse_otpauth("otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60")
    assert acc.digits == 8
    assert acc.period == 60
    sha1 = parse_otpauth("otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP")
    sha512 = parse_otpauth("otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512")
    assert (sha1.algo, acc.algo, sha512.algo) == (0, 1, 2)


def test_otpauth_hotp_unsupported():
    acc = parse_otpauth("otpauth://hotp/X:a?secret=JBSWY3DPEHPK3PXP&counter=1")
    assert not acc.supported
    assert acc.reason == "HOTP is not supported"


def test_migration_two_accounts():
    s1, s2 = b"secret-one-0123456789", b"\x01\x02\x03\x04\x05"
    uri = _migration_uri(
        [_params(s1, "alice@x.com", "Acme", 1, 1, 2), _params(s2, "Bank:bob", "Bank", 3, 2, 2)],
        batch_size=3, batch_index=1, batch_id=123456,
    )
    batch = parse_migration(uri)
    assert (batch.batch_id, batch.index, batch.size) == (123456, 1, 3)
    a, b = batch.accounts
    assert (a.issuer, a.account, a.secret, a.digits, a.period, a.supported) == ("Acme", "alice@x.com", s1, 6, 30, True)
    assert (b.issuer, b.secret, b.digits, b.period, b.supported) == ("Bank", s2, 8, 30, True)
    assert (a.algo, b.algo) == (0, 2)


def test_migration_md5_unsupported():
    uri = _migration_uri([_params(b"abc", "u", "I", 4, 1, 2)], 1, 0, 1)
    acc = parse_migration(uri).accounts[0]
    assert not acc.supported
    assert acc.reason


def test_truncate_utf8():
    out = truncate_utf8("ёжик" * 20, 32)
    assert len(out.encode("utf-8")) <= 32
    out.encode("utf-8").decode("utf-8")
    assert truncate_utf8("abc", 32) == "abc"


def _uri_from_payload(payload):
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


@pytest.mark.parametrize("payload", [
    _field_varint(1, 10**9),
    _field_bytes(1, _field_varint(1, 10**9)),
    _field_bytes(1, _field_varint(2, 5)),
    _field_bytes(1, _field_varint(3, 5)),
    _field_bytes(1, _field_bytes(4, b"x")),
    _varint((1 << 3) | 2) + _varint(50) + b"abc",
    _varint(2 << 3) + b"\xff" * 11,
    _varint((2 << 3) | 1) + b"\x00" * 4,
    _varint((2 << 3) | 5) + b"\x00" * 2,
    _field_varint(3, 1)[:-1],
])
def test_migration_malformed_raises_value_error(payload):
    with pytest.raises(ValueError):
        parse_migration(_uri_from_payload(payload))


def test_migration_unknown_enums_unsupported():
    acc = parse_migration(_migration_uri([_params(b"abc", "u", "I", 9, 1, 2)], 1, 0, 1)).accounts[0]
    assert not acc.supported and acc.reason == "Unknown algorithm"
    acc = parse_migration(_migration_uri([_params(b"abc", "u", "I", 1, 7, 2)], 1, 0, 1)).accounts[0]
    assert not acc.supported and "digits" in acc.reason
