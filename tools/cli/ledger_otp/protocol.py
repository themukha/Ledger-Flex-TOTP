import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

CLA = 0xE0


class Ins(IntEnum):
    GET_INFO = 0x01
    SET_TIME = 0x02
    LIST_ACCOUNTS = 0x03
    IMPORT_BEGIN = 0x10
    IMPORT_ACCOUNT = 0x11
    IMPORT_COMMIT = 0x12
    IMPORT_STATUS = 0x13
    RESTORE_ACCOUNT = 0x14
    EXPORT_BACKUP = 0x20


class Sw(IntEnum):
    OK = 0x9000
    DENIED = 0x6985
    INVALID_DATA = 0x6A80
    WRONG_P1P2 = 0x6A86
    INS_NOT_SUPPORTED = 0x6D00
    WRONG_CLA = 0x6E00
    NO_BATCH = 0xB001
    BATCH_FULL = 0xB002
    DECRYPT_FAILED = 0xB003
    EXPORT_NOT_APPROVED = 0xB004
    DEVICE_LOCKED = 0x5515
    APP_NOT_OPEN = 0x6511


@dataclass(frozen=True)
class Info:
    ver_major: int
    ver_minor: int
    ver_patch: int
    count: int
    capacity: int
    synced: int
    now_unix: int
    tz_offset_min: int


_INFO_FMT = ">BBBBBBQh"


def _apdu(ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
    if len(data) > 255:
        raise ValueError("APDU data longer than 255 bytes")
    return struct.pack(">BBBBB", CLA, ins, p1, p2, len(data)) + data


def encode_record(algo: int, digits: int, period: int, issuer: str, account: str, secret: bytes) -> bytes:
    issuer_b = issuer.encode("utf-8")
    account_b = account.encode("utf-8")
    return (
        struct.pack(">BBBB", algo, digits, period, len(issuer_b)) + issuer_b
        + struct.pack(">B", len(account_b)) + account_b
        + struct.pack(">B", len(secret)) + bytes(secret)
    )


def get_info() -> bytes:
    return _apdu(Ins.GET_INFO)


def parse_info(data: bytes) -> Info:
    if len(data) != struct.calcsize(_INFO_FMT):
        raise ValueError(f"GET_INFO response must be 16 bytes, got {len(data)}")
    return Info(*struct.unpack(_INFO_FMT, data))


def set_time(unix: int, tz_offset_min: int) -> bytes:
    return _apdu(Ins.SET_TIME, data=struct.pack(">Qh", unix, tz_offset_min))


def list_accounts(start: int) -> bytes:
    return _apdu(Ins.LIST_ACCOUNTS, p1=start)


def parse_list(data: bytes) -> "tuple[int, list[tuple[int, str, str]]]":
    total = data[0]
    pos = 1
    entries = []
    while pos < len(data):
        index, ilen = data[pos], data[pos + 1]
        pos += 2
        issuer = data[pos:pos + ilen].decode("utf-8")
        pos += ilen
        alen = data[pos]
        pos += 1
        account = data[pos:pos + alen].decode("utf-8")
        pos += alen
        entries.append((index, issuer, account))
    return total, entries


def import_begin(batch_id: bytes, expected: int) -> bytes:
    return _apdu(Ins.IMPORT_BEGIN, data=bytes(batch_id) + struct.pack(">B", expected))


def import_account(record: bytes) -> bytes:
    return _apdu(Ins.IMPORT_ACCOUNT, data=record)


def import_commit(batch_id: bytes) -> bytes:
    return _apdu(Ins.IMPORT_COMMIT, data=bytes(batch_id))


def import_status(batch_id: bytes) -> bytes:
    return _apdu(Ins.IMPORT_STATUS, data=bytes(batch_id))


def restore_account(payload: bytes) -> bytes:
    return _apdu(Ins.RESTORE_ACCOUNT, data=payload)


def export_backup(chunk: int) -> bytes:
    return _apdu(Ins.EXPORT_BACKUP, p1=chunk)


STATUS_MESSAGES = {
    Sw.DENIED: "Rejected on device",
    Sw.DEVICE_LOCKED: "Ledger is locked. Unlock it and open Authenticator",
    Sw.APP_NOT_OPEN: "Authenticator is not open. Open it on the Ledger",
    Sw.WRONG_CLA: "Another app is open on the Ledger. Open Authenticator",
    Sw.INS_NOT_SUPPORTED: "Another app is open on the Ledger. Open Authenticator",
}


class DeviceError(Exception):
    def __init__(self, sw: int):
        message = STATUS_MESSAGES.get(sw, f"device returned status 0x{sw:04X}")
        super().__init__(message)
        self.sw = sw

BACKUP_MAGIC = b"LOTP"
BACKUP_VERSION = 1
_BACKUP_HEADER_FMT = ">4sBB"
_NONCE_LEN = 12

def read_backup(exchange: Callable[[bytes], "tuple[int, bytes]"]) -> bytes:
    sw, header = exchange(export_backup(0))
    if sw != Sw.OK:
        raise DeviceError(sw)
    _, _, count = _parse_backup_header(header)
    parts = [bytes(header)]
    for chunk in range(1, count + 1):
        sw, payload = exchange(export_backup(chunk))
        if sw != Sw.OK:
            raise DeviceError(sw)
        parts.append(bytes(payload))
    return b"".join(parts)

def _parse_backup_header(blob: bytes) -> "tuple[bytes, int, int]":
    size = struct.calcsize(_BACKUP_HEADER_FMT)
    if len(blob) < size:
        raise ValueError("backup header is truncated")
    magic, version, count = struct.unpack(_BACKUP_HEADER_FMT, bytes(blob[:size]))
    if magic != BACKUP_MAGIC:
        raise ValueError("not a Ledger OTP backup")
    if version != BACKUP_VERSION:
        raise ValueError(f"unsupported backup version {version}")
    return magic, version, count

def iter_backup(blob: bytes) -> "tuple[int, list[bytes]]":
    blob = bytes(blob)
    size = struct.calcsize(_BACKUP_HEADER_FMT)
    _, version, count = _parse_backup_header(blob)
    payloads = []
    pos = size
    for _ in range(count):
        if pos >= len(blob):
            raise ValueError("backup is truncated")
        end = pos + 1 + _NONCE_LEN + blob[pos]
        if end > len(blob):
            raise ValueError("backup is truncated")
        payloads.append(blob[pos:end])
        pos = end
    if pos != len(blob):
        raise ValueError("backup has trailing bytes")
    return version, payloads
