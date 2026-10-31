import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

ALGO_SHA1, ALGO_SHA256, ALGO_SHA512 = 0, 1, 2
_ALGOS = {"SHA1": ALGO_SHA1, "SHA256": ALGO_SHA256, "SHA512": ALGO_SHA512}
MAX_SECRET = 64


@dataclass
class Account:
    issuer: str
    account: str
    secret: bytes
    algo: int = ALGO_SHA1
    digits: int = 6
    period: int = 30
    supported: bool = True
    reason: "str | None" = None


@dataclass
class MigrationBatch:
    batch_id: int
    index: int
    size: int
    accounts: "list[Account]" = field(default_factory=list)


def truncate_utf8(s: str, max_bytes: int) -> str:
    return s.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")


def _check(acc: Account) -> Account:
    if acc.supported:
        reason = None
        if not 1 <= len(acc.secret) <= MAX_SECRET:
            reason = "secret must be 1..64 bytes"
        elif acc.digits not in (6, 8):
            reason = f"{acc.digits} digits is not supported"
        elif acc.period not in (30, 60):
            reason = f"period {acc.period}s is not supported"
        if reason:
            acc.supported, acc.reason = False, reason
    return acc


def _b32(secret: str) -> bytes:
    s = secret.replace(" ", "").replace("-", "").upper().rstrip("=")
    s += "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base32 secret") from e


def parse_otpauth(uri: str) -> Account:
    parts = urlsplit(uri)
    if parts.scheme != "otpauth":
        raise ValueError("not an otpauth:// URI")
    kind = parts.netloc.lower()
    if kind not in ("totp", "hotp"):
        raise ValueError(f"unknown otpauth type {kind!r}")
    q = {k.lower(): v[0] for k, v in parse_qs(parts.query).items()}
    label = unquote(parts.path.lstrip("/"))
    label_issuer, sep, account = label.partition(":")
    if not sep:
        label_issuer, account = "", label
    issuer = q.get("issuer") or label_issuer.strip()
    if "secret" not in q:
        raise ValueError("otpauth URI has no secret")
    acc = Account(issuer=issuer, account=account.strip(), secret=_b32(q["secret"]))
    algo = q.get("algorithm", "SHA1").upper()
    if algo in _ALGOS:
        acc.algo = _ALGOS[algo]
    else:
        acc.supported, acc.reason = False, f"algorithm {algo} is not supported"
    try:
        acc.digits = int(q.get("digits", 6))
        acc.period = int(q.get("period", 30))
    except ValueError as e:
        raise ValueError("invalid digits or period") from e
    if kind == "hotp":
        acc.supported, acc.reason = False, "HOTP is not supported"
    return _check(acc)


def _read_varint(buf: bytes, pos: int) -> "tuple[int, int]":
    shift = value = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated protobuf")
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _fields(buf: bytes):
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        num, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            n, pos = _read_varint(buf, pos)
            if pos + n > len(buf):
                raise ValueError("truncated protobuf")
            value, pos = buf[pos:pos + n], pos + n
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if pos + size > len(buf):
                raise ValueError("truncated protobuf")
            value, pos = int.from_bytes(buf[pos:pos + size], "little"), pos + size
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield num, value


def _expect(value, kind: type, num: int):
    if not isinstance(value, kind):
        raise ValueError(f"malformed migration data: field {num} has the wrong type")
    return value


def _parse_params(buf: bytes) -> Account:
    secret, name, issuer = b"", "", ""
    algorithm, digits, otp_type = 0, 0, 0
    for num, v in _fields(buf):
        if num == 1:
            secret = _expect(v, bytes, num)
        elif num == 2:
            name = _expect(v, bytes, num).decode("utf-8", errors="replace")
        elif num == 3:
            issuer = _expect(v, bytes, num).decode("utf-8", errors="replace")
        elif num == 4:
            algorithm = _expect(v, int, num)
        elif num == 5:
            digits = _expect(v, int, num)
        elif num == 6:
            otp_type = _expect(v, int, num)
    prefix, sep, rest = name.partition(":")
    if sep and (not issuer or prefix == issuer):
        issuer, name = issuer or prefix, rest
    acc = Account(issuer=issuer.strip(), account=name.strip(), secret=bytes(secret))
    if digits in (0, 1):
        acc.digits = 6
    elif digits == 2:
        acc.digits = 8
    else:
        acc.supported, acc.reason = False, "Unknown digits value"
    if algorithm in (0, 1):
        acc.algo = ALGO_SHA1
    elif algorithm == 2:
        acc.algo = ALGO_SHA256
    elif algorithm == 3:
        acc.algo = ALGO_SHA512
    elif algorithm == 4:
        acc.supported, acc.reason = False, "MD5 is not supported"
    else:
        acc.supported, acc.reason = False, "Unknown algorithm"
    if otp_type == 1:
        acc.supported, acc.reason = False, "HOTP is not supported"
    return _check(acc)


def parse_migration(uri: str) -> MigrationBatch:
    parts = urlsplit(uri)
    if parts.scheme != "otpauth-migration":
        raise ValueError("not an otpauth-migration:// URI")
    data = parse_qs(parts.query).get("data")
    if not data:
        raise ValueError("migration URI has no data")
    b64 = data[0].replace(" ", "+").replace("-", "+").replace("_", "/")
    b64 += "=" * (-len(b64) % 4)
    try:
        payload = base64.b64decode(b64)
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base64 in migration data") from e
    batch = MigrationBatch(batch_id=0, index=0, size=1)
    for num, v in _fields(payload):
        if num == 1:
            batch.accounts.append(_parse_params(_expect(v, bytes, num)))
        elif num == 3:
            batch.size = _expect(v, int, num)
        elif num == 4:
            batch.index = _expect(v, int, num)
        elif num == 5:
            batch.batch_id = _expect(v, int, num)
    return batch
