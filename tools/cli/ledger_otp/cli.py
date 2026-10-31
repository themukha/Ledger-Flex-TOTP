import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from . import protocol as p
from .uris import Account, parse_migration, parse_otpauth, truncate_utf8

MAX_ISSUER, MAX_ACCOUNT = 32, 64
MAX_BATCH = 64
RESULT_TEXT = {0: "saved", 1: "already on device", 2: "no space"}
CONFIRM_MSG = "Confirm on your Ledger Flex..."
BACKUP_HINT = "Run `ledger-otp backup FILE` to keep an encrypted backup."


class Device:
    def __init__(self, speculos: bool):
        from ledgercomm import Transport
        try:
            self._t = Transport("tcp", "127.0.0.1", 9999) if speculos else Transport("hid")
        except Exception as e:
            where = "Speculos at 127.0.0.1:9999" if speculos else "Ledger"
            raise ConnectionError(
                f"{where} not found ({e}) - connect it, unlock, open Authenticator"
            ) from e

    def exchange(self, apdu: bytes) -> "tuple[int, bytes]":
        sw, data = self._t.exchange_raw(apdu)
        return sw, bytes(data)

    def call(self, apdu: bytes) -> bytes:
        sw, data = self.exchange(apdu)
        if sw != p.Sw.OK:
            raise p.DeviceError(sw)
        return data

    def sync_time(self) -> None:
        offset = datetime.now().astimezone().utcoffset()
        minutes = int(offset.total_seconds() // 60) if offset else 0
        now = time.time()
        target = int(now) + 1
        time.sleep(target - now)
        self.call(p.set_time(target, minutes))


def _label(a: Account) -> str:
    return f"{a.issuer} · {a.account}" if a.issuer else a.account


def _collect(uris: "list[str]") -> "list[Account]":
    accounts: "list[Account]" = []
    for uri in uris:
        if uri.startswith("otpauth-migration://"):
            accounts += parse_migration(uri).accounts
        else:
            accounts.append(parse_otpauth(uri))
    return accounts


def _run_batch(dev: Device, batch_id: bytes, expected: int, send) -> bytes:
    dev.call(p.import_begin(batch_id, expected))
    send()
    print(CONFIRM_MSG, flush=True)
    try:
        return dev.call(p.import_commit(batch_id))
    finally:
        try:
            dev.sync_time()
        except Exception as e:
            print(f"warning: could not re-sync time: {e}", file=sys.stderr)


def cmd_info(dev: Device, args) -> int:
    i = p.parse_info(dev.call(p.get_info()))
    print(f"version  {i.ver_major}.{i.ver_minor}.{i.ver_patch}")
    print(f"accounts {i.count}/{i.capacity}")
    print(f"synced   {'yes' if i.synced else 'no'}")
    if i.synced:
        local = datetime.fromtimestamp(i.now_unix, timezone.utc) + timedelta(minutes=i.tz_offset_min)
        sign = "+" if i.tz_offset_min >= 0 else "-"
        hh, mm = divmod(abs(i.tz_offset_min), 60)
        print(f"time     {local:%Y-%m-%d %H:%M:%S} (device local time, UTC{sign}{hh:02d}:{mm:02d})")
    return 0


def cmd_sync_time(dev: Device, args) -> int:
    dev.sync_time()
    print("Time synced")
    return 0


def cmd_list(dev: Device, args) -> int:
    entries: list = []
    total = 0
    start = 0
    while True:
        total, chunk = p.parse_list(dev.call(p.list_accounts(start)))
        entries += chunk
        if not chunk or len(entries) >= total:
            break
        start = chunk[-1][0] + 1
    for index, issuer, account in entries:
        print(f"{index:2d}  {issuer} · {account}" if issuer else f"{index:2d}  {account}")
    if not entries:
        print("No accounts")
    return 0


def cmd_import(dev: Device, args) -> int:
    accounts = _collect(args.uris)
    good = []
    for a in accounts:
        if a.supported:
            good.append(a)
        else:
            print(f"skipped {_label(a)}: {a.reason}")
    if not good:
        print("Nothing to import")
        return 1
    if len(good) > MAX_BATCH:
        print(f"Too many accounts ({len(good)}), at most {MAX_BATCH} per import", file=sys.stderr)
        return 1
    records = [
        p.encode_record(a.algo, a.digits, a.period, truncate_utf8(a.issuer, MAX_ISSUER),
                        truncate_utf8(a.account, MAX_ACCOUNT), a.secret)
        for a in good
    ]
    batch_id = os.urandom(16)

    def send():
        for r in records:
            dev.call(p.import_account(r))

    results = _run_batch(dev, batch_id, len(records), send)
    for a, r in zip(good, results):
        print(f"{RESULT_TEXT.get(r, f'unknown ({r})'):18s} {_label(a)}")
    if 0 in results:
        print(BACKUP_HINT)
    return 0


def cmd_backup(dev: Device, args) -> int:
    existing = None
    if os.path.exists(args.file):
        if not args.force:
            print(f"{args.file} already exists; refusing to overwrite it (use --force to replace it)",
                  file=sys.stderr)
            return 1
        try:
            with open(args.file, "rb") as f:
                existing = len(p.iter_backup(f.read())[1])
        except (ValueError, OSError):
            existing = None
    print(CONFIRM_MSG, flush=True)
    blob = p.read_backup(dev.exchange)
    _, payloads = p.iter_backup(blob)
    if not payloads and not args.force:
        print("The device has no accounts; not writing an empty backup (use --force to write it anyway)",
              file=sys.stderr)
        return 1
    if existing is not None and len(payloads) < existing:
        print(f"warning: {args.file} had {existing} accounts, the new backup has {len(payloads)}",
              file=sys.stderr)
    tmp = args.file + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, args.file)
    print(f"Backup of {len(payloads)} accounts written to {args.file}")
    return 0


def cmd_restore(dev: Device, args) -> int:
    with open(args.file, "rb") as f:
        _, payloads = p.iter_backup(f.read())
    if not payloads:
        print("Backup is empty")
        return 1

    def send():
        for payload in payloads:
            dev.call(p.restore_account(payload))

    results = _run_batch(dev, os.urandom(16), len(payloads), send)
    counts = {text: 0 for text in RESULT_TEXT.values()}
    for r in results:
        counts[RESULT_TEXT.get(r, "unknown")] = counts.get(RESULT_TEXT.get(r, "unknown"), 0) + 1
    print(", ".join(f"{n} {text}" for text, n in counts.items() if n))
    if counts["saved"]:
        print(BACKUP_HINT)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ledger-otp", description="Ledger OTP host client")
    ap.add_argument("--speculos", action="store_true", help="connect to Speculos at 127.0.0.1:9999")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sub.add_parser("sync-time").set_defaults(fn=cmd_sync_time)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    s = sub.add_parser("import")
    s.add_argument("uris", nargs="+", metavar="URI")
    s.set_defaults(fn=cmd_import)
    s = sub.add_parser("backup")
    s.add_argument("file")
    s.add_argument("--force", action="store_true",
                   help="overwrite an existing FILE, or write a backup of zero accounts")
    s.set_defaults(fn=cmd_backup)
    s = sub.add_parser("restore")
    s.add_argument("file")
    s.set_defaults(fn=cmd_restore)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(Device(args.speculos), args)
    except p.DeviceError as e:
        if e.sw == p.Sw.DENIED:
            print("Rejected on device", file=sys.stderr)
        else:
            print(f"Device error: {e}", file=sys.stderr)
        return 1
    except (ValueError, OSError, ConnectionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
