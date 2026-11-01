import hashlib
import hmac
import struct
import time
from pathlib import Path

from ledger_otp import protocol as p
from test_import import BATCH_A, commit_approve
from test_info_time import send

ALGO_SHA1 = 0
ALGO_SHA256 = 1
RFC_SECRET = "12345678901234567890".encode("ascii")
SYNC_UNIX = 1_800_000_000
TZ_OFFSET_MIN = 180

ACCOUNTS = [
    (ALGO_SHA1, 6, 30, "GitHub", "octocat@example.com"),
    (ALGO_SHA1, 6, 30, "Google", "user@gmail.com"),
    (ALGO_SHA256, 8, 30, "Cloudflare", "ops@example.com"),
    (ALGO_SHA1, 6, 60, "AWS", "root@example.com"),
    (ALGO_SHA1, 6, 30, "Dropbox", "me@example.com"),
]

SCREEN_X_CENTER = 240
BACK_BUTTON = (40, 44)
ROW_Y = [140, 245, 350, 455]
FOOTER_TEXT = (SCREEN_X_CENTER, 560)
CODES_SETTINGS = (96, 550)
NEXT_PAGE = (430, 550)
PREVIOUS_PAGE = (243, 550)
HOLD_BUTTON = (SCREEN_X_CENTER, 435)
HOLD_SECONDS = 3.0
TOAST_SECONDS = 1.5


def totp(secret: bytes, algo: int, digits: int, period: int, unix: int) -> str:
    digest = {ALGO_SHA1: hashlib.sha1, ALGO_SHA256: hashlib.sha256}[algo]
    mac = hmac.new(secret, struct.pack(">Q", unix // period), digest).digest()
    offset = mac[-1] & 15
    (word,) = struct.unpack(">I", mac[offset : offset + 4])
    code = str((word & 0x7FFFFFFF) % 10**digits).zfill(digits)
    half = digits // 2
    return f"{code[:half]} {code[half:]}"


def import_accounts(backend, navigator, accounts=ACCOUNTS):
    assert send(backend, p.import_begin(BATCH_A, len(accounts))).status == p.Sw.OK
    for algo, digits, period, issuer, account in accounts:
        rec = p.encode_record(algo, digits, period, issuer, account, RFC_SECRET)
        assert send(backend, p.import_account(rec)).status == p.Sw.OK
    assert commit_approve(backend, navigator, BATCH_A).status == p.Sw.OK


def info(backend):
    return p.parse_info(send(backend, p.get_info()).data)


def sync_and_wait_home(backend, unix=SYNC_UNIX, tz=TZ_OFFSET_MIN):
    assert send(backend, p.set_time(unix, tz)).status == p.Sw.OK
    backend.wait_for_text_on_screen("Time synced")
    time.sleep(TOAST_SECONDS + 0.3)


def wait_for_second(backend, target: int) -> None:
    while info(backend).now_unix < target:
        time.sleep(0.05)


def listed(backend):
    start = 0
    return p.parse_list(send(backend, p.list_accounts(start)).data)


def snapshot(backend, golden_run: bool, root: Path, name: str, timeout: float = 3.0) -> None:
    golden = root / "snapshots" / "flex" / name / "00000.png"
    tmp = root / "snapshots-tmp" / "flex" / name / "00000.png"
    golden.parent.mkdir(parents=True, exist_ok=True)
    tmp.parent.mkdir(parents=True, exist_ok=True)
    if golden_run:
        time.sleep(0.5)
        backend.compare_screen_with_snapshot(golden, tmp_snap_path=tmp, golden_run=True)
        return
    deadline = time.time() + timeout
    while not backend.compare_screen_with_snapshot(golden, tmp_snap_path=tmp):
        assert time.time() < deadline, f"screen does not match golden {name}"
        time.sleep(0.1)


def tap(backend, xy):
    backend.finger_touch(*xy)


def hold(backend, xy):
    backend.finger_touch(*xy, HOLD_SECONDS)


def test_home_unsynced_snapshot(backend, golden_run, default_screenshot_path):
    backend.wait_for_text_on_screen("Sync time from iPhone")
    assert backend.compare_screen_with_text("Open the Authenticator app")
    snapshot(backend, golden_run, default_screenshot_path, "home_unsynced")


def test_home_codes_snapshot(backend, navigator, golden_run, default_screenshot_path):
    import_accounts(backend, navigator)
    sync_and_wait_home(backend)

    page1_at = SYNC_UNIX + 4
    wait_for_second(backend, page1_at)
    snapshot(backend, golden_run, default_screenshot_path, "home_codes_page1", timeout=0.7)
    for algo, digits, period, issuer, _ in ACCOUNTS[:4]:
        assert backend.compare_screen_with_text(issuer)
        assert backend.compare_screen_with_text(totp(RFC_SECRET, algo, digits, period, page1_at))
    assert backend.compare_screen_with_text("1 of 2")
    assert not backend.compare_screen_with_text("Dropbox")

    backend.finger_swipe(SCREEN_X_CENTER, 300, direction="left")
    page2_at = SYNC_UNIX + 6
    wait_for_second(backend, page2_at)
    snapshot(backend, golden_run, default_screenshot_path, "home_codes_page2", timeout=0.7)
    algo, digits, period, issuer, _ = ACCOUNTS[4]
    assert backend.compare_screen_with_text(issuer)
    assert backend.compare_screen_with_text(totp(RFC_SECRET, algo, digits, period, page2_at))
    assert backend.compare_screen_with_text("2 of 2")


def test_home_no_accounts(backend):
    sync_and_wait_home(backend)
    backend.wait_for_text_on_screen("No accounts yet")


def test_paging_keeps_clock_running(backend, navigator):
    import_accounts(backend, navigator)
    sync_and_wait_home(backend)
    start = time.time()
    synced_at = info(backend).now_unix
    for _ in range(2):
        backend.finger_swipe(SCREEN_X_CENTER, 300, direction="left")
        backend.wait_for_text_on_screen("2 of 2")
        backend.finger_swipe(SCREEN_X_CENTER, 300, direction="right")
        backend.wait_for_text_on_screen("1 of 2")
        tap(backend, NEXT_PAGE)
        backend.wait_for_text_on_screen("2 of 2")
        tap(backend, PREVIOUS_PAGE)
        backend.wait_for_text_on_screen("1 of 2")
        time.sleep(0.5)
    elapsed = time.time() - start
    now = info(backend)
    assert now.synced == 1
    assert now.now_unix >= synced_at + int(elapsed) - 1


def test_delete_account(backend, navigator, golden_run, default_screenshot_path):
    import_accounts(backend, navigator)
    sync_and_wait_home(backend)

    tap(backend, (SCREEN_X_CENTER, ROW_Y[1]))
    backend.wait_for_text_on_screen("Delete account")
    for text in ("Google", "user@gmail.com", "SHA1"):
        assert backend.compare_screen_with_text(text)
    snapshot(backend, golden_run, default_screenshot_path, "account_details")

    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete account\\?")
    snapshot(backend, golden_run, default_screenshot_path, "account_delete_confirm")
    hold(backend, HOLD_BUTTON)
    backend.wait_for_text_on_screen("Codes")

    total, entries = listed(backend)
    assert total == 4
    assert [iss for _, iss, _ in entries] == ["GitHub", "Cloudflare", "AWS", "Dropbox"]
    assert info(backend).synced == 1


def test_delete_account_cancel(backend, navigator):
    import_accounts(backend, navigator)
    sync_and_wait_home(backend)
    tap(backend, (SCREEN_X_CENTER, ROW_Y[0]))
    backend.wait_for_text_on_screen("Delete account")
    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete account\\?")
    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("octocat@example.com")
    tap(backend, BACK_BUTTON)
    backend.wait_for_text_on_screen("Codes")
    assert listed(backend)[0] == len(ACCOUNTS)


def test_delete_all(backend, navigator, golden_run, default_screenshot_path):
    import_accounts(backend, navigator)
    backend.wait_for_text_on_screen("Sync time from iPhone")
    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete all accounts")
    snapshot(backend, golden_run, default_screenshot_path, "settings")

    tap(backend, FOOTER_TEXT)
    backend.wait_for_text_on_screen("Delete all accounts\\?")
    snapshot(backend, golden_run, default_screenshot_path, "delete_all_confirm")
    hold(backend, HOLD_BUTTON)
    backend.wait_for_text_on_screen("Sync time from iPhone")

    assert listed(backend) == (0, [])
    assert info(backend).count == 0


def test_settings_from_codes_page(backend, navigator):
    import_accounts(backend, navigator)
    sync_and_wait_home(backend)
    tap(backend, CODES_SETTINGS)
    backend.wait_for_text_on_screen("Delete all accounts")
    assert backend.compare_screen_with_text("5 of 64")
    tap(backend, BACK_BUTTON)
    backend.wait_for_text_on_screen("Codes")


def test_time_synced_toast_snapshot(backend, golden_run, default_screenshot_path):
    assert send(backend, p.set_time(SYNC_UNIX, TZ_OFFSET_MIN)).status == p.Sw.OK
    backend.wait_for_text_on_screen("Time synced")
    snapshot(backend, golden_run, default_screenshot_path, "time_synced_toast", timeout=1.0)
    backend.wait_for_text_on_screen("No accounts yet", timeout=3.0)
