# ledger-otp

TOTP authenticator for the Ledger Flex, plus a small Python CLI to sync time, import accounts and make backups.

Up to 64 accounts. SHA1 / SHA256 / SHA512, 6 or 8 digits, 30 or 60 s period.

## How it works

- Codes are computed and shown on the Flex only, never sent to the host.
- Secrets are stored encrypted (ChaCha20-Poly1305) with a key derived from the device seed. A backup is the same encrypted records, so it opens only on a device with the same recovery phrase (and passphrase, if you use one).
- The Flex has no clock an app can read. The host sends the time (`ledger-otp sync-time`), the app keeps counting while it is open.
- Import, restore, export and delete need a confirmation on the device.
- After an import or restore review the app loses its time sync (the SDK review screen stops the app's ticker). The CLI re-syncs right after.
- `SET_TIME` is not authenticated: check the time in the header.

Back up after every import. If the device loses power in the middle of a write, the SDK resets the app storage to empty on next start. Don't remove accounts from Google Authenticator until you have a backup and checked that the codes match.

## Build

```bash
docker run --rm -v "$PWD/device:/app" -w /app/flex-app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest cargo ledger build flex
```

The build targets Flex OS 1.7 (API level 27).

## Install on the Flex

Close Ledger Live, unlock the Flex and stay on the dashboard.

```bash
cd device/flex-app
python3 -m venv .venv && .venv/bin/pip install -r tools/sideload/requirements.txt
.venv/bin/python tools/sideload/make_bundle.py target build/sideload/bundle
.venv/bin/python tools/sideload/ledger_installer.py --bundle build/sideload/bundle
```

The device warns that the app is not genuine and asks for the PIN on every install.

## Speculos

```bash
docker run --rm -p 5001:5000 -p 9999:9999 -v "$PWD/device:/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  speculos -m flex --display headless /app/flex-app/target/flex/release/flex-app
```

Screen at http://localhost:5001, APDU on port 9999 (`ledger-otp --speculos ...`).

## CLI

```bash
cd tools/cli
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
```

```bash
ledger-otp sync-time
ledger-otp import 'otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'
ledger-otp import 'otpauth-migration://offline?data=...'
ledger-otp list
ledger-otp info
ledger-otp backup flex.lotp
ledger-otp restore flex.lotp
```

`import` takes plain `otpauth://` URIs and Google Authenticator export URIs (decode the export QR codes with any scanner). Unsupported entries are skipped with a reason. `backup` won't overwrite a file or write an empty backup without `--force`.

## Tests

```bash
cd device/otp-core && cargo test
cd tools/cli && .venv/bin/python -m pytest -q
```

Functional tests run in Speculos (build the app first):

```bash
docker run --rm -v "$PWD:/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest bash -c '
    python3 -m venv --system-site-packages /tmp/v &&
    cd tests/functional && /tmp/v/bin/pip install -r requirements.txt &&
    /tmp/v/bin/python -m pytest --device flex -q'
```

## Layout

- `device/otp-core` — TOTP, record format, vault crypto, APDU protocol, import logic (no_std, host-tested)
- `device/flex-app` — the Flex app: storage, keys, screens
- `tools/cli` — `ledger-otp`
- `tests/functional` — ragger tests
- `docs/hardware-checklist.md` — things to check on a real device
