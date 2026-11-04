# Hardware checklist

Run `ledger-otp sync-time` first. Compare `ledger-otp info` (device local time) with `date`.

- [x] Lock the Flex for 5 minutes, unlock: is the app still open, and is the clock still right?
- [x] Leave it unlocked on the app for an hour: drift in seconds?
- [x] After the screen turns off: codes, "Sync time from iPhone", or the dashboard?
- [x] Import one account, reinstall the app: does `ledger-otp list` still show it? Same after uninstall + install.
- [x] Import 64 accounts: no crash, 65th is reported as no space.
- [ ] Codes screen: no ghosting on the per-second update, `NNs` countdown readable, no ghost tap after "Hold to delete".
- [x] Close key and "Quit app" return to the dashboard.

## Acceptance

1. `ledger-otp sync-time`
2. Import a Google Authenticator export (`ledger-otp import 'otpauth-migration://...' ...`), hold to save.
3. Codes for 3 accounts match the phone.
4. `ledger-otp backup b.lotp`
5. `ledger-otp restore b.lotp`: everything reported as already on device.

## Results (Flex OS 1.7.0, 2026-11-04)

| Check | Result |
| :--- | :--- |
| Screen lock | App stays open, codes stay, clock keeps running |
| Idle hide | Codes hide after a minute without a touch |
| Auto-lock | Works on schedule once the codes are hidden |
| App restart | Clock is lost, `sync-time` needed every time |
| Ghosting | Fast B&W refresh smears in seconds; contrast B&W refresh is much better, slight smear left. Clean refresh every 10 s and on code change: to check |
| Everything else | OK |
