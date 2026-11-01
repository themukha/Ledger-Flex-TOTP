# Hardware checklist

Run `ledger-otp sync-time` first. Compare `ledger-otp info` (device local time) with `date`.

- [ ] Lock the Flex for 5 minutes, unlock: is the app still open, and is the clock still right?
- [ ] Leave it unlocked on the app for an hour: drift in seconds?
- [ ] After the screen turns off: codes, "Sync time from iPhone", or the dashboard?
- [ ] Import one account, reinstall the app: does `ledger-otp list` still show it? Same after uninstall + install.
- [ ] Import 64 accounts: no crash, 65th is reported as no space.
- [ ] Codes screen: flicker on the per-second update, `NNs` countdown readable, no ghost tap after "Hold to delete".

## Acceptance

1. `ledger-otp sync-time`
2. Import a Google Authenticator export (`ledger-otp import 'otpauth-migration://...' ...`), hold to save.
3. Codes for 3 accounts match the phone.
4. `ledger-otp backup b.lotp`
5. `ledger-otp restore b.lotp`: everything reported as already on device.

| Check | Result |
| :--- | :--- |
| | |
