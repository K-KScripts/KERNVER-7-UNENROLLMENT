# ManualEscape

Server-side ChromeOS unenroll. No shim, no TPM glitch, no disassembly.
Registers a clone of the victim Chromebook with Google's Device Management
API, then overwrites its **server-backed state keys** with garbage so the
real device no longer matches forced re-enrollment. Optionally verifies the
kill and deletes the clone record.

This is the manual form of the Quicksilver/Icarus primitive, extended with
verification (Phase 1) and deprovision (Phase 2).

> Educational / research use. You must own the device or have admin consent.
> Not the author's exploit; use at your own risk.

## How it works

1. **OAuth launcher.** Exchange a fresh OOBE auth-code with the Chrome
   enrollment client (`77185425430.apps.googleusercontent.com`) for a
   `refresh_token`, then an `access_token` scoped to
   `chromeosdevicemanagement + userinfo.email`.
2. **Clone registration.** `POST m.google.com/devicemanagement/data/api?request=register`
   with `DeviceRegisterRequest{type=DEVICE, machine_id=<serial>}` and a random
   `deviceid` uuid. Server returns a `device_management_token` (dmtoken).
3. **Poison keys.** `POST ?request=policy` with `PolicyFetchRequest` +
   `DeviceStateKeyUpdateRequest{server_backed_state_keys=[5x random 32B]}`.
   The server keeps 5 future time quanta (~1 year); overwriting all 5 orphans
   the real device's derived keys (`HMAC(stable_device_secret, ...)` or
   `SHA256(serial/disk/group+time)` — see
   `login_manager/device_identifier_generator.cc`).
4. **Phase 1 — verify.** Unauthenticated `device_state_retrieval` +
   `device_initial_enrollment_state` queries for the serial, same as OOBE
   does. Unenrolled = `RESTORE_MODE_NONE` /
   `INITIAL_ENROLLMENT_MODE_NONE` + empty `management_domain`.
5. **Phase 2 — deprovision.** Authenticated `?request=unregister` with
   `DeviceUnregisterRequest` + dmtoken deletes the clone record.

After that, powerwash the Chromebook and go through OOBE — it should skip
enterprise enrollment. Old `SH1MMER deprovision` (FWMP wipe) alone is not
enough on r125+ (partial) / r136+ (all) because of Unified State
Determination; this attacks the server record instead.

## Requirements

- Python 3.9+
- `pip install -r requirements.txt` (`requests`, `protobuf`)
- Victim Chromebook **serial number** (sticker, `chrome://system`, or OOBE)
- Fresh **OAuth auth-code** from an account allowed to enroll that device
  (grab via OOBE escape / sign-in flow; codes expire in minutes)

## Usage

```bash
pip install -r requirements.txt

# interactive (prompts for serial + hidden oauth code)
python unenroll.py

# non-interactive
python unenroll.py --serial ABC123XYZ --oauth-code '4/0A...'

# build protobufs without network calls
python unenroll.py --serial TEST --dry-run

# skip verification or unregister steps
python unenroll.py --serial X --oauth-code Y --skip-verify
python unenroll.py --serial X --oauth-code Y --skip-unregister
```

Full flow output ends with either `[+] VERIFIED: server reports no
enrollment` or `[-] NOT VERIFIED` (retry / wait for convergence, then
powerwash + re-check).

## What to do on the Chromebook afterwards

Server poison alone isn't the whole story — the device keeps local
enrollment triggers (VPD flags, FWMP, state-determination) that will
re-enroll it if you just reboot. The `client/` scripts cover that half
(run them in a VT2 root shell with `Ctrl+Alt+F2`, or a SH1MMER/GoodSilver
bash — not on your PC):

1. Powerwash (`Ctrl+Alt+Shift+R`) or recover, boot to OOBE, connect Wi-Fi.
2. Before completing setup: `sh client/check_enrollment.sh` (read-only) to
   see `check_enrollment / block_devmode / re_enrollment_key` + FWMP status.
3. `sh client/persist.sh` — sets `check_enrollment=0`, rotates
   `re_enrollment_key` to a random 32B value, bind-mounts a
   `/etc/chrome_dev.conf` with all four
   `--enterprise-enable-*-determination=never` flags (covers r125-135
   unified flags and the r136+ single flag; unknown ones are ignored),
   then `initctl restart ui`. Do NOT reboot — finish OOBE right away
   without enterprise credentials.
4. If enrollment re-appears, the poison hasn't converged — re-run
   `unenroll.py` verify queries from the PC, then repeat.
5. `sh client/persist.sh --undo` deletes the key again if you ever want to
   allow re-enrollment.

Why both halves: `unenroll.py` orphans the *server* record;
`client/persist.sh` suppresses the *local* triggers. Either alone
re-enrolls on r125+ (partial) / r136+ (all devices) Unified State
Determination.

## Files

| File | Purpose |
|---|---|
| `unenroll.py` | register + poison + verify + unregister CLI (PC side) |
| `client/check_enrollment.sh` | read-only device state check (run on Chromebook) |
| `client/persist.sh` | VPD + chrome_dev.conf anti-re-enroll (run on Chromebook) |
| `NISSA.md` | full step-by-step guide for nissa board (ChromeOS 147) |
| `device_management_backend_pb2.py` | compiled `device_management_backend.proto` bindings |
| `requirements.txt` | `requests`, `protobuf` |

## Device-specific guides

- [**Nissa (pujjoga)** — ChromeOS 147, v143+ fully patched](NISSA.md)

## Limitations

- Needs a valid, unexpired OAuth code per run.
- Verification endpoints are unauthenticated by design but Google may
  throttle or change them; verify failure doesn't always mean the poison failed — check OOBE.
- No bulk mode (Phase 3), no shim payload wrapper — single serial per run.
- Server-side fix (key rotation binding, registration auth) would kill this class entirely.
