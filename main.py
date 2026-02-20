import time
import pathlib
import urllib.parse
import base64
import datetime
import email.utils
import json
import sys
import os
import re
import logging
import argparse

import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "duo_config.json")
KEY_FILE = os.path.join(SCRIPT_DIR, "duo_key.pem")
LOG_FILE = os.path.join(SCRIPT_DIR, "duo_approver.log")
POLL_INTERVAL = 5  # seconds between transaction polls

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("duo-auto-approver")


# ═══════════════════════════════════════════════════════════════════════════
# Duo Client — handles activation, signing, polling, and approving
# ═══════════════════════════════════════════════════════════════════════════
class DuoClient:
    """Lightweight Duo Push API client.

    Implements the same protocol that the Duo Mobile app and the Auto-2FA
    browser extension use:
      • RSA-2048 keypair for device identity
      • RSASSA-PKCS1-v1_5 / SHA-512 request signing
      • REST calls to /push/v2/* endpoints
    """

    def __init__(self):
        self.pkey: str | None = None      # device identifier (from activation response)
        self.akey: str | None = None      # activation key     (from activation response)
        self.host: str | None = None      # API hostname        (e.g. api-XXXX.duosecurity.com)
        self._rsa_key: RSA.RsaKey | None = None  # RSA-2048 key object (private + public)

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------
    def generate_keypair(self):
        """Generate a fresh RSA-2048 keypair."""
        self._rsa_key = RSA.generate(2048)
        log.info("Generated new RSA-2048 keypair")

    def load_key_pem(self, path: str):
        """Load an RSA key from a PEM file."""
        with open(path, "rb") as f:
            self._rsa_key = RSA.import_key(f.read())
        log.info("Loaded RSA key from %s", path)

    def save_key_pem(self, path: str):
        """Save the RSA private key to a PEM file."""
        with open(path, "wb") as f:
            f.write(self._rsa_key.export_key("PEM"))
        log.info("Saved RSA key to %s", path)

    def load_key_from_base64_der(self, b64: str):
        """Load a private key from base64-encoded DER/PKCS8 (Auto-2FA export format)."""
        der = base64.b64decode(b64)
        self._rsa_key = RSA.import_key(der)
        log.info("Loaded RSA key from base64 DER")

    # ------------------------------------------------------------------
    # Credential persistence
    # ------------------------------------------------------------------
    def save_config(self):
        """Persist pkey / akey / host to JSON and the RSA key to PEM."""
        with open(CONFIG_FILE, "w") as f:
            json.dump({"pkey": self.pkey, "akey": self.akey, "host": self.host}, f, indent=2)
        self.save_key_pem(KEY_FILE)
        log.info("Credentials saved  ->  %s  +  %s", CONFIG_FILE, KEY_FILE)

    def load_config(self):
        """Load previously saved credentials."""
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        self.pkey = cfg["pkey"]
        self.akey = cfg["akey"]
        self.host = cfg["host"]
        self.load_key_pem(KEY_FILE)
        log.info("Loaded config  pkey=%s  host=%s", self.pkey, self.host)

    # ------------------------------------------------------------------
    # Import helpers
    # ------------------------------------------------------------------
    def import_auto2fa_export(self, path: str):
        """Import device data exported from the Auto-2FA browser extension.

        The JSON must contain at minimum: pkey, akey, host, privateRaw.
        """
        with open(path, "r") as f:
            data = json.load(f)
        self.pkey = data["pkey"]
        self.akey = data["akey"]
        self.host = data["host"]
        self.load_key_from_base64_der(data["privateRaw"])
        log.info("Imported Auto-2FA export  host=%s  pkey=%s", self.host, self.pkey)

    def import_ruo_files(self, response_path: str, key_path: str):
        """Import from the original Ruo project's response.json + key.pem."""
        with open(response_path, "r") as f:
            resp = json.load(f)
        if "response" in resp:
            resp = resp["response"]
        self.pkey = resp["pkey"]
        self.akey = resp["akey"]
        self.host = resp.get("host", "")
        self.load_key_pem(key_path)
        if not self.host:
            raise ValueError("response.json is missing 'host' — cannot continue")
        log.info("Imported Ruo files  host=%s  pkey=%s", self.host, self.pkey)

    # ------------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------------
    @staticmethod
    def parse_activation_input(raw: str):
        """Parse an activation code or URL into (code, host).

        Supported formats:
          • CODE-BASE64HOST  (from the Duo email / QR code)
          • https://m-XXXX.duosecurity.com/activate/{code}  (activation URL)

        When given a URL, we fetch the page to extract the real activation
        code (which contains the correct api-* host in base64).
        """
        raw = raw.strip()

        if raw.startswith("https://") or raw.startswith("http://"):
            # This is a Duo activation *web page* URL, NOT the API endpoint.
            # Fetch the page and extract the real CODE-BASE64HOST from it.
            log.info("Fetching activation page: %s", raw)
            try:
                resp = requests.get(raw, timeout=15)
                resp.raise_for_status()
                page = resp.text
                # The page contains "duo://CODE-BASE64HOST" in an activation link
                # and also shows the code as plain text.
                # Look for duo:// protocol link first (most reliable)
                m = re.search(r'duo://([A-Za-z0-9+/=]+-[A-Za-z0-9+/=]+)', page)
                if not m:
                    # Fall back to looking for the raw code pattern
                    # 20 alphanum chars, dash, base64 string
                    m = re.search(r'([A-Za-z0-9]{20}-[A-Za-z0-9+/=]{20,})', page)
                if m:
                    raw = m.group(1)
                    log.info("Extracted activation code from page: %s", raw)
                else:
                    # Last resort: use the URL path as the code and guess the API host
                    parsed = urllib.parse.urlparse(raw)
                    url_code = parsed.path.rstrip("/").split("/")[-1]
                    url_host = parsed.netloc
                    # Convert m-XXXX to api-XXXX
                    if url_host.startswith("m-"):
                        api_host = "api-" + url_host[2:]
                    else:
                        api_host = url_host
                    log.warning("Could not extract code from page, using URL parts: code=%s host=%s", url_code, api_host)
                    return url_code, api_host
            except Exception as e:
                log.warning("Could not fetch activation page: %s — trying URL parse fallback", e)
                parsed = urllib.parse.urlparse(raw)
                url_code = parsed.path.rstrip("/").split("/")[-1]
                url_host = parsed.netloc
                if url_host.startswith("m-"):
                    api_host = "api-" + url_host[2:]
                else:
                    api_host = url_host
                return url_code, api_host

        # Now parse the CODE-BASE64HOST format
        if "-" in raw:
            parts = raw.split("-", 1)
            code = parts[0].strip("<>")
            host_b64 = parts[1].strip("<>")
            # fix base64 padding
            pad = len(host_b64) % 4
            if pad:
                host_b64 += "=" * (4 - pad)
            host = base64.b64decode(host_b64.encode("ascii")).decode("ascii")
            return code, host
        else:
            raise ValueError(
                f"Unrecognised activation input: {raw!r}\n"
                "Expected CODE-BASE64HOST or an https:// activation URL."
            )

    def activate(self, raw_code: str):
        """Register this script as a new Duo Mobile device.

        Parameters
        ----------
        raw_code : str
            Either ``CODE-BASE64HOST`` or a full activation URL.
        """
        code, host = self.parse_activation_input(raw_code)
        self.host = host
        log.info("Activating with host=%s  code=%s", host, code)

        if self._rsa_key is None:
            self.generate_keypair()

        pubkey_pem = self._rsa_key.publickey().export_key("PEM").decode("ascii")

        params = {
            "customer_protocol": "1",
            "pubkey": pubkey_pem,
            "pkpush": "rsa-sha512",
            "jailbroken": "false",
            "architecture": "arm64",
            "region": "US",
            "app_id": "com.duosecurity.duomobile",
            "full_disk_encryption": "true",
            "passcode_status": "true",
            "platform": "Android",
            "app_version": "4.87.0",
            "app_build_number": "487010",
            "version": "14",
            "manufacturer": "samsung",
            "language": "en",
            "model": "Galaxy Tab S9+",
            "security_patch_level": "2025-12-01",
        }

        # Try POST with params as query string first (matches Ruo + Auto-2FA),
        # then fall back to form-encoded body if that fails.
        url = f"https://{host}/push/v2/activation/{code}"
        log.info("POST %s", url)
        r = requests.post(url, params=params, timeout=15)

        if r.status_code == 404:
            log.warning("Activation returned 404 with query params — trying form-encoded body...")
            r = requests.post(url, data=params, timeout=15)

        if r.status_code != 200:
            log.error("Activation HTTP %d: %s", r.status_code, r.text[:500])
            if r.status_code == 404:
                raise RuntimeError(
                    "Activation failed (HTTP 404). The activation code has likely expired.\n"
                    "Generate a new one from your Duo device management portal."
                )
            raise RuntimeError(f"Activation failed (HTTP {r.status_code})")

        body = r.json()
        if body.get("stat") != "OK":
            log.error("Duo returned: %s", body)
            raise RuntimeError(f"Duo activation error: {body.get('message', body)}")

        device = body.get("response", {})
        self.akey = device.get("akey")
        self.pkey = device.get("pkey")
        # The response may contain the correct API host; prefer it.
        api_host = device.get("host")
        if api_host:
            self.host = api_host

        log.info("Activation successful!")
        log.info("  pkey = %s", self.pkey)
        log.info("  akey = %s", self.akey)
        log.info("  host = %s", self.host)

    # ------------------------------------------------------------------
    # Duo API request signing  (RSASSA-PKCS1-v1_5 / SHA-512)
    # ------------------------------------------------------------------
    def _sign(self, method: str, path: str, timestamp: str, params: dict) -> str:
        """Build the ``Authorization: Basic …`` header value.

        The canonical request signed is::

            <timestamp>\\n
            <METHOD>\\n
            <host>\\n
            <path>\\n
            <url-encoded sorted params>

        This matches both the original Ruo library and the Auto-2FA
        extension's ``buildRequest()`` implementation.
        """
        # Sort params alphabetically by key — critical for signature match
        sorted_params = sorted(params.items())
        encoded = urllib.parse.urlencode(sorted_params)

        canon = (
            timestamp + "\n"
            + method.upper() + "\n"
            + self.host.lower() + "\n"
            + path + "\n"
            + encoded
        )

        h = SHA512.new(canon.encode("ascii"))
        sig = pkcs1_15.new(self._rsa_key).sign(h)
        sig_b64 = base64.b64encode(sig).decode("ascii")

        cred = self.pkey + ":" + sig_b64
        auth = "Basic " + base64.b64encode(cred.encode("ascii")).decode("ascii")
        return auth

    def _timestamp(self) -> str:
        """RFC-2822 UTC timestamp (matches Ruo's ``email.utils.format_datetime``)."""
        dt = datetime.datetime.utcnow()
        return email.utils.format_datetime(dt)

    # ------------------------------------------------------------------
    # API methods
    # ------------------------------------------------------------------
    def get_transactions(self) -> dict:
        """GET /push/v2/device/transactions — fetch pending push requests."""
        ts = self._timestamp()
        path = "/push/v2/device/transactions"
        params = {
            "akey": self.akey,
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512",
        }
        auth = self._sign("GET", path, ts, params)
        r = requests.get(
            f"https://{self.host}{path}",
            params=params,
            headers={
                "Authorization": auth,
                "x-duo-date": ts,
                "Host": self.host,
            },
            timeout=10,
        )
        return r.json()

    def approve_transaction(self, urgid: str) -> dict:
        """POST /push/v2/device/transactions/{urgid} — approve a push.

        The ``answer=approve`` field is what tells Duo to approve.
        All fields that are signed must also be sent and vice-versa.
        Follows the original Ruo ``reply_transaction`` implementation.
        """
        ts = self._timestamp()
        path = f"/push/v2/device/transactions/{urgid}"
        data = {
            "akey": self.akey,
            "answer": "approve",
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512",
        }
        auth = self._sign("POST", path, ts, data)
        r = requests.post(
            f"https://{self.host}{path}",
            data=data,
            headers={
                "Authorization": auth,
                "x-duo-date": ts,
                "Host": self.host,
                "txId": urgid,
            },
            timeout=10,
        )
        return r.json()

    def deny_transaction(self, urgid: str) -> dict:
        """POST /push/v2/device/transactions/{urgid} — deny a push."""
        ts = self._timestamp()
        path = f"/push/v2/device/transactions/{urgid}"
        data = {
            "akey": self.akey,
            "answer": "deny",
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512",
        }
        auth = self._sign("POST", path, ts, data)
        r = requests.post(
            f"https://{self.host}{path}",
            data=data,
            headers={
                "Authorization": auth,
                "x-duo-date": ts,
                "Host": self.host,
                "txId": urgid,
            },
            timeout=10,
        )
        return r.json()

    def get_device_info(self) -> dict:
        """GET /push/v2/device/info — query device status."""
        ts = self._timestamp()
        path = "/push/v2/device/info"
        params = {
            "akey": self.akey,
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512",
        }
        auth = self._sign("GET", path, ts, params)
        r = requests.get(
            f"https://{self.host}{path}",
            params=params,
            headers={
                "Authorization": auth,
                "x-duo-date": ts,
                "Host": self.host,
            },
            timeout=10,
        )
        return r.json()

    # ------------------------------------------------------------------
    # Readiness check
    # ------------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        return all([self.pkey, self.akey, self.host, self._rsa_key])


# ═══════════════════════════════════════════════════════════════════════════
# Setup helpers
# ═══════════════════════════════════════════════════════════════════════════

def interactive_setup() -> DuoClient:
    """Walk the user through first-time setup."""
    client = DuoClient()

    while True:
        print()
        print("=" * 60)
        print("  Duo Auto-Approver — First-Time Setup")
        print("=" * 60)
        print()
        print("  1) Activate with a new code (QR code / emailed link)")
        print("  2) Import Auto-2FA browser extension export")
        print("  3) Import existing Ruo response.json + key.pem")
        print("  q) Quit")
        print()
        try:
            choice = input("Choose [1/2/3/q]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print("No input available. Exiting.")
            sys.exit(1)

        if choice.lower() == "q":
            print("Exiting.")
            sys.exit(0)

        if choice == "1":
            print()
            print("Get an activation code by adding a new device in your Duo")
            print("device management portal.  Choose 'tablet' and either scan")
            print("the QR code or email yourself the activation link.")
            print()
            print("The code looks like:  ABCDEFGHIJKLMNOPQRST-YXBpLTEyMzQ1Ng...")
            print("Or paste the full URL: https://m-XXXX.duosecurity.com/…/CODE")
            print()
            raw = input("Activation code or URL: ").strip()
            if not raw:
                print("No code provided. Try again.")
                continue
            client.activate(raw)
            client.save_config()
            print()
            print("Activation complete! Credentials saved.")
            return client

        elif choice == "2":
            print()
            print("In the Auto-2FA extension go to Settings → Export, and save")
            print("the JSON file.  It must contain: pkey, akey, host, privateRaw.")
            print()
            path = input("Path to export JSON: ").strip()
            if not path or not os.path.isfile(path):
                print(f"File not found: {path}")
                continue
            client.import_auto2fa_export(path)
            client.save_config()
            print("Import complete! Credentials saved.")
            return client

        elif choice == "3":
            print()
            resp_path = input("Path to response.json [response.json]: ").strip() or "response.json"
            key_path = input("Path to key.pem [key.pem]: ").strip() or "key.pem"
            if not os.path.isfile(resp_path):
                print(f"File not found: {resp_path}")
                continue
            if not os.path.isfile(key_path):
                print(f"File not found: {key_path}")
                continue
            client.import_ruo_files(resp_path, key_path)
            client.save_config()
            print("Import complete! Credentials saved.")
            return client

        else:
            print(f"Invalid choice: {choice!r}. Please enter 1, 2, 3, or q.")


# ═══════════════════════════════════════════════════════════════════════════
# Main approval loop
# ═══════════════════════════════════════════════════════════════════════════

def run_forever(client: DuoClient):
    """Poll Duo for pending push requests and auto-approve them."""
    log.info("=" * 50)
    log.info("Duo Auto-Approver running")
    log.info("  host = %s", client.host)
    log.info("  pkey = %s", client.pkey)
    log.info("  poll = every %ds", POLL_INTERVAL)
    log.info("=" * 50)

    consecutive_errors = 0

    while True:
        try:
            result = client.get_transactions()
            stat = result.get("stat")

            if stat != "OK":
                consecutive_errors += 1
                msg = result.get("message", result.get("message_detail", ""))
                log.warning("API error (stat=%s): %s", stat, msg)
                if consecutive_errors >= 30:
                    log.error("30+ consecutive errors — check credentials / network")
                    consecutive_errors = 0
                time.sleep(POLL_INTERVAL)
                continue

            consecutive_errors = 0
            txns = result.get("response", {}).get("transactions", [])

            if txns:
                log.info("Found %d pending push request(s)", len(txns))
                for tx in txns:
                    urgid = tx.get("urgid", "")
                    # Log whatever identifying info is available
                    attrs = tx.get("attributes", [])
                    log.info("  -> Approving urgid=%s  %s", urgid, _summarise_tx(tx))
                    try:
                        resp = client.approve_transaction(urgid)
                        if resp.get("stat") == "OK":
                            log.info("     APPROVED")
                        else:
                            log.warning("     Duo returned: %s", resp)
                    except Exception as e:
                        log.error("     Error approving %s: %s", urgid, e)
                    time.sleep(1)
            # else: no transactions — silently continue

        except requests.exceptions.ConnectionError:
            consecutive_errors += 1
            log.warning("Connection error (attempt %d), retrying...", consecutive_errors)
        except KeyboardInterrupt:
            log.info("Shutting down (KeyboardInterrupt)")
            break
        except Exception as e:
            consecutive_errors += 1
            log.error("Unexpected error: %s", e, exc_info=True)

        time.sleep(POLL_INTERVAL)


def _summarise_tx(tx: dict) -> str:
    """Pull a short human-readable summary from a transaction dict."""
    parts = []
    # Try various structures Duo might return
    user = tx.get("user", {})
    if isinstance(user, dict) and user.get("name"):
        parts.append(f"user={user['name']}")
    factors = tx.get("factors")
    if factors:
        parts.append(f"factors={factors}")
    return "  ".join(parts) if parts else ""


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    global POLL_INTERVAL

    parser = argparse.ArgumentParser(
        description="Duo Auto-Approver — approve Duo push requests without a phone."
    )
    parser.add_argument(
        "code",
        nargs="?",
        default=None,
        help="Activation code (CODE-BASE64HOST) or activation URL for first-time setup",
    )
    parser.add_argument(
        "--import",
        dest="import_file",
        default=None,
        help="Path to an Auto-2FA export JSON to import",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=POLL_INTERVAL,
        help=f"Seconds between polls (default: {POLL_INTERVAL})",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        default=False,
        help="Run activation/import only, then exit (don't start the approval loop)",
    )
    args = parser.parse_args()

    POLL_INTERVAL = args.poll_interval

    client = DuoClient()

    # ── Decide how to initialise ──────────────────────────────────────
    if args.import_file:
        # Import from Auto-2FA export JSON
        client.import_auto2fa_export(args.import_file)
        client.save_config()

    elif args.code:
        # Activate with a code passed on the command line
        client.activate(args.code)
        client.save_config()

    elif os.path.isfile(CONFIG_FILE) and os.path.isfile(KEY_FILE):
        # We already have saved credentials — just load them
        client.load_config()

    else:
        # Nothing saved yet → interactive setup
        client = interactive_setup()

    # ── Sanity check ──────────────────────────────────────────────────
    if not client.is_ready:
        log.error(
            "Missing credentials (pkey=%s, akey=%s, host=%s, key=%s). "
            "Run setup again or provide an activation code.",
            client.pkey, client.akey, client.host,
            "OK" if client._rsa_key else "MISSING",
        )
        sys.exit(1)

    # ── Setup-only mode: exit before starting the loop ────────────────
    if args.setup_only:
        log.info("Setup complete (--setup-only). Exiting.")
        sys.exit(0)

    # ── Quick connectivity test ───────────────────────────────────────
    try:
        log.info("Testing connectivity with device_info call...")
        info = client.get_device_info()
        if info.get("stat") == "OK":
            log.info("Device info OK — device is properly registered")
        else:
            log.warning("device_info returned: %s", info)
            log.warning("Continuing anyway — transactions poll may still work")
    except Exception as e:
        log.warning("device_info test failed: %s — continuing anyway", e)

    # ── Start the main loop ───────────────────────────────────────────
    run_forever(client)


if __name__ == "__main__":
    main()
