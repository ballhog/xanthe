"""Coeno machine key for Xanthe (Coeno Group 7 sign-in, 2026-10-14).

Importing this module adds `Authorization: Bearer <key>` to every urllib request
this process makes to Coeno, and to nothing else. The key lives in
/etc/reefcore/coeno.key (root, mode 600) and is read on each request, so a new key
takes effect without restarting nz-home. No key file = no header, which is fine
while Coeno is in "Public view" (reads open); in "Sign-in only" the key is what
keeps the readings flowing.

Get or replace the key:  /opt/reefcore/coeno-key.py request   (then approve its code)
Check it:                /opt/reefcore/coeno-key.py check
"""
import os
import urllib.request

KEY_FILE = "/etc/reefcore/coeno.key"
OLD_KEY_FILE = "/etc/reefcore/lsss.key"   # read if coeno.key is missing (rename 2026-10-21)
COENO_HOSTS = {h.strip() for h in os.environ.get(
    "COENO_HOSTS", os.environ.get("LSSS_HOSTS", "10.0.0.228:8000,100.79.0.32:8000")).split(",") if h.strip()}


def key():
    for path in (KEY_FILE, OLD_KEY_FILE):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            continue
    return ""


class _CoenoKey(urllib.request.BaseHandler):
    handler_order = 100          # before the default handlers send the request

    def http_request(self, req):
        if req.host in COENO_HOSTS and not req.has_header("Authorization"):
            k = key()
            if k:
                req.add_unredirected_header("Authorization", f"Bearer {k}")
        return req

    https_request = http_request


urllib.request.install_opener(urllib.request.build_opener(_CoenoKey()))
