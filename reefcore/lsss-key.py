#!/usr/bin/env python3
"""Ask Coeno for Xanthe's machine key, or check the one we have.

  coeno-key.py request [scope ...]   ask for a key (default scope: read = read only),
                                    print the code to approve, wait up to 5 min,
                                    save it to /etc/reefcore/coeno.key (mode 600)
  coeno-key.py check                 ask Coeno who this key belongs to

Approve the code on Coeno: lock button -> Waiting for approval, Coeno
Telegram bot, or over SSH on the Pi: ~/coeno/.venv/bin/python -m coeno.auth approve <code>
"""
import json, os, sys, time, urllib.request

sys.path.insert(0, "/opt/reefcore")
import coeno_auth  # noqa: E402

COENO = "http://10.0.0.228:8000"
NAME = "Xanthe (reefcore)"


def call(path, body=None, auth=True):
    req = urllib.request.Request(COENO + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    if not auth:
        req.add_header("Authorization", "none")   # suppress coeno_auth's header
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def request(scopes):
    j = call("/api/auth/start", {"name": NAME, "machine": True, "scopes": scopes or ["read"]}, auth=False)
    print(f"CODE {j['code']}  (approve on Coeno within {j['expires'] // 60} min)", flush=True)
    end = time.time() + j["expires"]
    while time.time() < end:
        time.sleep(3)
        r = call(f"/api/auth/poll?id={j['id']}&nonce={j['nonce']}", auth=False)
        if r["state"] == "ok" and r.get("key"):
            os.makedirs(os.path.dirname(coeno_auth.KEY_FILE), mode=0o700, exist_ok=True)
            tmp = coeno_auth.KEY_FILE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(r["key"] + "\n")
            os.replace(tmp, coeno_auth.KEY_FILE)
            print("APPROVED - key saved to", coeno_auth.KEY_FILE, flush=True)
            return check()
        if r["state"] != "waiting":
            print("NOT APPROVED:", r["state"], flush=True)
            return 1
    print("EXPIRED - nobody approved it in time", flush=True)
    return 1


def check():
    if not coeno_auth.key():
        print("No key in", coeno_auth.KEY_FILE)
        return 1
    m = call("/api/auth/me").get("machine")
    if not m:
        print("Coeno does not recognise this key (revoked, or Coeno is older than the key feature).")
        return 1
    print(f"Key OK: {m['name']} - {m['access']}")
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["request"]:
        sys.exit(request(a[1:]))
    if a[:1] == ["check"]:
        sys.exit(check())
    print(__doc__)
