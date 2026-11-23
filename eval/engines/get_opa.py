"""Download the pinned OPA binary (Windows amd64) from the official release and verify its SHA-256."""
import urllib.request, hashlib, os
V = "v1.22.4"; SHA = "4cd179b95041aa50c44241324da3becf35d0b28dca92bf10a07f32d002724d5e"
url = f"https://github.com/open-policy-agent/opa/releases/download/{V}/opa_windows_amd64.exe"
dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "opa.exe"); os.makedirs(os.path.dirname(dest), exist_ok=True)
data = urllib.request.urlopen(url).read()
assert hashlib.sha256(data).hexdigest() == SHA, "checksum mismatch"
open(dest, "wb").write(data); print("opa", V, "ok")
