# SPDX-License-Identifier: MIT
"""v1280_stores.py — stand-ins for the stores warden-secrets reads, for
test_v1280.sh section 2: HashiCorp Vault (KV version 2, version 1 and a
leased secret), AWS Secrets Manager (each request's SigV4 signature checked,
written here from the AWS documentation, apart from the C signer) and the
instance metadata service (IMDSv2). Vault and Secrets Manager are served
over HTTPS with a CA made for the test; the metadata service over HTTP.

  v1280_stores.py DIR

writes DIR/ca.pem, then serves and writes DIR/ports ("HTTPS_PORT IMDS_PORT")
when ready; each request it answers is logged to DIR/requests.log (method,
path, and for Vault whether the token matched; never a value).
"""
import datetime
import hashlib
import hmac
import http.server
import json
import os
import ssl
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

D = sys.argv[1]
VAULT_TOKEN = "s.test-token-v1280"
AWS_ID, AWS_SECRET = "AKIDV1280TEST", "v1280-test-secret-key/abc"
ROLE_ID, ROLE_SECRET, ROLE_TOKEN = "ASIAROLEV1280", "role-secret-v1280", "role-session-token-v1280"
VALUES = {                                     # what each store holds (test values, not secrets)
    "vault2": "vault-kv2-value-7f3a", "vault1": "vault-kv1-value-91c2", "lease": "db-password-5d8e",
    "aws": "aws-sm-value-c4b1",
}
LOG = open(os.path.join(D, "requests.log"), "a", buffering=1)


def make_tls():
    now = datetime.datetime.now(datetime.timezone.utc)
    ck = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v1280 test CA")])
    ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ck, hashes.SHA256()))
    sk = ec.generate_private_key(ec.SECP256R1())
    import ipaddress
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(cn).public_key(sk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(ck, hashes.SHA256()))
    with open(os.path.join(D, "ca.pem"), "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(D, "server.pem"), "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()))


def sigv4_ok(h, method, path, body, secret):
    """Check the request's Authorization against our own SigV4 computation."""
    auth = h.get("Authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return False
    parts = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
    akid, day, region, service, term = parts["Credential"].split("/")
    signed = parts["SignedHeaders"].split(";")
    canon_h = "".join(f"{n}:{h.get(n, '').strip()}\n" for n in signed)
    canon = "\n".join([method, path, "", canon_h, ";".join(signed), hashlib.sha256(body).hexdigest()])
    scope = f"{day}/{region}/{service}/{term}"
    sts = "\n".join(["AWS4-HMAC-SHA256", h.get("X-Amz-Date", ""), scope,
                     hashlib.sha256(canon.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for m in (day, region, service, term):
        k = hmac.new(k, m.encode(), hashlib.sha256).digest()
    want = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, parts["Signature"]) and service == "secretsmanager" and term == "aws4_request"


class Stores(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, obj, chunked=False):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(b), 7):
                c = b[i:i + 7]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(c), c))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        p = self.path
        if p.startswith("/v1/"):                                   # Vault
            ok = self.headers.get("X-Vault-Token") == VAULT_TOKEN
            LOG.write(f"vault GET {p} token={'ok' if ok else 'bad'}\n")
            if not ok:
                return self.send(403, {"errors": ["permission denied"]})
            if p == "/v1/secret/data/agents/gh":
                return self.send(200, {"data": {"data": {"token": VALUES["vault2"], "other": "x"},
                                                "metadata": {"version": 3}}}, chunked=True)
            if p == "/v1/kv1/thing":
                return self.send(200, {"lease_id": "", "data": {"value": VALUES["vault1"]}})
            if p == "/v1/database/creds/ro":
                return self.send(200, {"lease_id": "database/creds/ro/AbC123", "lease_duration": 3600,
                                       "renewable": True, "data": {"password": VALUES["lease"], "username": "u"}})
            if p == "/v1/secret/data/agents/nl":
                return self.send(200, {"data": {"data": {"token": "two\nlines"}, "metadata": {"version": 1}}})
            return self.send(404, {"errors": []})
        if p.startswith("/latest/meta-data/iam/security-credentials/"):     # IMDS
            if self.headers.get("X-aws-ec2-metadata-token") != "imds-token-v1280":
                return self.send(401, b"")
            role = p[len("/latest/meta-data/iam/security-credentials/"):]
            LOG.write(f"imds GET role={role or '-'}\n")
            if not role:
                b = b"v1280-role\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                return self.wfile.write(b)
            return self.send(200, {"Code": "Success", "AccessKeyId": ROLE_ID, "SecretAccessKey": ROLE_SECRET,
                                   "Token": ROLE_TOKEN})
        self.send(404, b"")

    def do_PUT(self):
        if self.path == "/latest/api/token" and self.headers.get("X-aws-ec2-metadata-token-ttl-seconds"):
            LOG.write("imds PUT token\n")
            b = b"imds-token-v1280"
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        self.send(404, b"")

    def do_POST(self):
        b = self.body()
        if self.headers.get("X-Amz-Target") != "secretsmanager.GetSecretValue":
            return self.send(400, {"__type": "UnknownOperation"})
        h = {k.lower(): v for k, v in self.headers.items()}
        h["Authorization"] = self.headers.get("Authorization", "")
        h["X-Amz-Date"] = self.headers.get("X-Amz-Date", "")
        akid = h["Authorization"].split("Credential=")[-1].split("/")[0]
        secret = {AWS_ID: AWS_SECRET, ROLE_ID: ROLE_SECRET}.get(akid)
        tok_ok = akid != ROLE_ID or h.get("x-amz-security-token") == ROLE_TOKEN
        ok = secret is not None and tok_ok and sigv4_ok(h, "POST", self.path, b, secret)
        sid = json.loads(b or b"{}").get("SecretId", "")
        LOG.write(f"aws POST id={sid} key={akid} signature={'ok' if ok else 'bad'}\n")
        if not ok:
            return self.send(403, {"__type": "InvalidSignatureException"})
        if sid.endswith(":secret:binary-Xy"):
            return self.send(200, {"ARN": sid, "SecretBinary": "AAEC", "VersionId": "v-bin"})
        if sid.endswith(":secret:stripe-AbCdEf"):
            return self.send(200, {"ARN": sid, "SecretString": VALUES["aws"],
                                   "VersionId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"})
        return self.send(400, {"__type": "ResourceNotFoundException"})


class Threaded(http.server.ThreadingHTTPServer):
    daemon_threads = True


make_tls()
https = Threaded(("127.0.0.1", 0), Stores)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(D, "server.pem"))
https.socket = ctx.wrap_socket(https.socket, server_side=True)
imds = Threaded(("127.0.0.1", 0), Stores)
for s in (https, imds):
    threading.Thread(target=s.serve_forever, daemon=True).start()
with open(os.path.join(D, "ports.tmp"), "w") as f:
    f.write(f"{https.server_address[1]} {imds.server_address[1]}\n")
os.rename(os.path.join(D, "ports.tmp"), os.path.join(D, "ports"))
threading.Event().wait()
