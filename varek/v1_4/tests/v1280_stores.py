# SPDX-License-Identifier: MIT
"""v1280_stores.py — stand-ins for the stores warden-secrets reads, for
test_v1280.sh section 2: HashiCorp Vault (KV version 2, version 1 and a
leased secret), AWS Secrets Manager (each request's SigV4 signature checked,
written here from the AWS documentation, apart from the C signer) and the
instance metadata service (IMDSv2). Vault and Secrets Manager are served
over HTTPS with a CA made for the test; the metadata service over HTTP.
v1.36 step 4 (D1): and the DaemonSet's sign-ins, each checking the token it
is given: Vault's Kubernetes login, STS's AssumeRoleWithWebIdentity (IRSA,
over HTTPS) and the EKS Pod Identity agent (over HTTP).

  v1280_stores.py DIR

writes DIR/ca.pem, then serves and writes DIR/ports ("HTTPS_PORT IMDS_PORT")
when ready; each request it answers is logged to DIR/requests.log (method,
path, and for Vault whether the token matched; never a value). Its
certificates last V1280_CERT_HOURS (default 2); tests/soak_v1280 sets it.
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
CERT_HOURS = float(os.environ.get("V1280_CERT_HOURS", "2"))     # the soak needs longer
VAULT_TOKEN = "s.test-token-v1280"
AWS_ID, AWS_SECRET = "AKIDV1280TEST", "v1280-test-secret-key/abc"
ROLE_ID, ROLE_SECRET, ROLE_TOKEN = "ASIAROLEV1280", "role-secret-v1280", "role-session-token-v1280"
# v1.36 step 4: the service account's tokens (JWT-shaped), what each sign-in gives
K8S_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ2YXJlay1ub2RlIn0.c2lnLWs4cy12MTM2MA"
K8S_VAULT_TOKEN = "s.k8s-login-v1360"
IRSA_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJzdHMuYW1hem9uYXdzLmNvbSJ9.c2lnLWlyc2E"
IRSA_ROLE = "arn:aws:iam::111122223333:role/varek-node"
IRSA_ID, IRSA_SECRET, IRSA_TOKEN = "ASIAIRSAV1360", "irsa-secret-v1360/xyz", "irsa-session-token-v1360"
POD_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJwb2RzLmVrcy5hbWF6b25hd3MuY29tIn0.c2lnLXBvZA"
POD_ID, POD_SECRET, POD_TOKEN = "ASIAPODV1360", "pod-secret-v1360", "pod-session-token-v1360"
VALUES = {                                     # what each store holds (test values, not secrets)
    "vault2": "vault-kv2-value-7f3a", "vault1": "vault-kv1-value-91c2", "lease": "db-password-5d8e",
    "short": "db-short-6b1f", "stuck": "db-stuck-0c4a", "soak": "db-soak-3e9d", "aws": "aws-sm-value-c4b1",
}
LOG = open(os.path.join(D, "requests.log"), "a", buffering=1)


def make_tls():
    now = datetime.datetime.now(datetime.timezone.utc)
    ck = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v1280 test CA")])
    ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(hours=CERT_HOURS))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ck, hashes.SHA256()))
    sk = ec.generate_private_key(ec.SECP256R1())
    import ipaddress
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(cn).public_key(sk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=CERT_HOURS))
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
        if p == "/v1/credentials":                                  # v1.36: the EKS Pod Identity agent
            ok = self.headers.get("Authorization") == POD_JWT
            LOG.write(f"pod-identity GET token={'ok' if ok else 'bad'}\n")
            if not ok:
                return self.send(400, {"code": "InvalidTokenException"})
            return self.send(200, {"AccessKeyId": POD_ID, "SecretAccessKey": POD_SECRET, "Token": POD_TOKEN,
                                   "AccountId": "111122223333", "Expiration": "2099-01-01T00:00:00Z"})
        if p.startswith("/v1/"):                                   # Vault
            ok = self.headers.get("X-Vault-Token") in (VAULT_TOKEN, K8S_VAULT_TOKEN)
            LOG.write(f"vault GET {p} token={'ok' if ok else 'bad'}"
                      + (" (the Kubernetes login's)" if self.headers.get("X-Vault-Token") == K8S_VAULT_TOKEN else "") + "\n")
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
            if p == "/v1/database/creds/short":                       # v1.28 step 4: renewed at 2 s
                return self.send(200, {"lease_id": "database/creds/short/Rn7", "lease_duration": 3,
                                       "renewable": True, "data": {"password": VALUES["short"], "username": "u"}})
            if p == "/v1/database/creds/soak":                        # the soak (tests/soak_v1280): 60 s
                return self.send(200, {"lease_id": "database/creds/soak/Sk1", "lease_duration": 60,
                                       "renewable": True, "data": {"password": VALUES["soak"], "username": "u"}})
            if p == "/v1/database/creds/stuck":                       # its renewal is refused
                return self.send(200, {"lease_id": "database/creds/stuck/Fx2", "lease_duration": 3,
                                       "renewable": True, "data": {"password": VALUES["stuck"], "username": "u"}})
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
        if self.path in ("/v1/sys/leases/revoke", "/v1/sys/leases/renew"):      # v1.28 step 4
            ok = self.headers.get("X-Vault-Token") == VAULT_TOKEN
            try:
                j = json.loads(self.body() or b"{}")
            except ValueError:
                j = {}
            op = self.path.rsplit("/", 1)[1]
            lid = j.get("lease_id", "-")
            LOG.write(f"vault PUT {op} {lid} token={'ok' if ok else 'bad'}"
                      + (f" increment={j.get('increment')}" if op == "renew" else "") + "\n")
            if not ok:
                return self.send(403, {"errors": ["permission denied"]})
            if op == "revoke":
                return self.send(204, b"")
            if lid.endswith("/Fx2"):
                return self.send(400, {"errors": ["lease is not renewable"]})
            ttl = 60 if lid.endswith("/Sk1") else 3
            return self.send(200, {"lease_id": lid, "lease_duration": ttl, "renewable": True, "data": None})
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
        if self.path.startswith("/v1/auth/") and self.path.endswith("/login"):      # v1.36: Vault's Kubernetes auth
            try:
                j = json.loads(b or b"{}")
            except ValueError:
                j = {}
            mount = self.path[len("/v1/auth/"):-len("/login")]
            ok = j.get("jwt") == K8S_JWT and j.get("role") == "agents"
            LOG.write(f"vault POST login mount={mount} role={j.get('role')} jwt={'ok' if ok else 'bad'}\n")
            if not ok:
                return self.send(403, {"errors": ["permission denied"]})
            return self.send(200, {"auth": {"client_token": K8S_VAULT_TOKEN, "lease_duration": 3600}})
        if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):  # v1.36: STS
            import urllib.parse
            q = dict(urllib.parse.parse_qsl(b.decode()))
            ok = (q.get("Action") == "AssumeRoleWithWebIdentity" and q.get("WebIdentityToken") == IRSA_JWT
                  and q.get("RoleArn") == IRSA_ROLE and q.get("RoleSessionName") and q.get("Version") == "2011-06-15")
            LOG.write(f"sts POST {q.get('Action')} role={q.get('RoleArn')} token={'ok' if ok else 'bad'}\n")
            if not ok:
                return self.send(403, b"<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>")
            x = ("<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                 "<AssumeRoleWithWebIdentityResult><Credentials>"
                 f"<AccessKeyId>{IRSA_ID}</AccessKeyId><SecretAccessKey>{IRSA_SECRET}</SecretAccessKey>"
                 f"<SessionToken>{IRSA_TOKEN}</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>"
                 "</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>")
            return self.send(200, x.encode())
        if self.headers.get("X-Amz-Target") != "secretsmanager.GetSecretValue":
            return self.send(400, {"__type": "UnknownOperation"})
        h = {k.lower(): v for k, v in self.headers.items()}
        h["Authorization"] = self.headers.get("Authorization", "")
        h["X-Amz-Date"] = self.headers.get("X-Amz-Date", "")
        akid = h["Authorization"].split("Credential=")[-1].split("/")[0]
        secret = {AWS_ID: AWS_SECRET, ROLE_ID: ROLE_SECRET, IRSA_ID: IRSA_SECRET, POD_ID: POD_SECRET}.get(akid)
        tok_ok = h.get("x-amz-security-token") == {ROLE_ID: ROLE_TOKEN, IRSA_ID: IRSA_TOKEN,
                                                    POD_ID: POD_TOKEN}.get(akid, h.get("x-amz-security-token"))
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
