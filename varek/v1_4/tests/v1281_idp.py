# SPDX-License-Identifier: MIT
"""v1281_idp.py — a stand-in identity provider and SPIFFE authority for
test_v1281.sh section 2 (docs/security/v1.28.1-delegation-chain.md). The
tokens and the SVIDs it makes are signed here, with the cryptography
package, apart from the C verifier in warden-secrets.

  v1281_idp.py serve DIR        make the keys and the TLS certificate, serve
                                over HTTPS (a CA made for the test, DIR/ca.pem)
                                and write DIR/port when ready:
                                  /.well-known/openid-configuration  issuer https://127.0.0.1:PORT
                                  /jwks          one key of each type, each with its kid
                                  /jwks-two      two RSA keys (a token naming no kid is ambiguous)
                                  /liar/.well-known/openid-configuration  names another issuer
                                each request is logged to DIR/requests.log
  v1281_idp.py mint DIR CASE    print a token (see CASES)
  v1281_idp.py svid DIR         write DIR/bundle.pem (example.test's authority),
                                DIR/bundle-other.pem, and DIR/svid-CASE.pem for
                                each SVID case (leaf, its key)
"""
import base64
import datetime
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import ssl
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

AUD = "varek-agent"
PEM = serialization.Encoding.PEM


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def uint(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def key_pem(k):
    return k.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def cert(subject_cn, key, issuer_name, issuer_key, ca, days=1, before=None, san=None, uris=(), ku=None):
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(before or now() - datetime.timedelta(minutes=5))
         .not_valid_after((before or now()) + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    names = list(san or []) + [x509.UniformResourceIdentifier(u) for u in uris]
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if ku is None and ca:
        ku = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                           data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                           encipher_only=False, decipher_only=False)
    if ku:
        b = b.add_extension(ku, critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def ku(sign=True, cert_sign=False):
    return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign, crl_sign=False,
                         encipher_only=False, decipher_only=False)


# ---- serve ----

def serve(d):
    ck = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v1281 test CA")])
    ca = cert("v1281 test CA", ck, cn, ck, True)
    sk = ec.generate_private_key(ec.SECP256R1())
    leaf = cert("localhost", sk, cn, ck, False,
                san=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    open(os.path.join(d, "ca.pem"), "wb").write(ca.public_bytes(PEM))
    open(os.path.join(d, "tls.pem"), "wb").write(leaf.public_bytes(PEM) + key_pem(sk))
    keys = {
        "rsa1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "rsa2": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ec1": ec.generate_private_key(ec.SECP256R1()),
        "ed1": ed25519.Ed25519PrivateKey.generate(),
        "other": ec.generate_private_key(ec.SECP256R1()),   # not in any JWKS
    }
    for name, k in keys.items():
        open(os.path.join(d, "key-%s.pem" % name), "wb").write(key_pem(k))

    def jwk(name):
        k = keys[name].public_key()
        if isinstance(k, rsa.RSAPublicKey):
            n = k.public_numbers()
            return {"kty": "RSA", "kid": name, "use": "sig", "n": uint(n.n), "e": uint(n.e)}
        if isinstance(k, ec.EllipticCurvePublicKey):
            n = k.public_numbers()
            return {"kty": "EC", "kid": name, "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")),
                    "y": b64(n.y.to_bytes(32, "big"))}
        raw = k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "kid": name, "crv": "Ed25519", "x": b64(raw)}

    jwks = {"keys": [jwk("rsa1"), jwk("ec1"), jwk("ed1")]}
    jwks_two = {"keys": [jwk("rsa1"), jwk("rsa2")]}
    # review cases: keys whose use or alg cannot be read (passed over), and one
    # kid on keys of two types (the one of the token's type is used)
    odd = [dict(jwk("ec1"), kid="odd-use", use=["enc"]), dict(jwk("ec1"), kid="odd-alg", alg="ES256" + "x" * 40)]
    shared = [dict(jwk("rsa1"), kid="ec1"), jwk("ec1")]
    log = open(os.path.join(d, "requests.log"), "a", buffering=1)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            base = "https://127.0.0.1:%d" % self.server.server_port
            log.write("GET %s\n" % self.path)
            body = None
            if self.path == "/.well-known/openid-configuration":
                body = {"issuer": base, "jwks_uri": base + "/jwks"}
            elif self.path == "/liar/.well-known/openid-configuration":
                body = {"issuer": base, "jwks_uri": base + "/jwks"}      # not https://.../liar
            elif self.path == "/jwks":
                body = jwks
            elif self.path == "/jwks-set":
                # v1.36 step 6: as the Kubernetes API server serves its keys
                # (application/jwk-set+json only, 406 to a request for JSON alone)
                if "application/jwk-set+json" not in self.headers.get("Accept", ""):
                    self.send_response(406)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                out = json.dumps(jwks).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/jwk-set+json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            elif self.path == "/jwks-two":
                body = jwks_two
            elif self.path == "/jwks-odd":
                body = {"keys": odd}
            elif self.path == "/jwks-shared":
                body = {"keys": shared}
            elif self.path.startswith("/slow/"):
                time.sleep(40)                  # longer than the Warden waits
                body = {"issuer": base + "/slow", "jwks_uri": base + "/jwks"}
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            out = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(d, "tls.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    open(os.path.join(d, "port.tmp"), "w").write("%d\n" % srv.server_port)
    os.rename(os.path.join(d, "port.tmp"), os.path.join(d, "port"))
    srv.serve_forever()


# ---- mint ----

def load(d, name):
    return serialization.load_pem_private_key(open(os.path.join(d, "key-%s.pem" % name), "rb").read(), None)


def sign(d, alg, kid, header, claims, key=None):
    h = {"alg": alg, "typ": "JWT"}
    if kid:
        h["kid"] = kid
    h.update(header)
    si = (b64(json.dumps(h).encode()) + "." + b64(json.dumps(claims).encode())).encode()
    if alg == "none":
        return si.decode() + "."
    if alg == "HS256":                       # the RSA public key as the HMAC secret
        pub = load(d, "rsa1").public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return si.decode() + "." + b64(hmac.new(pub, si, hashlib.sha256).digest())
    k = key or load(d, {"RS256": "rsa1", "PS256": "rsa1", "ES256": "ec1", "EdDSA": "ed1"}[alg])
    if alg == "RS256":
        sig = k.sign(si, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256":
        sig = k.sign(si, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif alg == "ES256":
        r, s = decode_dss_signature(k.sign(si, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = k.sign(si)
    return si.decode() + "." + b64(sig)


def mint(d, case, iss):
    t = int(time.time())
    c = {"iss": iss, "sub": "alice@example.test", "aud": AUD, "exp": t + 3600, "iat": t - 10, "nbf": t - 10,
         "jti": "jti-" + case}
    alg, kid, hdr, key = "ES256", "ec1", {}, None
    if case in ("rs256", "ps256", "eddsa"):
        alg, kid = {"rs256": ("RS256", "rsa1"), "ps256": ("PS256", "rsa1"), "eddsa": ("EdDSA", "ed1")}[case]
    elif case == "es256-nokid":
        kid = None
    elif case == "rs256-nokid":             # with /jwks-two: two RSA keys
        alg, kid = "RS256", None
    elif case == "none":
        alg, kid = "none", None
    elif case == "hs256":
        alg, kid = "HS256", "rsa1"
    elif case == "badsig":
        key = load(d, "other")
    elif case == "unknown-kid":
        kid = "nope"
    elif case == "wrong-iss":
        c["iss"] = "https://idp.elsewhere.test"
    elif case == "wrong-aud":
        c["aud"] = "someone-else"
    elif case == "aud-array":
        c["aud"] = ["someone-else", AUD]
    elif case == "expired":
        c["exp"] = t - 3600
    elif case.startswith("exp") and case[3:].isdigit():     # expiring N s from now (step 4)
        c["exp"] = t + int(case[3:])
    elif case == "near-expiry":
        c["exp"] = t + 20
    elif case == "nbf-future":
        c["nbf"] = t + 600
    elif case == "iat-future":
        c["iat"] = t + 600
    elif case == "no-exp":
        del c["exp"]
    elif case == "no-sub":
        del c["sub"]
    elif case == "sub-ctl":
        c["sub"] = "alice\u0007"
    elif case == "longkey":                 # a claim name over 255 bytes before exp
        c = {k: v for k, v in c.items() if k != "exp"}
        c["k" * 300] = 1
        c["exp"] = t + 3600
    elif case in ("odd-use", "odd-alg"):
        kid = case
    elif case == "crit":
        hdr = {"crit": ["x-varek"], "x-varek": 1}
    elif case == "exchange":                # RFC 8693: two actors, the current one outermost
        c["act"] = {"sub": "agent-orchestrator", "iss": iss, "act": {"sub": "ci-runner"}}
    elif case == "act9":
        a = {"sub": "actor-9"}
        for i in range(8, 0, -1):
            a = {"sub": "actor-%d" % i, "act": a}
        c["act"] = a
    elif case == "act8":
        a = {"sub": "actor-8"}
        for i in range(7, 0, -1):
            a = {"sub": "actor-%d" % i, "act": a}
        c["act"] = a
    elif case != "es256":
        sys.exit("unknown case " + case)
    return sign(d, alg, kid, hdr, c, key)


# ---- svid ----

def svid(d):
    def authority(name):
        k = ec.generate_private_key(ec.SECP256R1())
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        return k, n, cert(name, k, n, k, True)

    ak, an, ac = authority("example.test SPIFFE authority")
    ok_, on, oc = authority("other.test SPIFFE authority")
    open(os.path.join(d, "bundle.pem"), "wb").write(ac.public_bytes(PEM))
    open(os.path.join(d, "bundle-other.pem"), "wb").write(oc.public_bytes(PEM))
    agent = "spiffe://example.test/agents/coder"

    def write(case, crt, key):
        open(os.path.join(d, "svid-%s.pem" % case), "wb").write(crt.public_bytes(PEM) + key_pem(key))

    k = ec.generate_private_key(ec.SECP256R1())
    write("good", cert("agent", k, an, ak, False, uris=[agent], ku=ku()), k)
    old = now() - datetime.timedelta(days=3)
    write("expired", cert("agent", k, an, ak, False, before=old, uris=[agent], ku=ku()), k)
    write("other-domain", cert("agent", k, on, ok_, False, uris=["spiffe://other.test/agents/coder"], ku=ku()), k)
    write("wrong-ca", cert("agent", k, on, ok_, False, uris=[agent], ku=ku()), k)
    k2 = ec.generate_private_key(ec.SECP256R1())
    open(os.path.join(d, "svid-key-mismatch.pem"), "wb").write(
        cert("agent", k, an, ak, False, uris=[agent], ku=ku()).public_bytes(PEM) + key_pem(k2))
    write("two-uris", cert("agent", k, an, ak, False, uris=[agent, "spiffe://example.test/x"], ku=ku()), k)
    write("ca-leaf", cert("agent", k, an, ak, True, uris=[agent], ku=ku(cert_sign=True)), k)
    write("not-spiffe", cert("agent", k, an, ak, False, uris=["https://example.test/agent"], ku=ku()), k)
    # review cases: a leaf with no basicConstraints; a second key that cannot be read
    nb = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
          .issuer_name(an).public_key(k.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now() - datetime.timedelta(minutes=5)).not_valid_after(now() + datetime.timedelta(days=1))
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ak.public_key()), critical=False)
          .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(agent)]), critical=False)
          .add_extension(ku(), critical=True).sign(ak, hashes.SHA256()))
    write("no-bcons", nb, k)
    enc = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
    open(os.path.join(d, "svid-two-keys.pem"), "wb").write(
        cert("agent", k, an, ak, False, uris=[agent], ku=ku()).public_bytes(PEM) + key_pem(k) + enc)
    # through an intermediate in the file
    ik = ec.generate_private_key(ec.SECP256R1())
    inn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test intermediate")])
    ic = cert("example.test intermediate", ik, an, ak, True)
    leaf = cert("agent", k, inn, ik, False, uris=[agent], ku=ku())
    open(os.path.join(d, "svid-chain.pem"), "wb").write(leaf.public_bytes(PEM) + ic.public_bytes(PEM) + key_pem(k))


if __name__ == "__main__":
    cmd, d = sys.argv[1], sys.argv[2]
    if cmd == "serve":
        serve(d)
    elif cmd == "mint":
        port = open(os.path.join(d, "port")).read().strip()
        iss = sys.argv[4] if len(sys.argv) > 4 else "https://127.0.0.1:%s" % port
        print(mint(d, sys.argv[3], iss))
    elif cmd == "svid":
        svid(d)
    else:
        sys.exit(__doc__)
