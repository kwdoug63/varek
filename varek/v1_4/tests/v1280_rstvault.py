# SPDX-License-Identifier: MIT
"""v1280_rstvault.py DIR — for test_v1280.sh section 6 (v1.28 review): a
Vault-like TLS server on 127.0.0.1. The first
connection gets a renewable 3 s lease; each later one is closed with a
reset right after the handshake (a Vault restarting, a load balancer
dropping it). Writes DIR/ca.pem and DIR/port."""
import datetime, ipaddress, json, os, socket, ssl, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

D = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
ck = ec.generate_private_key(ec.SECP256R1())
cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rst CA")])
ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
      .not_valid_after(now + datetime.timedelta(hours=1))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ck, hashes.SHA256()))
sk = ec.generate_private_key(ec.SECP256R1())
leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .issuer_name(cn).public_key(sk.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(ck, hashes.SHA256()))
open(os.path.join(D, "ca.pem"), "wb").write(ca.public_bytes(serialization.Encoding.PEM))
with open(os.path.join(D, "server.pem"), "wb") as f:
    f.write(leaf.public_bytes(serialization.Encoding.PEM))
    f.write(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(D, "server.pem"))
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(8)
open(os.path.join(D, "port"), "w").write(str(ls.getsockname()[1]))
log = open(os.path.join(D, "log"), "a", buffering=1)
n = 0
while True:
    c, _ = ls.accept()
    n += 1
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except Exception as e:
        log.write(f"conn {n}: handshake {e}\n"); c.close(); continue
    if n == 1:
        t.recv(65536)
        b = json.dumps({"lease_id": "database/creds/x/L1", "lease_duration": 3, "renewable": True,
                        "data": {"password": "rst-value"}}).encode()
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(b), b))
        t.close()
        log.write("conn 1: lease\n")
        continue
    t.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    t.close()
    log.write(f"conn {n}: reset after the handshake\n")
