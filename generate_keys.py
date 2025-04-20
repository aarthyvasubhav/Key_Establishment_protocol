# gen_keys_certs.py

import os
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

ENTITIES = ['A','B','C','S']

KEY_DIR  = 'Keys'
CERT_DIR = 'Certs'

def make_dirs():
    os.makedirs(KEY_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)

def gen_key(entity: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = os.path.join(KEY_DIR, f"{entity}_priv.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return key

def gen_cert(key, entity: str):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, entity),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(CERT_DIR, f"{entity}.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    make_dirs()
    for ent in ENTITIES:
        print(f"Generating key and cert for {ent}")
        key = gen_key(ent)
        gen_cert(key, ent)
    print("Done. Keys in ./Keys/, certs in ./Certs/")

if __name__ == "__main__":
    main()
