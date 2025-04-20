# crypto_utils.py

import os
import time
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives import serialization


# ——— Random Nonce & Timestamp ———

def generate_nonce(length: int = 16) -> bytes:
    """
    Generate a cryptographically strong random nonce.
    Default length=16 bytes (128 bits).
    """
    return os.urandom(length)


def current_timestamp() -> float:
    """Return current UTC time in seconds with sub-second precision."""
    return time.time()


# ——— SHA-256 Hash ———

def hash_sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


# ——— RSA-OAEP Encryption / Decryption ———

def rsa_oaep_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ——— RSA-PSS Sign / Verify ———

def rsa_pss_sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_pss_verify(signature: bytes, message: bytes, public_key: rsa.RSAPublicKey) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ——— HKDF-SHA256 Extract & Expand ———

def hkdf_extract_and_expand(
    salt: bytes,
    ikm: bytes,
    info: bytes,
    length: int = 32
) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)



# ——— AES-GCM Encrypt / Decrypt ———

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt `plaintext` under `key` (32 bytes) using AES-GCM.
    Returns (nonce, ciphertext+tag).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt AES-GCM ciphertext+tag under `key` and `nonce`.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ——— Key Loading Helpers ———

def load_private_key(pem_data: bytes, password: bytes = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_data, password=password)

def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_data)
