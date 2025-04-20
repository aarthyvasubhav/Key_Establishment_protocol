# auth_manager.py

import os
import time
from typing import Set, Tuple

from cryptography import x509
from cryptography.x509 import Certificate

import crypto_utils as cu


class AuthManager:
    """
    Manages authentication, signature verification, timestamp freshness,
    and replay protection for the Secure Chat protocol.
    """

    def __init__(self, private_key_path: str, certs_dir: str, max_skew: float = 30.0):
        """
        :param private_key_path: Path to this entity's PEM‑encoded RSA private key.
        :param certs_dir: Directory containing PEM‑encoded certificates (A.pem, B.pem, C.pem, S.pem).
        :param max_skew: Allowed maximum clock skew in seconds for timestamp freshness.
        """
        # Load own private key
        with open(private_key_path, "rb") as f:
            self._sk = cu.load_private_key(f.read())
        self._max_skew = max_skew

        # Replay cache: stores (session_id, hash) tuples
        self._seen: Set[Tuple[str, bytes]] = set()

        # Load all certificates from certs_dir
        self._certs = {}
        for fname in os.listdir(certs_dir):
            if fname.endswith(".pem"):
                path = os.path.join(certs_dir, fname)
                with open(path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                entity = os.path.splitext(fname)[0]  # e.g. "A" from "A.pem"
                self._certs[entity] = cert

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using RSA‑PSS (SHA‑256).
        """
        return cu.rsa_pss_sign(message, self._sk)

    def verify(self, signature: bytes, message: bytes, cert: Certificate) -> bool:
        """
        Verify an RSA‑PSS signature against the public key in a certificate.
        """
        pub = cert.public_key()
        return cu.rsa_pss_verify(signature, message, pub)

    def is_fresh(self, timestamp: float) -> bool:
        """
        Check if the provided timestamp is within allowed skew of current time.
        """
        return abs(time.time() - timestamp) <= self._max_skew

    def check_and_record(self, session: str, hash_data: bytes) -> bool:
        """
        Check replay cache for (session, hash_data). If unseen, record it and return True.
        If already seen, return False to indicate a replay.
        """
        key = (session, hash_data)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def get_cert(self, entity: str) -> Certificate:
        """
        Retrieve a loaded certificate for an entity ('A', 'B', 'C', or 'S').
        """
        return self._certs.get(entity)
