# client_C.py

import socket, json, time, threading
from pathlib import Path
from cryptography import x509

import crypto_utils as cu
from auth_manager import AuthManager

HOST, PORT = '127.0.0.1', 8000
KEY_PATH, CERTS_DIR = 'Keys/C_priv.pem', 'Certs'
CERT_FILE = Path(CERTS_DIR) / 'C.pem'

def recv_loop(sock, Kabc):
    while True:
        raw = sock.recv(65536)
        if not raw:
            print("Connection closed.")
            break
        for msg in raw.decode().splitlines():
            pkt = json.loads(msg)
            pt = cu.aesgcm_decrypt(
                Kabc,
                bytes.fromhex(pkt['nonce']),
                bytes.fromhex(pkt['ct'])
            )
            print(f"\n[{pkt['from']}] {pt.decode()}\n> ", end='', flush=True)

def main():
    sock = socket.create_connection((HOST, PORT))
    sock.send(json.dumps({'id': 'C'}).encode())

    auth = AuthManager(KEY_PATH, CERTS_DIR)
    pk_A = auth.get_cert('A').public_key()
    pk_B = auth.get_cert('B').public_key()
    certC_pem = CERT_FILE.read_text()

    # === Step 2 & 4: Receive Na and Nb ===
    Na, Nb = None, None
    session = None

    while Na is None or Nb is None:
        raw = sock.recv(65536)
        for msg in raw.decode().splitlines():
            fwd = json.loads(msg)
            step = fwd.get('step')
            if step not in (2, 4):
                continue

            assert auth.is_fresh(fwd['timestamp'])
            sender_cert = x509.load_pem_x509_certificate(fwd['cert_sender'].encode())
            assert auth.verify(bytes.fromhex(fwd['sig_sender']),
                               bytes.fromhex(fwd['hash']), sender_cert)

            if step == 2 and Na is None:
                Na = cu.rsa_oaep_decrypt(bytes.fromhex(fwd['enc_nonce']), auth._sk)
                session = fwd['session']
                print("[C] Got Na")

            elif step == 4 and Nb is None:
                Nb = cu.rsa_oaep_decrypt(bytes.fromhex(fwd['enc_nonce']), auth._sk)
                print("[C] Got Nb")

    # === Step 5: Send Nc ===
    Nc = cu.generate_nonce()
    T5 = time.time()
    enc_to_A = cu.rsa_oaep_encrypt(Nc, pk_A).hex()
    enc_to_B = cu.rsa_oaep_encrypt(Nc, pk_B).hex()
    hC = cu.hash_sha256(session.encode() + str(T5).encode() + Nc + b"A" + b"B" + b"C").hex()
    sigC = auth.sign(bytes.fromhex(hC)).hex()
    msg5 = {
        'session': session, 'timestamp': T5,
        'from': 'C', 'step': 5,
        'enc_to_A': enc_to_A, 'enc_to_B': enc_to_B,
        'hash': hC, 'sig': sigC, 'certC': certC_pem
    }
    sock.send(json.dumps(msg5).encode())
    print("[C] Sent step 5")

    # === Step 7: Derive shared key Kabc ===
    IKM = Na + Nb + Nc
    Kabc = cu.hkdf_extract_and_expand(b'\x00' * 32, IKM, b"GroupChatKabc", length=32)
    print(f"[C] Kabc = {Kabc.hex()}")

    # === Step 8: Chat loop ===
    threading.Thread(target=recv_loop, args=(sock, Kabc), daemon=True).start()
    while True:
        text = input("> ")
        if not text:
            continue
        nonce, ct = cu.aesgcm_encrypt(Kabc, text.encode())
        sock.send(json.dumps({'from': 'C', 'nonce': nonce.hex(), 'ct': ct.hex()}).encode())

if __name__ == '__main__':
    main()
