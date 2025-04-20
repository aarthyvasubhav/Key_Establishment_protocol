# client_A.py

import socket, json, time, uuid, threading
from pathlib import Path
from cryptography import x509

import crypto_utils as cu
from auth_manager import AuthManager

HOST, PORT = '127.0.0.1', 8000
KEY_PATH, CERTS_DIR = 'Keys/A_priv.pem', 'Certs'
CERT_FILE = Path(CERTS_DIR) / 'A.pem'

def recv_loop(sock, Kabc):
    while True:
        raw = sock.recv(65536)
        if not raw:
            print("Connection closed.")
            break
        msg = json.loads(raw.decode())
        pt = cu.aesgcm_decrypt(
            Kabc,
            bytes.fromhex(msg['nonce']),
            bytes.fromhex(msg['ct'])
        )
        print(f"\n[{msg['from']}] {pt.decode()}\n> ", end='', flush=True)

def main():
    # 0) register
    sock = socket.create_connection((HOST, PORT))
    sock.send(json.dumps({'id': 'A'}).encode())

    # load crypto
    auth = AuthManager(KEY_PATH, CERTS_DIR)
    pk_B = auth.get_cert('B').public_key()
    pk_C = auth.get_cert('C').public_key()
    certA_pem = CERT_FILE.read_text()

    # 1) handshake Step 1
    session = str(uuid.uuid4())
    Na = cu.generate_nonce()
    T1 = time.time()
    enc_to_B = cu.rsa_oaep_encrypt(Na, pk_B).hex()
    enc_to_C = cu.rsa_oaep_encrypt(Na, pk_C).hex()
    hA = cu.hash_sha256(
        session.encode()+str(T1).encode()+Na+b"A"+b"B"+b"C"
    ).hex()
    sigA = auth.sign(bytes.fromhex(hA)).hex()
    msg1 = {
        'session': session, 'timestamp': T1,
        'from': 'A', 'step': 1,
        'enc_to_B': enc_to_B, 'enc_to_C': enc_to_C,
        'hash': hA, 'sig': sigA, 'certA': certA_pem
    }
    sock.send(json.dumps(msg1).encode())
    print("[A] Sent step 1… waiting for Nb, Nc")

    # 2) collect Nb (step 4) and Nc (step 6)
    nonces = {'Nb':None,'Nc':None}
    while nonces['Nb'] is None or nonces['Nc'] is None:
        raw = sock.recv(65536)
        fwd = json.loads(raw.decode())
        step = fwd['step']
        # verify freshness + signature…
        sender_cert = x509.load_pem_x509_certificate(fwd['cert_sender'].encode())
        assert auth.is_fresh(fwd['timestamp'])
        assert auth.verify(bytes.fromhex(fwd['sig_sender']),
                           bytes.fromhex(fwd['hash']),
                           sender_cert)
        plain = cu.rsa_oaep_decrypt(bytes.fromhex(fwd['enc_nonce']), auth._sk)
        if step == 4:
            nonces['Nb'] = plain; print("[A] Got Nb")
        elif step == 6:
            nonces['Nc'] = plain; print("[A] Got Nc")

    # 3) derive group key
    IKM = Na + nonces['Nb'] + nonces['Nc']
    Kabc = cu.hkdf_extract_and_expand(b'\x00'*32, IKM, b"GroupChatKabc", length=32)
    print(f"[A] Kabc = {Kabc.hex()}")

    # 4) start receive thread
    threading.Thread(target=recv_loop, args=(sock, Kabc), daemon=True).start()

    # 5) interactive send
    while True:
        text = input("> ")
        if not text:
            continue
        nonce, ct = cu.aesgcm_encrypt(Kabc, text.encode())
        pkt = {'from':'A','nonce':nonce.hex(),'ct':ct.hex()}
        sock.send(json.dumps(pkt).encode())

if __name__ == '__main__':
    main()
