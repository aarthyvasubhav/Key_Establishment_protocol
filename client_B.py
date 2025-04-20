# client_B.py

import socket, json, time, threading
from pathlib import Path
from cryptography import x509

import crypto_utils as cu
from auth_manager import AuthManager

HOST, PORT = '127.0.0.1', 8000
KEY_PATH, CERTS_DIR = 'Keys/B_priv.pem', 'Certs'
CERT_FILE = Path(CERTS_DIR) / 'B.pem'

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
    sock = socket.create_connection((HOST, PORT))
    sock.send(json.dumps({'id':'B'}).encode())

    auth = AuthManager(KEY_PATH, CERTS_DIR)
    pk_A = auth.get_cert('A').public_key()
    pk_C = auth.get_cert('C').public_key()
    certB_pem = CERT_FILE.read_text()

    # wait for step 2 (Na)
    raw = sock.recv(65536)
    fwd = json.loads(raw.decode())
    assert fwd['step']==2
    assert auth.is_fresh(fwd['timestamp'])
    sender_cert = x509.load_pem_x509_certificate(fwd['cert_sender'].encode())
    assert auth.verify(bytes.fromhex(fwd['sig_sender']),
                       bytes.fromhex(fwd['hash']), sender_cert)
    session = fwd['session']
    Na = cu.rsa_oaep_decrypt(bytes.fromhex(fwd['enc_nonce']), auth._sk)
    print("[B] Got Na")

    # step 3: send Nb
    Nb = cu.generate_nonce()
    T3 = time.time()
    enc_to_A = cu.rsa_oaep_encrypt(Nb, pk_A).hex()
    enc_to_C = cu.rsa_oaep_encrypt(Nb, pk_C).hex()
    hB = cu.hash_sha256(session.encode()+str(T3).encode()+Nb+b"A"+b"B"+b"C").hex()
    sigB = auth.sign(bytes.fromhex(hB)).hex()
    msg3 = {
        'session':session,'timestamp':T3,
        'from':'B','step':3,
        'enc_to_A':enc_to_A,'enc_to_C':enc_to_C,
        'hash':hB,'sig':sigB,'certB':certB_pem
    }
    sock.send(json.dumps(msg3).encode())
    print("[B] Sent step 3")

    # wait for step 6 (Nc)
    raw = sock.recv(65536)
    fwd = json.loads(raw.decode())
    assert fwd['step']==6
    assert auth.is_fresh(fwd['timestamp'])
    sender_cert = x509.load_pem_x509_certificate(fwd['cert_sender'].encode())
    assert auth.verify(bytes.fromhex(fwd['sig_sender']),
                       bytes.fromhex(fwd['hash']), sender_cert)
    Nc = cu.rsa_oaep_decrypt(bytes.fromhex(fwd['enc_nonce']), auth._sk)
    print("[B] Got Nc")

    # derive Kabc
    IKM = Na + Nb + Nc
    Kabc = cu.hkdf_extract_and_expand(b'\x00'*32, IKM, b"GroupChatKabc", length=32)
    print(f"[B] Kabc = {Kabc.hex()}")

    # start receive thread & interactive send
    threading.Thread(target=recv_loop, args=(sock, Kabc), daemon=True).start()
    while True:
        text = input("> ")
        if not text: continue
        nonce, ct = cu.aesgcm_encrypt(Kabc, text.encode())
        sock.send(json.dumps({'from':'B','nonce':nonce.hex(),'ct':ct.hex()}).encode())

if __name__=='__main__':
    main()
