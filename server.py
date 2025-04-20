# server.py

import socket
import threading
import json
import time
from cryptography.hazmat.primitives import serialization

from auth_manager import AuthManager
import crypto_utils as cu

HOST = '127.0.0.1'
PORT = 8000

# load server’s own key + all certs
KEY_PATH   = 'Keys/S_priv.pem'
CERTS_DIR  = 'Certs'
auth       = AuthManager(KEY_PATH, CERTS_DIR)

# currently connected clients: entity_id -> socket
clients        = {}
clients_lock   = threading.Lock()

# after authentication steps 1/3/5 we forward each 'fwd' blob —
# if the target isn't yet online, stash it here
pending = { 'A': [], 'B': [], 'C': [] }
pending_lock = threading.Lock()

def deliver_pending(entity):
    """Send any buffered handshake messages to entity once it connects."""
    with pending_lock:
        for pkt in pending[entity]:
            with clients_lock:
                clients[entity].send((json.dumps(pkt) + "\n").encode())
                
        pending[entity].clear()

def handle_client(conn):
    entity = None
    try:
        # --- Registration ---
        init = conn.recv(4096)
        info = json.loads(init.decode())
        entity = info['id']   # 'A', 'B' or 'C'
        with clients_lock:
            clients[entity] = conn

        # immediately deliver any handshake blobs waiting for this party
        deliver_pending(entity)

        # --- Main loop ---
        while True:
            raw = conn.recv(65536)
            if not raw:
                break
            msg = json.loads(raw.decode())
            step    = msg.get('step')
            session = msg.get('session')
            sender  = msg.get('from')

            # Handshake Steps 1,3,5
            if step in (1, 3, 5):
                # 1) freshness
                if not auth.is_fresh(msg['timestamp']):
                    conn.send(b'{"error":"stale_timestamp"}'); return

                # 2) replay‑protection
                hbytes = bytes.fromhex(msg['hash'])
                if not auth.check_and_record(session, hbytes):
                    conn.send(b'{"error":"replay"}'); return

                # 3) verify signature
                cert_sender = auth.get_cert(sender)
                if not auth.verify(bytes.fromhex(msg['sig']), hbytes, cert_sender):
                    conn.send(b'{"error":"bad_signature"}'); return

                # 4) now forward to the other two
                recipients = { 'A':['B','C'], 'B':['A','C'], 'C':['A','B'] }[sender]
                for rec in recipients:
                    fwd = {
                        'session':      session,
                        'timestamp':    time.time(),
                        'from':         'S',
                        'to':           rec,
                        'step':         step + 1,
                        'enc_nonce':    msg[f'enc_to_{rec}'],
                        'hash':         msg['hash'],
                        'sig_sender':   msg['sig'],
                        'cert_sender':  cert_sender.public_bytes(
                                           encoding=serialization.Encoding.PEM
                                       ).decode(),
                    }
                    # S signs H(session||rec||cipher||sig_sender)
                    payload = (
                        session.encode() +
                        rec.encode() +
                        bytes.fromhex(fwd['enc_nonce']) +
                        bytes.fromhex(msg['sig'])
                    )
                    fwd['sig_S'] = auth.sign(cu.hash_sha256(payload)).hex()
                    fwd['cert_S'] = auth.get_cert('S').public_bytes(
                                         encoding=serialization.Encoding.PEM
                                     ).decode()

                    # if rec is already connected, send immediately...
                    with clients_lock:
                        sock = clients.get(rec)
                    if sock:
                        sock.send((json.dumps(fwd) + "\n").encode())
                    else:
                        # otherwise buffer it until rec registers
                        with pending_lock:
                            pending[rec].append(fwd)

            else:
                # all other messages (Steps 7+, chat) are just blind relays
                with clients_lock:
                    for eid, sock in clients.items():
                        if eid != sender:
                            sock.send(raw.rstrip(b"\n") + b"\n")

    finally:
        conn.close()
        if entity:
            with clients_lock:
                del clients[entity]

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    main()
