# server.py
import socket
from cipher import encrypt, decrypt

HOST = '127.0.0.1'
PORT = 9999
KEY  = "wazaa"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[SERVIDOR] Esperando en {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"[SERVIDOR] Cliente conectado\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[SERVIDOR] Cifrado recibido : {data.hex()}")
            plain = decrypt(data, KEY)
            print(f"[SERVIDOR] Descifrado       : {plain}\n")
            resp = f"ACK: '{plain}' recibido OK"
            conn.sendall(encrypt(resp, KEY))