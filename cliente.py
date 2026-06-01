# cliente.py
import socket
from cipher import encrypt, decrypt

HOST = '127.0.0.1'
PORT = 9999
KEY  = "wazaa"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[CLIENTE] Conectado al servidor\n")
    while True:
        msg = input("Mensaje (o 'salir'): ")
        if msg.lower() == 'salir':
            break
        cifrado = encrypt(msg, KEY)
        print(f"[CLIENTE] Enviando cifrado : {cifrado.hex()}")
        s.sendall(cifrado)
        resp = s.recv(1024)
        print(f"[CLIENTE] Servidor dice    : {decrypt(resp, KEY)}\n")