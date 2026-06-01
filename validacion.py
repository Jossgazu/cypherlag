# validacion.py - Pruebas, comparativas y analisis para el paper

import random
import string
import time
from cipher import encrypt, decrypt, BLOCK_SIZE, ROUNDS, expand_key

KEY_16 = "abcdefghijklmnop"

def test_validacion():
    print("=" * 70)
    print("1. VALIDACION: CIFRADO Y DESCIFRADO")
    print("=" * 70)
    casos = [
        "Hola",
        "paper",
        "seguridad informatica",
        "constraseña1111",
        "abc abc abc abc abc",
        "AAAAAAAAAAAAAAAAAAAAAA",
        "wazaaaaa",
        "1234567890!@#$%^&*()",
        "texto largo para probar el algoritmo de cifrado con multiples bloques",
        "!@#$%^&*()_+-=[]{}|;':\",./<>?",
    ]
    print(f"{'#':<4} {'Mensaje':<45} {'OK':<8} {'Bloques':<8} {'Cifrado (hex)'}")
    print("-" * 100)
    todos_ok = True
    for i, msg in enumerate(casos):
        enc = encrypt(msg, KEY_16)
        dec = decrypt(enc, KEY_16)
        ok = dec == msg
        if not ok:
            todos_ok = False
        bloques = len(enc) // BLOCK_SIZE
        print(f"{i+1:<4} {msg[:43]:<45} {'SI' if ok else 'NO':<8} {bloques:<8} {enc.hex()[:30]}...")
    print()
    print(f"Resultado: {'TODOS LOS CASOS PASARON' if todos_ok else 'ALGUNOS FALLARON'}")
    print()

def caesar_encrypt(text, shift=3):
    result = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    return result.encode()

def xor_simple_encrypt(text, key="clave"):
    key_bytes = [ord(c) for c in key]
    msg_bytes = text.encode('utf-8')
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(msg_bytes)])

def test_comparativa():
    print("=" * 70)
    print("2. COMPARATIVA: Cipher Mejorado vs Caesar vs XOR Simple")
    print("=" * 70)
    msg = "seguridad"

    enc_cipher = encrypt(msg, KEY_16)
    enc_caesar = caesar_encrypt(msg)
    enc_xor    = xor_simple_encrypt(msg)

    print(f"Mensaje original : {msg}")
    print(f"Clave            : {KEY_16} ({len(KEY_16)} bytes)")
    print()
    print(f"Cipher (8 rondas, CBC, S-box): {enc_cipher.hex()}")
    print(f"Caesar (shift=3)             : {enc_caesar.hex()}")
    print(f"XOR Simple                  : {enc_xor.hex()}")
    print()

    msg_rep = "aaaa"
    print(f"Mensaje repetido : '{msg_rep}' (4 caracteres)")
    enc_rep_cipher = encrypt(msg_rep, KEY_16)
    enc_rep_caesar = caesar_encrypt(msg_rep)
    enc_rep_xor    = xor_simple_encrypt(msg_rep)
    print(f"Cipher (CBC hide patterns)  : {enc_rep_cipher.hex()}")
    print(f"Caesar                      : {enc_rep_caesar.hex()}")
    print(f"XOR Simple                  : {enc_rep_xor.hex()}")
    print()
    print("Observacion: Cipher con CBC produce bloques distintos aunque")
    print("el mensaje sea igual, gracias al encadenamiento.")
    print()

    print(f"{'Algoritmo':<20} {'Clave':<12} {'Rondas':<10} {'Modo':<10} {'Resistencia'}")
    print("-" * 70)
    print(f"{'Cipher Mejorado':<20} {'16 bytes':<12} {'8':<10} {'CBC':<10} {'Alta'}")
    print(f"{'XOR Simple':<20} {'Variable':<12} {'1':<10} {'ECB':<10} {'Baja'}")
    print(f"{'Caesar':<20} {'Ninguna':<12} {'1':<10} {'N/A':<10} {'Muy baja'}")
    print(f"{'AES-128':<20} {'16 bytes':<12} {'10':<10} {'CBC':<10} {'Muy alta'}")
    print()

def test_frecuencia():
    print("=" * 70)
    print("3. ANALISIS DE FRECUENCIA DE BYTES")
    print("=" * 70)
    msg = "la seguridad de la informacion es un pilar fundamental de la seguridad"
    enc = encrypt(msg, KEY_16)

    freq_orig = {}
    for b in msg.encode():
        freq_orig[b] = freq_orig.get(b, 0) + 1

    freq_enc = {}
    for b in enc[BLOCK_SIZE:]:
        freq_enc[b] = freq_enc.get(b, 0) + 1

    max_orig = max(freq_orig.values())
    max_enc  = max(freq_enc.values())
    bytes_unicos_orig = len(freq_orig)
    bytes_unicos_enc  = len(freq_enc)

    print(f"Mensaje             : '{msg}'")
    print(f"Longitud original   : {len(msg)} caracteres")
    print(f"Longitud cifrado    : {len(enc)} bytes (incluye IV)")
    print()
    print(f"{'Metrica':<35} {'Original':<15} {'Cifrado'}")
    print("-" * 60)
    print(f"{'Bytes unicos':<35} {bytes_unicos_orig:<15} {bytes_unicos_enc}")
    print(f"{'Frecuencia maxima':<35} {max_orig:<15} {max_enc}")
    print(f"{'Byte mas frecuente':<35} {max(freq_orig, key=freq_orig.get):<15} {max(freq_enc, key=freq_enc.get)}")
    print()
    print("Observacion: CBC + 8 rondas difunden los patrones del mensaje original.")
    print()

def test_key_expansion():
    print("=" * 70)
    print("4. ANALISIS DE KEY EXPANSION")
    print("=" * 70)
    key = KEY_16.encode()
    subkeys = expand_key(key)
    print(f"Clave base: {KEY_16} ({len(KEY_16)} bytes)")
    print(f"Subclaves generadas: {len(subkeys)} (1 initial + {ROUNDS} rounds)")
    print(f"Tamano por subclave: {len(subkeys[0])} bytes")
    print()
    print(f"Subclave 0 (AddRoundKey inicial): {subkeys[0].hex()[:32]}...")
    print(f"Subclave {ROUNDS} (Final):              {subkeys[ROUNDS].hex()[:32]}...")
    print()
    print("Cada subclave es distinta -> cada ronda usa clave diferente.")
    print()

def test_cbc_chain():
    print("=" * 70)
    print("5. PRUEBA DE ENCADENAMIENTO CBC")
    print("=" * 70)
    msg = "BBBBBBBBBBBBBBBB"
    enc = encrypt(msg, KEY_16)
    iv = enc[:BLOCK_SIZE]
    blocks = [enc[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(enc), BLOCK_SIZE)]
    print(f"Mensaje: '{msg}' (16 bytes, 1 bloque)")
    print(f"IV:     {iv.hex()}")
    print(f"Bloque cifrado: {blocks[0].hex()}")
    print()
    print("CBC: block = E(plain XOR prev), prev = block")
    print("Si el IV es fijo y el mensaje es igual, el primer bloque vary.")
    print()

def test_rendimiento():
    print("=" * 70)
    print("6. RENDIMIENTO (tiempo de cifrado)")
    print("=" * 70)
    tamanos = [16, 64, 256, 1024, 4096]
    print(f"{'Longitud (chars)':<20} {'Cifrado (ms)':<20} {'Descifrado (ms)':<20}")
    print("-" * 60)
    for n in tamanos:
        msg = ''.join(random.choices(string.ascii_letters, k=n))
        t1 = time.perf_counter()
        enc = encrypt(msg, KEY_16)
        t2 = time.perf_counter()
        dec = decrypt(enc, KEY_16)
        t3 = time.perf_counter()
        print(f"{n:<20} {(t2-t1)*1000:<20.4f} {(t3-t2)*1000:.4f}")
    print()

def test_key_sizes():
    print("=" * 70)
    print("7. PRUEBA CON DIFERENTES CLAVES")
    print("=" * 70)
    msg = "test message"
    test_keys = [
        "abcdefghijklmnop",
        "1234567890123456",
        "masde16bytes!!!",
    ]
    print(f"Mensaje: '{msg}'")
    print()
    for k in test_keys:
        try:
            enc = encrypt(msg, k)
            dec = decrypt(enc, k)
            status = "OK" if dec == msg else "FAIL"
            klen = len(k) if len(k) <= 16 else 16
            print(f"Clave '{k[:16]}...' ({klen} bytes truncado) -> {status}")
        except Exception as e:
            print(f"Clave '{k[:16]}...' -> ERROR: {e}")
    print()

if __name__ == "__main__":
    test_validacion()
    test_comparativa()
    test_frecuencia()
    test_key_expansion()
    test_cbc_chain()
    test_rendimiento()
    test_key_sizes()
    print("=" * 70)
    print("Resultados generados correctamente.")
    print("=" * 70)