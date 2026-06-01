# CipherLag - Documentacion Tecnica

## Indice

1. [Vista General](#vista-general)
2. [Parametros del Algoritmo](#parametros-del-algoritmo)
3. [Key Expansion](#key-expansion)
4. [S-Box](#s-box)
5. [Aritmetica GF(256)](#aritmetica-gf256)
6. [Round Function](#round-function)
   - [SubBytes](#subbytes)
   - [ShiftRows](#shiftrows)
   - [MixColumns](#mixcolumns)
   - [AddRoundKey](#addroundkey)
7. [Modo CBC](#modo-cbc)
8. [Padding PKCS7](#padding-pkcs7)
9. [Flujo Completo](#flujo-completo)
10. [Seguridad](#seguridad)

---

## Vista General

CipherLag es un cifrador simetrico por bloques inspirado en AES que utiliza:

- **Bloques de 16 bytes** (128 bits)
- **8 rondas** de cifrado
- **Clave de 16 bytes** expandida a 9 subclaves
- **Modo CBC** (Cipher Block Chaining) con IV
- **S-Box original** de 256 bytes

```
┌─────────────────────────────────────────────────────────────┐
│                      CIFRADO SIMETRICO                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Mensaje ──► PKCS7 Padding ──► CBC Mode ──► 8 Rondas ──► │
│                                                             │
│   Clave (16 bytes) ──► Key Expansion ──► 9 Subclaves ──►   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Parametros del Algoritmo

| Parametro | Valor |
|-----------|-------|
| Tamanio de bloque | 16 bytes (128 bits) |
| Numero de rondas | 8 |
| Tamanio de clave | 16 bytes (128 bits) |
| Subclaves generadas | 9 (1 inicial + 8 rondas) |
| Tamanio de subclave | 16 bytes |
| Modo de operacion | CBC |
| Tamanio de IV | 16 bytes |

---

## Key Expansion

La clave de 16 bytes se expande a 9 subclaves de 16 bytes cada una.

### Algoritmo

```
1. Dividir clave en 4 palabras de 32 bits (W0, W1, W2, W3)

2. Para cada ronda r = 0..7:
   a) RotWord: rotar W3 8 bits a la izquierda
   b) SubWord: aplicar S-Box a cada byte
   c) XOR con RCON[r] en el primer byte
   d) Xor con W0 y con (r+1)
   e) Generar W4, W5, W6, W7 = W0^W4, W1^W5, W2^W6, W3^W7

3. Concatenar palabras en subclaves de 16 bytes
```

### constantes

```python
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
```

### Ejemplo

```
Clave: "abcdefghijklmnop"
Bytes: [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70]

Subclave 0: 6162636465666768696a6b6c6d6e6f70...
Subclave 8: 5aaf61b23fc906da56a36db63bcd02c6...
```

---

## S-Box

Tabla de sustitucion de 256 bytes que proporciona no linealidad.

```
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...
    ...
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, ...
]
```

### Propiedades

- **No lineal**: Resiste criptanalisis diferencial y lineal
- ** biyectiva**: Cada entrada tiene exactamente una salida
- **difusion**: Cambios en entrada propagan a salida

### SubBytes

```python
def sub_bytes(state):
    return bytes(SBOX[b] for b in state)
```

Cada byte del estado se reemplaza por el byte correspondiente en la S-Box.

---

## Aritmetica GF(256)

Galois Field de 256 elementos usado en MixColumns.

### Multiplicacion en GF(256)

```python
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        p ^= a if b & 1 else 0
        hi = a & 0x80
        a = ((a << 1) ^ 0x1b) & 0xFF if hi else (a << 1)
        b >>= 1
    return p
```

### Propiedades

- `a * 1 = a` (elemento identidad)
- `a * 2 = xshift-left con reduccion si bit mas significativo = 1`
- `a * 3 = (a * 2) XOR a`

### Tabla de multiplicacion

| a \ b | 1 | 2 | 3 | 9 | 0x0b | 0x0d | 0x0e |
|-------|---|---|---|---|------|------|------|
| 0x63 | 63 | c6 | a5 | 8a | 8a | da | 89 |

---

## Round Function

Cada ronda aplica 4 operaciones en secuencia:

```
State ──► SubBytes ──► ShiftRows ──► MixColumns ──► AddRoundKey ──► State
```

### SubBytes

Sustitucion no lineal byte por byte.

```
Antes:  [e2, 12, cb, ff, 0d, f6, d5, 22, 92, 1b, 20, 36, 18, f2, fa, bf]
Despues:[8a, 97, 8d, 5d, 52, 4a, ...]
```

### ShiftRows

Desplazamiento ciclico de filas en la matriz de estado.

```
Matriz de estado (4x4):

  Col 0   Col 1   Col 2   Col 3
┌───────┬───────┬───────┬───────┐
│  0    │  1    │  2    │  3    │  Row 0: sin cambio
├───────┼───────┼───────┼───────┤
│  4    │  5    │  6    │  7    │  Row 1: shift left 1
├───────┼───────┼───────┼───────┤
│  8    │  9    │  10   │  11   │  Row 2: shift left 2
├───────┼───────┼───────┼───────┤
│  12   │  13   │  14   │  15   │  Row 3: shift left 3
└───────┴───────┴───────┴───────┘
```

```python
def shift_rows(state):
    return bytes([
        state[0],  state[1],  state[2],  state[3],   # Row 0: sin cambio
        state[5],  state[6],  state[7],  state[4],   # Row 1: 1 izquierda
        state[10], state[11], state[8],  state[9],   # Row 2: 2 izquierda
        state[15], state[12], state[13], state[14],  # Row 3: 3 izquierda
    ])
```

### MixColumns

Mezcla columnas usando aritmetica GF(256).

```
Columna = [c0, c1, c2, c3]

Resultado[0] = 2*c0 XOR 3*c1 XOR 1*c2 XOR 1*c3
Resultado[1] = 1*c0 XOR 2*c1 XOR 3*c2 XOR 1*c3
Resultado[2] = 1*c0 XOR 1*c1 XOR 2*c2 XOR 3*c3
Resultado[3] = 3*c0 XOR 1*c1 XOR 1*c2 XOR 2*c3
```

Matriz de transformacion:

```
┌─────┐   ┌─────────────────────────────┐   ┌─────┐
│ c0' │   │ 2  3  1  1 │ c0 │            │ c0' │
│ c1' │ = │ 1  2  3  1 │ c1 │            │ c1' │
│ c2' │   │ 1  1  2  3 │ c2 │            │ c2' │
│ c3' │   │ 3  1  1  2 │ c3 │            │ c3' │
└─────┘   └─────────────────────────────┘   └─────┘
```

### AddRoundKey

XOR del estado con la subclave de la ronda actual.

```python
def add_round_key(state, subkey):
    return bytes(a ^ b for a, b in zip(state, subkey))
```

---

## Modo CBC

Cipher Block Chaining encadena bloques para evitar patrones.

```
                    ┌─────────────────┐
 IV ────────┬──────►│                 │
            │       │     E (clave)   │──────┐
            │       │                 │      │
            ▼       └─────────────────┘      │
            │                                  │
            ▼                                  ▼
    ┌───────────────┐                 ┌───────────────┐
    │  Block 0      │                 │  Block 1      │
    │  Plaintext   │                 │  Plaintext   │
    └───────────────┘                 └───────────────┘
            │                                  │
            ▼                                  ▼
    ┌───────────────┐                 ┌───────────────┐
    │    XOR        │                 │    XOR        │
    └───────────────┘                 └───────────────┘
            │                                  │
            │       ┌─────────────────┐        │
            └──────►│                 │◄───────┘
                    │     E (clave)   │
                    │                 │──────┐
                    └─────────────────┘      │
                                             ▼
                                    ┌───────────────┐
                                    │  Ciphertext   │
                                    └───────────────┘
```

### Cifrado

```python
prev_block = iv
for cada bloque:
    block_xored = plaintext XOR prev_block
    ciphertext = encrypt_block(block_xored)
    prev_block = ciphertext
```

### Descifrado

```python
prev_block = iv
for cada bloque:
    decrypted = decrypt_block(ciphertext)
    plaintext = decrypted XOR prev_block
    prev_block = ciphertext
```

---

## Padding PKCS7

PKCS7 agrega bytes para completar bloques de 16 bytes.

```python
if len(data) % 16 == 0:
    padding_len = 16
else:
    padding_len = 16 - (len(data) % 16)

padded = data + bytes([padding_len] * padding_len)
```

### Ejemplos

| Mensaje | Bytes | Padding | Resultado |
|---------|-------|---------|----------|
| "Hi" | 2 | 14 | 4869 + 14*0x0E |
| "AAAAAAAAAAAAAA" | 14 | 2 | 41*14 + 0202 |
| "ABCD..." (16 bytes) | 16 | 16 | ... + 16*0x10 |

---

## Flujo Completo

### Cifrado

```
1. VALIDACION
   └─► Clave debe ser 16 bytes (se trunca o pad con \x00)

2. KEY EXPANSION
   └─► Generar 9 subclaves de 16 bytes

3. GENERAR IV
   └─► 16 bytes aleatorios

4. PARA CADA BLOQUE:
   a) CBC XOR: block = plaintext XOR prev_block
   b) AddRoundKey: state = block XOR subkeys[0]
   c) Para r = 1..7:
      - SubBytes
      - ShiftRows
      - MixColumns
      - AddRoundKey: state = state XOR subkeys[r]
   d) Ronda final (sin MixColumns):
      - SubBytes
      - ShiftRows
      - AddRoundKey: state = state XOR subkeys[8]

5. OUTPUT: IV || ciphertext
```

### Descifrado

```
1. EXTRAER IV (primer bloque)

2. PARA CADA BLOQUE:
   a) Descifrar bloque con _crypt_block(ciphertext, subkeys, encrypt=False)
   b) XOR con prev_block
   c) prev_block = ciphertext

3. REMOVER PADDING

4. OUTPUT: plaintext
```

### _crypt_block

```python
def _crypt_block(block, subkeys, encrypt):
    state = block

    if encrypt:
        state = add_round_key(state, subkeys[0])
        for r in range(1, ROUNDS):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, subkeys[r])
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, subkeys[ROUNDS])
    else:
        state = add_round_key(state, subkeys[ROUNDS])
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        for r in range(ROUNDS - 1, 0, -1):
            state = add_round_key(state, subkeys[r])
            state = inv_mix_columns(state)
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
        state = add_round_key(state, subkeys[0])

    return state
```

---

## Seguridad

### Fortalezas

1. **8 rondas**: Suficientes para difusion y confusion
2. **S-Box no lineal**: Resistente a criptanalisis diferencial
3. **GF(256) MixColumns**: Distribuye bits por todo el bloque
4. **Key expansion**: Cada ronda usa subclave diferente
5. **CBC mode**: Oculta patrones en mensajes repetidos

### Limitaciones (comparado con AES)

1. **S-Box fijo**: AES usa S-Box matematicamente verificable
2. **Sin tables precomputadas**: Vulnerable a ataques de timing
3. **Implementacion en Python**: Mas lento que C/ASM
4. **IV fijo**: Debe ser aleatorio en uso real

### Recomendaciones de Uso

- Usar clave de 16 bytes verdadera (no strings predecibles)
- IV debe ser aleatorio y unico por mensaje
- No reutilizar IV con la misma clave
- Para produccion, usar AES standary en su lugar

---

## Implementacion

### Archivos

- `cipher.py`: Implementacion principal
- `validacion.py`: Tests y analisis comparativo
- `bot_telegram.py`: Bot de Telegram integrado

### Uso Basico

```python
from cipher import encrypt, decrypt

KEY = "abcdefghijklmnop"
msg = "Hola UCSM"

# Cifrar
ciphertext = encrypt(msg, KEY)
print(ciphertext.hex())

# Descifrar
plaintext = decrypt(ciphertext, KEY)
print(plaintext)  # "Hola UCSM"
```

---

## Autor

Desarrollado por: **Fabricio Miota - UCSM 2024**

Repositorio: https://github.com/Jossgazu/cypherlag
