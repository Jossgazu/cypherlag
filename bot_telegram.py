# bot_telegram.py - Bot para Telegram
import telebot
from cipher import encrypt, decrypt

TOKEN = "8991021964:AAHhae6-E-BTsheNGWdklX2xRUsTRY-ASuk"
KEY   = "wazaa"

bot = telebot.TeleBot(TOKEN)

# /start
@bot.message_handler(commands=['start'])
def cmd_start(message):
    bot.reply_to(message,
        "Bienvenido a CipherBot\n\n"
        "Comandos disponibles:\n"
        "/cifrar <mensaje>   → cifra tu mensaje\n"
        "/descifrar <hex>    → descifra un hex\n"
        "/info               → como funciona el algoritmo"
    )

# /cifrar
@bot.message_handler(commands=['cifrar'])
def cmd_cifrar(message):
    partes = message.text.split(' ', 1)
    if len(partes) < 2:
        bot.reply_to(message, "Uso: /cifrar <mensaje>\nEjemplo: /cifrar Hola UCSM")
        return
    msg = partes[1]
    enc = encrypt(msg, KEY)
    bot.reply_to(message,
        f"Mensaje original : {msg}\n"
        f"Cifrado (hex)    : {enc.hex()}\n"
        f"Longitud         : {len(msg)} chars → {len(enc)} bytes cifrados"
    )

# /descifrar
@bot.message_handler(commands=['descifrar'])
def cmd_descifrar(message):
    partes = message.text.split(' ', 1)
    if len(partes) < 2:
        bot.reply_to(message, "Uso: /descifrar <hex>\nEjemplo: /descifrar 1a2b3c...")
        return
    try:
        raw = bytes.fromhex(partes[1].strip())
        dec = decrypt(raw, KEY)
        bot.reply_to(message,
            f"Hex recibido  : {partes[1].strip()}\n"
            f"Descifrado    : {dec}"
        )
    except Exception as e:
        bot.reply_to(message, f"Error al descifrar: {e}\nAsegurate de enviar un hex valido.")

# /info
@bot.message_handler(commands=['info'])
def cmd_info(message):
    bot.reply_to(message,
        "Cipher - Algoritmo de cifrado propio\n\n"
        "Pasos del algoritmo:\n"
        "1. Clave dinamica: se expande segun la longitud del mensaje\n"
        "2. XOR: cada byte del mensaje se combina con la clave\n"
        "3. Permutacion: los bloques de 4 bytes se invierten\n\n"
        "Clave base: ucsm2024\n"
        "Desarrollado por: Fabricio Miota - UCSM 2024"
    )

# mensajes de texto libre → cifra automaticamente
@bot.message_handler(func=lambda m: True)
def msg_libre(message):
    msg = message.text
    enc = encrypt(msg, KEY)
    bot.reply_to(message,
        f"Texto cifrado automaticamente:\n"
        f"Original : {msg}\n"
        f"Cifrado  : {enc.hex()}"
    )

print("Cipher Bot corriendo...")
bot.infinity_polling()