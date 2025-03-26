#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

Este módulo cifra un frame de TV usando un esquema seguro:
    - Se usa AES-CTR para cifrar (FRAME || TS)
    - Se calcula un HMAC (AES-CMAC) sobre {CHID | TS | CIPHERTEXT} usando K_mac.
El paquete final tiene la estructura:
    { CHID (4B) | TS (8B) | CIPHERTEXT (FRAME||TS) | HMAC (16B) }
"""

import argparse
import struct
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Counter

class Encoder:
    def __init__(self, secrets: bytes):
        # Se carga el JSON de los secretos y se guarda la clave de autenticación
        secrets = json.loads(secrets)
        self.secrets = secrets
        self.K_mac = bytes.fromhex(secrets["K_mac"])
    def encrypt_frame(self, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        # Se usa AES en modo CTR
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(plaintext)
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        # Obtiene la clave del canal
        key_hex = self.secrets["keys"].get(str(channel))
        if not key_hex:
            raise ValueError("Clave para canal no encontrada")
        channel_key = bytes.fromhex(key_hex)
        # Construye el nonce: 8 bytes de TS, 4 bytes de canal y 4 bytes 0 (total 16B)
        nonce = struct.pack("<Q", timestamp) + struct.pack("<I", channel) + b'\x00\x00\x00\x00'
        # El plaintext es: FRAME || TS (para proteger el timestamp)
        plaintext = frame + struct.pack("<Q", timestamp)
        ciphertext = self.encrypt_frame(channel_key, nonce, plaintext)
        # Calcula el HMAC sobre: {CHID (4B) | TS (8B) | CIPHERTEXT}
        header = struct.pack("<IQ", channel, timestamp)
        cobj = CMAC.new(self.K_mac, ciphermod=AES)
        cobj.update(header + ciphertext)
        hmac = cobj.digest()
        # El paquete final es: header || ciphertext || hmac
        return header + ciphertext + hmac

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()
    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))

if __name__ == "__main__":
    main()
