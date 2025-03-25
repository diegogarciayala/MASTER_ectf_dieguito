#!/usr/bin/env python3
"""
encoder.py
----------
Esta versión segura combina la lógica de:
  - Truncar/rellenar un “frame” a 8 bytes.
  - Concatenar un trailer de 16 bytes con los campos: <timestamp (8 bytes), seq (4 bytes), channel (4 bytes)>.
  - Cifrar el bloque de 24 bytes (8+16) usando AES‑CTR con una clave dinámica derivada mediante AES‑CMAC.
  - Generar una suscripción de 52 bytes (36 bytes de datos + 16 bytes de CMAC) usando la clave específica del canal.
  - Empaquetar todo junto con un header de 20 bytes (<I I I Q>) para obtener un paquete final de 96 bytes.

La interfaz (tamaños y orden) es idéntica al diseño original.
"""

import argparse
import struct
import json
import base64
import os

from Crypto.Cipher import AES

# --- Funciones de AES-CMAC manual (RFC4493) ---
def leftshift_onebit(block16: bytes) -> bytearray:
    out = bytearray(16)
    overflow = 0
    for i in reversed(range(16)):
        out[i] = ((block16[i] << 1) & 0xFE) | overflow
        overflow = 1 if (block16[i] & 0x80) else 0
    return out

def aes_ecb_encrypt_block(key: bytes, block16: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block16)

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    zero16 = b'\x00' * 16
    L = aes_ecb_encrypt_block(key, zero16)
    K1 = leftshift_onebit(L)
    if L[0] & 0x80:
        K1[15] ^= 0x87
    K2 = leftshift_onebit(K1)
    if K1[0] & 0x80:
        K2[15] ^= 0x87

    n = (len(msg) + 15) // 16
    complete = (len(msg) % 16 == 0 and len(msg) != 0)
    if n == 0:
        n = 1
        complete = False

    if complete:
        last_block = msg[(n-1)*16 : n*16]
        last = bytes(x ^ y for x,y in zip(last_block, K1))
    else:
        rem = len(msg) % 16
        temp = bytearray(16)
        temp[:rem] = msg[(n-1)*16 : (n-1)*16+rem]
        temp[rem] = 0x80
        last = bytes(x ^ y for x,y in zip(temp, K2))
    cipher = AES.new(key, AES.MODE_ECB)
    X = bytes(16)
    for i in range(n-1):
        block = bytes(a ^ b for a,b in zip(X, msg[i*16:(i+1)*16]))
        X = cipher.encrypt(block)
    block = bytes(a ^ b for a,b in zip(X, last))
    X = cipher.encrypt(block)
    return X
# ----------------------------------------------------------------

def store64_be(val: int) -> bytes:
    return bytes([
        (val >> 56) & 0xFF,
        (val >> 48) & 0xFF,
        (val >> 40) & 0xFF,
        (val >> 32) & 0xFF,
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >>  8) & 0xFF,
        (val >>  0) & 0xFF,
    ])

class Encoder:
    MAX_FRAME_SIZE = 8  # El frame se ajusta a 8 bytes.
    def __init__(self, secrets_json: bytes):
        # Carga el JSON con las claves
        data = json.loads(secrets_json)
        if "channel_keys" not in data:
            raise ValueError("No se encontró 'channel_keys' en el JSON.")
        self.channel_keys = data["channel_keys"]
        self.KMAC = base64.b64decode(data["KMAC"]) if "KMAC" in data else None
        self.seq = 0
        self.encoder_id = 1  # Fijo, como en el diseño original

    def _get_channel_key(self, channel: int) -> bytes:
        key_b64 = self.channel_keys.get(str(channel))
        if not key_b64:
            raise ValueError(f"No se encontró clave para el canal {channel}.")
        return base64.b64decode(key_b64)

    def _derive_dynamic_key(self, K_channel: bytes, seq: int, channel: int) -> bytes:
        # Derivación:
        #   K1 = CMAC(K_channel, b"K1-Derivation")
        #   dynamic_key = CMAC(K1, struct.pack("<I I", seq, channel))
        K1 = aes_cmac(K_channel, b"K1-Derivation")
        data_le = struct.pack("<I I", seq, channel)
        dynamic_key = aes_cmac(K1, data_le)
        return dynamic_key

    def _encrypt_24bytes(self, dynamic_key: bytes, frame_8: bytes,
                         timestamp: int, seq: int, channel: int) -> bytes:
        # Construye el nonce: 8 ceros + seq (8 bytes big-endian)
        big_end_seq = store64_be(seq)
        nonce = b"\x00"*8 + big_end_seq
        # Construye el trailer de 16 bytes: <Q I I> (timestamp, seq, channel)
        trailer = struct.pack("<Q I I", timestamp, seq, channel)
        plaintext_24 = frame_8 + trailer  # 8 + 16 = 24 bytes
        cipher = AES.new(dynamic_key, AES.MODE_CTR, initial_value=nonce, nonce=b"")
        return cipher.encrypt(plaintext_24)

    def encode(self, channel: int, input_msg: bytes, timestamp: int) -> bytes:
        # Incrementa el contador de secuencia
        self.seq += 1
        seq = self.seq

        # Ajusta el frame a 8 bytes (trunca o rellena con ceros)
        if len(input_msg) > self.MAX_FRAME_SIZE:
            input_msg = input_msg[:self.MAX_FRAME_SIZE]
        frame_8 = input_msg.ljust(self.MAX_FRAME_SIZE, b'\x00')

        # Obtiene la clave del canal
        K_channel = self._get_channel_key(channel)
        # Deriva la clave dinámica
        dynamic_key = self._derive_dynamic_key(K_channel, seq, channel)
        # Cifra los 24 bytes (frame + trailer)
        ciph_24 = self._encrypt_24bytes(dynamic_key, frame_8, timestamp, seq, channel)
        # Construye el header de 20 bytes: <I I I Q> (seq, channel, encoder_id, timestamp)
        header = struct.pack("<I I I Q", seq, channel, self.encoder_id, timestamp)
        # Construye la suscripción de 52 bytes:
        # Formato: <I I I I 20s> (canal, encoder_id, start_time, end_time, 20 bytes de ceros)
        # Se usan valores fijos de ejemplo (los mismos que espera el decoder)
        start_time = 123456789
        end_time = 387654321
        subs_data = struct.pack("<I I I I 20s", channel, self.encoder_id, start_time, end_time, b'\x00'*20)
        mac_16 = aes_cmac(K_channel, subs_data)
        subscription = subs_data + mac_16  # 36 + 16 = 52 bytes
        # Empaqueta todo: header (20) + subscription (52) + ciphertext (24) = 96 bytes
        packet = header + subscription + ciph_24
        print("Sent pkt (96 bytes):")
        print(packet.hex())
        print("----------------------------------------------------------")
        return packet

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Archivo JSON con 'channel_keys' y opcional 'KMAC'")
    parser.add_argument("channel", type=int, help="Canal ID")
    parser.add_argument("frame", help="Mensaje a enviar (se ajustará a 8 bytes)")
    parser.add_argument("timestamp", type=int, help="Timestamp de 64 bits (usado en trailer)")
    args = parser.parse_args()

    enc = Encoder(args.secrets_file.read())
    packet = enc.encode(args.channel, args.frame.encode(), args.timestamp)
    print(packet.hex())

if __name__ == "__main__":
    main()
