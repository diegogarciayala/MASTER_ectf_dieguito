#!/usr/bin/env python3
"""
encoder.py
----------
Versión segura del encoder para el diseño eCTF.
Se ajusta para trabajar con frames de 64 bytes y un trailer de 16 bytes,
usando AES-CTR con una clave dinámica derivada mediante AES-CMAC.
El paquete final se compone de:
  - Header: 20 bytes (<I I I Q>)  --> seq, channel, encoder_id, timestamp
  - Suscripción: 52 bytes (generada por gen_subscription)
  - Ciphertext: 80 bytes (frame de 64 bytes + trailer de 16 bytes)
Total: 152 bytes
"""

import argparse
import struct
import json
import base64
from Crypto.Cipher import AES

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
        temp[:rem] = msg[(n-1)*16 : (n-1)*16 + rem]
        temp[rem] = 0x80
        last = bytes(x ^ y for x,y in zip(temp, K2))
    cipher = AES.new(key, AES.MODE_ECB)
    X = bytes(16)
    for i in range(n-1):
        block = bytes(a ^ b for a, b in zip(X, msg[i*16 : i*16+16]))
        X = cipher.encrypt(block)
    block = bytes(a ^ b for a, b in zip(X, last))
    X = cipher.encrypt(block)
    return X

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
    MAX_FRAME_SIZE = 64
    def __init__(self, secrets_json: bytes):
        data = json.loads(secrets_json)
        if "channel_keys" not in data:
            raise ValueError("No se encontró 'channel_keys' en el JSON.")
        self.channel_keys = data["channel_keys"]
        self.KMAC = base64.b64decode(data["KMAC"]) if "KMAC" in data else None
        self.seq = 0
        self.encoder_id = 1

    def _get_channel_key(self, channel: int) -> bytes:
        key_b64 = self.channel_keys.get(str(channel))
        if not key_b64:
            raise ValueError(f"No se encontró clave para el canal {channel}.")
        return base64.b64decode(key_b64)

    def _derive_dynamic_key(self, K_channel: bytes, seq: int, channel: int) -> bytes:
        K1 = aes_cmac(K_channel, b"K1-Derivation")
        data_le = struct.pack("<I I", seq, channel)
        dynamic_key = aes_cmac(K1, data_le)
        return dynamic_key

    def _encrypt_80bytes(self, dynamic_key: bytes, frame_64: bytes,
                         timestamp: int, seq: int, channel: int) -> bytes:
        # Nonce: 8 ceros + seq en big-endian (8 bytes)
        nonce = b"\x00" * 8 + store64_be(seq)
        # Trailer: 16 bytes, formato: <Q I I> (timestamp, seq, channel)
        trailer = struct.pack("<Q I I", timestamp, seq, channel)
        plaintext_80 = frame_64 + trailer  # 64 + 16 = 80 bytes
        cipher = AES.new(dynamic_key, AES.MODE_CTR, initial_value=nonce, nonce=b"")
        return cipher.encrypt(plaintext_80)

    def encode(self, channel: int, input_msg: bytes, timestamp: int) -> bytes:
        self.seq += 1
        seq = self.seq
        # Asegurar que el frame tenga 64 bytes
        if len(input_msg) > self.MAX_FRAME_SIZE:
            frame_64 = input_msg[:self.MAX_FRAME_SIZE]
        else:
            frame_64 = input_msg.ljust(self.MAX_FRAME_SIZE, b'\x00')
        # Obtener clave del canal
        K_channel = self._get_channel_key(channel)
        # Derivar dynamic_key
        dynamic_key = self._derive_dynamic_key(K_channel, seq, channel)
        # Cifrar frame + trailer (80 bytes)
        ciph_80 = self._encrypt_80bytes(dynamic_key, frame_64, timestamp, seq, channel)
        # Construir header (20 bytes): <I I I Q>
        header = struct.pack("<I I I Q", seq, channel, self.encoder_id, timestamp)
        # Nota: La suscripción se genera por separado y se inserta en el paquete final.
        # Aquí se retorna solo el frame cifrado con header.
        packet = header + ciph_80
        # En la integración final, el paquete completo será: header (20) + suscripción (52) + ciphertext (80) = 152 bytes.
        print("Sent pkt (152 bytes):")
        print(packet.hex())
        return packet

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Archivo JSON con 'channel_keys' y opcional 'KMAC'")
    parser.add_argument("channel", type=int, help="Canal ID")
    parser.add_argument("frame", help="Mensaje a enviar (se ajusta a 64 bytes)")
    parser.add_argument("timestamp", type=int, help="Timestamp de 64 bits (usado en trailer)")
    args = parser.parse_args()

    enc = Encoder(args.secrets_file.read())
    pkt = enc.encode(args.channel, args.frame.encode(), args.timestamp)
    print(pkt.hex())

if __name__ == "__main__":
    main()
