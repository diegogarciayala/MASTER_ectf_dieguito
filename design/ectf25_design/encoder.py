#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

This secure encoder produces packets of 96 bytes with the following structure:
  - Header (20 bytes): <I I I Q> => (seq, channel, encoder_id, timestamp)
  - Subscription (52 bytes): 36 bytes of data plus a 16-byte CMAC over that data using the channel key.
  - Ciphertext (24 bytes): Encryption of (frame, trailer) where:
         frame: 8 bytes (the original frame, padded/truncated)
         trailer: 16 bytes: <Q I I> (timestamp, seq, channel)
The encryption is done in AES-CTR mode with a dynamic key derived from the channel key.
"""

import argparse
import struct
import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def leftshift_onebit(block16: bytes) -> bytes:
    out = bytearray(16)
    overflow = 0
    for i in range(15, -1, -1):
        out[i] = ((block16[i] << 1) & 0xFE) | overflow
        overflow = 1 if (block16[i] & 0x80) else 0
    return bytes(out)

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(msg)
    return cobj.digest()

def store64_be(val: int) -> bytes:
    return val.to_bytes(8, byteorder='big')

class Encoder:
    MAX_FRAME_SIZE = 64  # Original frame size.
    def __init__(self, secrets_json: bytes = None):
        # Si no se proporcionan secretos, se intenta leer desde la ruta global
        if secrets_json is None:
            try:
                with open("/global.secrets", "rb") as f:
                    secrets_json = f.read()
            except Exception as e:
                raise ValueError(f"No se pudieron cargar los secretos desde /global.secrets: {e}")
        data = json.loads(secrets_json)
        if "channel_keys" not in data:
            raise ValueError("No se encontró 'channel_keys' en el JSON.")
        self.channel_keys = data["channel_keys"]
        self.some_secrets = data.get("some_secrets", "EXAMPLE")
        self.seq = 0
        self.encoder_id = 1  # Fijo según el original.

    def _get_channel_key(self, channel: int) -> bytes:
        key_b64 = self.channel_keys.get(str(channel))
        if not key_b64:
            raise ValueError(f"No se encontró clave para el canal {channel}.")
        return base64.b64decode(key_b64)

    def _derive_dynamic_key(self, K_channel: bytes, seq: int, channel: int) -> bytes:
        # Derive K1 = AES-CMAC(K_channel, "K1-Derivation")
        K1 = aes_cmac(K_channel, b"K1-Derivation")
        data_le = struct.pack("<I I", seq, channel)
        dynamic_key = aes_cmac(K1, data_le)
        return dynamic_key

    def _encrypt_24bytes(self, dynamic_key: bytes, frame_8: bytes, timestamp: int, seq: int, channel: int) -> bytes:
        # Trailer: pack as <Q I I> (timestamp, seq, channel)
        trailer = struct.pack("<Q I I", timestamp, seq, channel)
        plaintext = frame_8 + trailer  # 8 + 16 = 24 bytes
        # Nonce: 8 zero bytes + store64_be(seq)
        nonce = b"\x00"*8 + store64_be(seq)
        cipher = AES.new(dynamic_key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(nonce, 'big'))
        return cipher.encrypt(plaintext)

    def encode(self, channel: int, input_msg: bytes, timestamp: int) -> bytes:
        self.seq += 1
        seq = self.seq
        # Prepare frame: take input_msg, truncate or pad to 8 bytes.
        frame_8 = input_msg[:8].ljust(8, b'\x00')
        # Get channel key
        K_channel = self._get_channel_key(channel)
        # Derive dynamic key
        dynamic_key = self._derive_dynamic_key(K_channel, seq, channel)
        # Encrypt frame+trailer (24 bytes)
        ciph_24 = self._encrypt_24bytes(dynamic_key, frame_8, timestamp, seq, channel)
        # Header: pack as <I I I Q>
        header = struct.pack("<I I I Q", seq, channel, self.encoder_id, timestamp)
        # For subscription, use fixed start and end timestamps as in original design.
        start_time = 123456789
        end_time = 387654321
        # Pack subscription data: <I I Q Q 20s>
        subs_data = struct.pack("<I I Q Q 20s", channel, self.encoder_id, start_time, end_time, b'\x00'*20)
        mac_16 = aes_cmac(K_channel, subs_data)
        subscription = subs_data + mac_16  # 36+16=52 bytes.
        # Final packet: header (20) + subscription (52) + ciphertext (24) = 96 bytes.
        packet = header + subscription + ciph_24
        return packet

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Archivo JSON con las claves (channel_keys, some_secrets, etc.)")
    parser.add_argument("channel", type=int, help="Canal a codificar")
    parser.add_argument("frame", help="Contenido del frame")
    parser.add_argument("timestamp", type=int, help="Timestamp de 64 bits a utilizar")
    args = parser.parse_args()
    encoder = Encoder(args.secrets_file.read())
    packet = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(repr(packet))

if __name__ == "__main__":
    main()
