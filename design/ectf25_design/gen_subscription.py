#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is provided for educational purposes only.

In this secure version, in addition to packing the subscription data,
a CMAC is computed over the 36-byte subscription data using the channel key.
The final subscription is 36 bytes of data plus 16 bytes of MAC = 52 bytes.
"""

import argparse
import json
import struct
import base64
from loguru import logger

# For CMAC, we use the cryptography library
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

def derive_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    secrets_data = json.loads(secrets)
    # Si el canal es 0 (emergency), se usa una clave fija (32 bytes de 0xFF)
    if channel == 0:
        channel_key = b'\xFF' * 32
    else:
        channel_key_b64 = secrets_data.get("channel_keys", {}).get(str(channel))
        if channel_key_b64 is None:
            raise ValueError(f"No se encontró la clave para el canal {channel} en GS.")
        channel_key = base64.b64decode(channel_key_b64)
    # Empaquetar los 36 bytes de datos de suscripción:
    #   canal (4 bytes), decoder_id (4 bytes), start (8 bytes), end (8 bytes), 20 bytes de relleno.
    subs_data = struct.pack("<I I Q Q 20s", channel, device_id, start, end, b'\x00'*20)
    mac_16 = derive_cmac(channel_key, subs_data)
    subscription = subs_data + mac_16  # Total: 36 + 16 = 52 bytes.
    logger.debug(f"Generated subscription: {subscription.hex()}")
    return subscription

def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera el código de suscripción para un decodificador utilizando la clave específica del canal."
    )
    parser.add_argument("--force", "-f", action="store_true", help="Sobreescribir archivo de suscripción existente.")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Ruta al archivo de secretos creado por gen_secrets.py")
    parser.add_argument("subscription_file", type=str, help="Archivo de salida para la suscripción")
    parser.add_argument("device_id", type=lambda x: int(x, 0), help="ID del decodificador (DECODER_ID)")
    parser.add_argument("start", type=lambda x: int(x, 0), help="Timestamp de inicio de la suscripción")
    parser.add_argument("end", type=int, help="Timestamp de expiración de la suscripción")
    parser.add_argument("channel", type=int, help="Canal a suscribir")
    return parser.parse_args()

def main():
    args = parse_args()
    subscription = gen_subscription(args.secrets_file.read(), args.device_id, args.start, args.end, args.channel)
    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as f:
        f.write(subscription)
    logger.success(f"Wrote subscription to {args.subscription_file}")

if __name__ == "__main__":
    main()
