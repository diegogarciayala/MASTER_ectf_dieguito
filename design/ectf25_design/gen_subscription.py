#!/usr/bin/env python3
"""
gen_subscription.py
-------------------
Genera el código de suscripción para un decodificador usando la clave específica del canal.
El código de suscripción se genera a partir de:
  - 36 bytes de datos, empaquetados con: 
      canal (4 bytes), decoder_id (4 bytes), ts_start (4 bytes), ts_end (4 bytes),
      y 20 bytes de relleno.
  - Se calcula un CMAC (16 bytes) usando la clave específica del canal.
El paquete final tiene 52 bytes.
"""

import argparse
import json
import struct
import base64
from pathlib import Path

def derive_cmac(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    secrets_data = json.loads(secrets)
    if "channel_keys" not in secrets_data:
        raise ValueError("El archivo de secretos no contiene 'channel_keys'.")
    channel_key_b64 = secrets_data["channel_keys"].get(str(channel))
    if channel_key_b64 is None:
        raise ValueError(f"No se encontró la clave para el canal {channel} en GS.")
    channel_key = base64.b64decode(channel_key_b64)
    # Empaquetar 36 bytes de datos: canal, decoder_id, start, end y 20 bytes de relleno.
    subs_data = struct.pack("<I I I I 20s", channel, device_id, start, end, b'\x00'*20)
    mac_16 = derive_cmac(channel_key, subs_data)
    subscription = subs_data + mac_16  # 36 + 16 = 52 bytes
    print(f"\n[gen_subscription] Subscription final (length = {len(subscription)} bytes): {subscription.hex()}\n")
    return subscription

def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera el código de suscripción para un decodificador utilizando la clave específica del canal."
    )
    parser.add_argument("--force", "-f", action="store_true", help="Sobreescribir archivo de suscripción existente.")
    parser.add_argument("secrets_file", type=str, help="Ruta al archivo de secretos generado con gen_secrets.py")
    parser.add_argument("subscription_file", type=str, help="Archivo de salida para la suscripción")
    parser.add_argument("device_id", type=lambda x: int(x, 0), help="ID del decodificador (decoder_id)")
    parser.add_argument("start", type=lambda x: int(x, 0), help="Timestamp de inicio de la suscripción (32-bit)")
    parser.add_argument("end", type=int, help="Timestamp de expiración de la suscripción (32-bit)")
    parser.add_argument("channel", type=int, help="Canal (channel) a suscribir")
    return parser.parse_args()

def main():
    args = parse_args()
    with open(args.secrets_file, "rb") as f:
        secrets = f.read()
    subscription = gen_subscription(secrets, args.device_id, args.start, args.end, args.channel)
    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as f:
        f.write(subscription)
    print(f"\n[gen_subscription] Código de suscripción generado en {args.subscription_file}\n")

if __name__ == "__main__":
    main()
