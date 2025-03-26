#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

Este módulo genera un código de suscripción seguro para un decodificador.
El formato es:
    {CHID (4B) | DECODER_ID (4B) | TS_start (8B) | TS_end (8B) | HMAC (16B)}
El HMAC se calcula con AES-CMAC usando la clave derivada para el canal.
"""

import argparse
import json
import struct
import binascii
from pathlib import Path
from loguru import logger
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    # Se carga el JSON de los secretos
    secrets = json.loads(secrets)
    # Se obtiene la clave para el canal solicitado
    key_hex = secrets["keys"].get(str(channel))
    if not key_hex:
        raise ValueError("Clave para canal no encontrada")
    channel_key = bytes.fromhex(key_hex)
    # Prepara los datos de la suscripción:
    # {channel (uint32), decoder_id (uint32), ts_start (uint64), ts_end (uint64)}
    data = struct.pack("<IIQQ", channel, device_id, start, end)
    # Calcula el HMAC usando AES-CMAC (cryptography)
    cobj = CMAC(algorithms.AES(channel_key))
    cobj.update(data)
    hmac = cobj.finalize()
    # Retorna la suscripción completa: datos || HMAC
    return data + hmac

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Path to the secrets file created by ectf25_design.gen_secrets")
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument("device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient.")
    parser.add_argument("start", type=lambda x: int(x, 0), help="Subscription start timestamp")
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()

def main():
    args = parse_args()
    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )
    logger.debug(f"Generated subscription: {subscription}")
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")

if __name__ == "__main__":
    main()
