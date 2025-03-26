#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

Este módulo genera el archivo de secretos para eCTF. Se crea un master key aleatoria
y se derivan las claves de cada canal (incluyendo el canal 0 de emergencia) y la clave de
autenticación (K_mac) usando AES-CMAC.
"""

import argparse
import json
import os
import binascii
from pathlib import Path
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from loguru import logger

def derive_key(master_key: bytes, label: bytes) -> bytes:
    c = CMAC(algorithms.AES(master_key))
    c.update(label)
    return c.finalize()

def gen_secrets(channels: list[int]) -> bytes:
    master_key = os.urandom(16)
    K_mac = derive_key(master_key, b"MAC")
    all_channels = set(channels)
    all_channels.add(0)
    keys = {}
    for ch in all_channels:
        label = b"CHANNEL" + ch.to_bytes(4, "little")
        keys[str(ch)] = binascii.hexlify(derive_key(master_key, label)).decode()
    secrets = {
        "master_key": binascii.hexlify(master_key).decode(),
        "K_mac": binascii.hexlify(K_mac).decode(),
        "keys": keys,
        "channels": channels  # canales originalmente especificados (sin el 0)
    }
    return json.dumps(secrets).encode()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument("secrets_file", type=Path,
                        help="Path to the secrets file to be created")
    parser.add_argument("channels", nargs="+", type=int,
                        help="Supported channels. Channel 0 (broadcast) is always valid and will not be provided in this list")
    return parser.parse_args()

def main():
    args = parse_args()
    secrets = gen_secrets(args.channels)
    logger.debug(f"Generated secrets: {secrets}")
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()
