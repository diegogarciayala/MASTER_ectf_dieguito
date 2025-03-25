#!/usr/bin/env python3
"""
gen_secrets.py
---------------
Genera el archivo de secretos (Global Secrets, GS) para el sistema seguro.

El archivo contendrá:
  - "channels": la lista de canales válidos.
  - "channel_keys": para cada canal se genera una clave aleatoria de 32 bytes (codificada en base64).
  - "KMAC": una clave aleatoria de 16 bytes (codificada en base64).
  - "partial_keys": un diccionario de claves aleatorias de 16 bytes (codificadas en base64) para cada decodificador.

Uso:
  python gen_secrets.py secrets.json <channel1> <channel2> ... [num_decoders]
"""

import argparse
import json
import os
import base64
from typing import List

def gen_secrets(channels: List[int], num_decoders: int = 8) -> bytes:
    KMAC = os.urandom(16)
    channel_keys = {str(channel): base64.b64encode(os.urandom(32)).decode('utf-8')
                    for channel in channels}
    partial_keys = {f"decoder_{i}": base64.b64encode(os.urandom(16)).decode('utf-8')
                    for i in range(1, num_decoders + 1)}
    secrets = {
        "channels": channels,
        "channel_keys": channel_keys,
        "KMAC": base64.b64encode(KMAC).decode('utf-8'),
        "partial_keys": partial_keys
    }
    secrets_json = json.dumps(secrets, indent=2)
    print(f"\n[gen_secrets] Final secrets JSON generated (total length = {len(secrets_json.encode('utf-8'))} bytes).\n")
    return secrets_json.encode('utf-8')

def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera el archivo de secretos para el sistema seguro."
    )
    parser.add_argument("--force", "-f", action="store_true", help="Sobreescribir archivo de secretos existente.")
    parser.add_argument("secrets_file", type=str, help="Ruta del archivo de secretos a crear.")
    parser.add_argument("channels", nargs="+", type=int, help="Lista de canales válidos (excluyendo canal 0).")
    parser.add_argument("num_decoders", nargs="?", type=int, default=8,
                        help="Número de decodificadores (por defecto 8).")
    return parser.parse_args()

def main():
    args = parse_args()
    secrets_data = gen_secrets(args.channels, args.num_decoders)
    mode = "wb" if args.force else "xb"
    with open(args.secrets_file, mode) as f:
        f.write(secrets_data)
    print(f"\n[gen_secrets] Archivo de secretos generado en {args.secrets_file}\n")

if __name__ == "__main__":
    main()
