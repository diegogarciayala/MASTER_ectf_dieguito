import argparse
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import base64

def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate secure secrets file with channel-specific keys and MAC key
    
    :param channels: List of channel numbers that will be valid in this deployment
    :returns: Contents of the secrets file
    """
    # Generate master key (32 bytes for AES-256)
    master_key = os.urandom(32)
    
    # Derive channel-specific keys and MAC key using AES-CMAC
    channel_keys = {}
    for channel in channels:
        # Use HMAC with SHA256 to derive channel-specific key
        h = hmac.HMAC(master_key, hashes.SHA256(), backend=default_backend())
        h.update(f"channel_{channel}".encode())
        channel_keys[channel] = h.finalize()
    
    # Derive MAC key
    h = hmac.HMAC(master_key, hashes.SHA256(), backend=default_backend())
    h.update(b"mac_key")
    mac_key = h.finalize()
    
    # Create secrets dictionary
    secrets = {
        "master_key": base64.b64encode(master_key).decode(),
        "channels": channels,
        "channel_keys": {
            str(ch): base64.b64encode(key).decode() for ch, key in channel_keys.items()
        },
        "mac_key": base64.b64encode(mac_key).decode()
    }
    
    return json.dumps(secrets).encode()

def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()

def main():
    """Main function of gen_secrets"""
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    print(f"Wrote secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()