#!/usr/bin/env python3
"""
Known-Plaintext XOR Cracker
Usage: python3 auto_xor_brute.py --hex "1122334455..." --prefix "vere{"
"""
import argparse
import sys
import itertools

def solve(hex_string, prefix):
    try:
        ciphertext = bytes.fromhex(hex_string)
    except ValueError:
        print("[-] Invalid hex string.")
        sys.exit(1)
        
    prefix_bytes = prefix.encode()
    
    if len(ciphertext) < len(prefix_bytes):
        print("[-] Ciphertext is shorter than the prefix!")
        sys.exit(1)

    # Derive the key from the known prefix
    # key[i] = ciphertext[i] ^ plaintext[i]
    derived_key = bytearray()
    for i in range(len(prefix_bytes)):
        derived_key.append(ciphertext[i] ^ prefix_bytes[i])
        
    print(f"[*] Derived potential key prefix: {derived_key.hex()}")
    
    # Try different key lengths (assume repeating key)
    for key_len in range(1, len(derived_key) + 1):
        key = derived_key[:key_len]
        
        # Decrypt using this key length
        decrypted = bytearray()
        for i, byte in enumerate(ciphertext):
            decrypted.append(byte ^ key[i % len(key)])
            
        # Check if the result looks like printable ASCII
        if all(32 <= b <= 126 for b in decrypted):
            print(f"\n[+] SUCCESS! Repeating Key length: {key_len} ({key.hex()})")
            print(f"[+] FLAG: {decrypted.decode('ascii')}")
            return
            
    print("\n[-] Could not find a clean repeating key that yields printable ASCII.")
    print(f"[-] Raw partial decryption with full prefix key: ", end="")
    dec = bytearray([c ^ k for c, k in zip(ciphertext, itertools.cycle(derived_key))])
    print(repr(dec))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hex", required=True, help="Ciphertext in hex format")
    parser.add_argument("--prefix", default="vere{", help="Known plaintext prefix")
    args = parser.parse_args()
    solve(args.hex, args.prefix)
