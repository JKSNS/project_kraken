#!/usr/bin/env python3
"""
Safe C-Code Variable Renamer for Kraken Agent
Usage: python3 auto_normalize.py decompile.c rename_map.json --out clean.c
"""
import re
import json
import argparse
import sys

def normalize_code(source_file, map_file, out_file):
    print(f"[*] Loading rename mapping from {map_file}...")
    try:
        with open(map_file, 'r') as f:
            renames = json.load(f)
    except Exception as e:
        print(f"[-] Failed to load JSON map: {e}")
        print("[-] Ensure your mapping file is valid JSON. Example: {\"local_18\": \"flag_idx\", \"uVar1\": \"encrypted_char\"}")
        sys.exit(1)

    print(f"[*] Reading source from {source_file}...")
    try:
        with open(source_file, 'r') as f:
            code = f.read()
    except Exception as e:
        print(f"[-] Failed to read source file: {e}")
        sys.exit(1)

    print(f"[*] Applying {len(renames)} regex boundary replacements...")
    
    # Sort keys by length descending so longer variable names are replaced first 
    # (e.g., local_100 before local_10) to prevent partial replacement collisions.
    sorted_keys = sorted(renames.keys(), key=len, reverse=True)
    
    for old_name in sorted_keys:
        new_name = renames[old_name]
        # Use \b (word boundaries) so we don't accidentally replace 'i' inside 'int'
        # re.escape ensures any weird characters in variable names are treated safely
        pattern = rf'\b{re.escape(old_name)}\b'
        
        # Track how many replacements we make for debugging
        count = len(re.findall(pattern, code))
        if count > 0:
            code = re.sub(pattern, new_name, code)
            print(f"    -> Replaced '{old_name}' with '{new_name}' ({count} times)")
        else:
            print(f"    -> WARNING: '{old_name}' not found in source code.")

    try:
        with open(out_file, 'w') as f:
            f.write(code)
        print(f"\n[+] Normalization complete! Clean code saved to: {out_file}")
    except Exception as e:
        print(f"[-] Failed to write output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kraken Safe Variable Renamer")
    parser.add_argument("source", help="Original C file (e.g., decompile.c)")
    parser.add_argument("map", help="JSON file containing {'old_name': 'new_name'} mapping")
    parser.add_argument("--out", default="normalized.c", help="Output file name")
    
    args = parser.parse_args()
    normalize_code(args.source, args.map, args.out)
