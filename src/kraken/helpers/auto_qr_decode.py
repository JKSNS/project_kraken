#!/usr/bin/env python3
"""Decode QR codes from text-encoded bitmap data.

Handles formats:
  - Decimal integers per line (each integer's binary represents a row of pixels)
  - Space-separated binary data
  - ASCII art QR codes (using block characters)

Attempts multiple decoding strategies: pyzbar, manual QR parsing, image-based.
"""
import sys
import argparse


def decode_decimal_qr(data: str) -> list[list[int]] | None:
    """Convert decimal integers to a 2D binary matrix."""
    lines = data.strip().splitlines()
    rows = []
    max_bits = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            val = int(line)
            bits = bin(val)[2:]
            max_bits = max(max_bits, len(bits))
            rows.append(val)
        except ValueError:
            continue

    if not rows:
        return None

    # Convert to consistent-width binary matrix
    matrix = []
    for val in rows:
        bits = bin(val)[2:].zfill(max_bits)
        matrix.append([int(b) for b in bits])

    return matrix


def matrix_to_image(matrix: list[list[int]], scale: int = 20):
    """Convert binary matrix to PIL Image with QR quiet zone."""
    try:
        from PIL import Image
    except ImportError:
        return None

    height = len(matrix)
    width = len(matrix[0]) if matrix else 0

    # QR codes need a 4-module quiet zone around them
    quiet = 4 * scale
    img = Image.new("L", (width * scale + 2 * quiet, height * scale + 2 * quiet), 255)
    pixels = img.load()

    for y, row in enumerate(matrix):
        for x, val in enumerate(row):
            color = 0 if val else 255
            for dy in range(scale):
                for dx in range(scale):
                    pixels[quiet + x * scale + dx, quiet + y * scale + dy] = color

    return img


def decode_with_pyzbar(img):
    """Try decoding with pyzbar."""
    try:
        from pyzbar.pyzbar import decode
        results = decode(img)
        if results:
            return results[0].data.decode("utf-8", errors="replace")
    except ImportError:
        pass
    except Exception:
        pass
    return None


def decode_with_qrcode(matrix: list[list[int]]):
    """Try decoding with qrcode library (reader mode)."""
    try:
        import qrcode
        # qrcode library is mainly for generation, not reading
        return None
    except ImportError:
        return None


def decode_with_cv2(img):
    """Try decoding with OpenCV QR detector."""
    try:
        import cv2
        import numpy as np
        arr = np.array(img)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(arr)
        if data:
            return data
        # Try with WeChat QR detector as fallback
        try:
            wechat = cv2.wechat_qrcode.WeChatQRCode()
            results, _ = wechat.detectAndDecode(arr)
            if results:
                return results[0]
        except Exception:
            pass
    except ImportError:
        pass
    except Exception:
        pass
    return None


def decode_with_zxing(img_path: str):
    """Try decoding with zxingcpp."""
    try:
        import zxingcpp
        from PIL import Image
        img = Image.open(img_path)
        results = zxingcpp.read_barcodes(img)
        if results:
            return results[0].text
    except ImportError:
        pass
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Kraken QR Code Decoder")
    parser.add_argument("datafile", help="Path to QR code data file")
    args = parser.parse_args()

    try:
        with open(args.datafile) as f:
            data = f.read()
    except OSError as e:
        print(f"[-] Cannot read {args.datafile}: {e}")
        sys.exit(1)

    print(f"[*] Analyzing QR data: {args.datafile}")

    # Parse decimal format
    matrix = decode_decimal_qr(data)
    if not matrix:
        print("[-] Could not parse QR data")
        sys.exit(1)

    print(f"[*] Parsed {len(matrix)}x{len(matrix[0])} QR matrix")

    # Convert to image
    img = matrix_to_image(matrix)
    if img is None:
        print("[-] PIL not available, cannot create image")
        sys.exit(1)

    # Save temp image for fallback decoders
    import tempfile
    import os
    tmp_path = tempfile.mktemp(suffix=".png")
    img.save(tmp_path)
    print(f"[*] Saved QR image to {tmp_path}")

    # Try multiple decode strategies
    result = None

    # Strategy 1: pyzbar
    result = decode_with_pyzbar(img)
    if result:
        print(f"[+] QR_DECODE SUCCESS (pyzbar)")
        print(f"[+] EXTRACTED FLAG: {result}")
        os.unlink(tmp_path)
        return

    # Strategy 2: OpenCV
    result = decode_with_cv2(img)
    if result:
        print(f"[+] QR_DECODE SUCCESS (opencv)")
        print(f"[+] EXTRACTED FLAG: {result}")
        os.unlink(tmp_path)
        return

    # Strategy 3: zxingcpp
    result = decode_with_zxing(tmp_path)
    if result:
        print(f"[+] QR_DECODE SUCCESS (zxingcpp)")
        print(f"[+] EXTRACTED FLAG: {result}")
        os.unlink(tmp_path)
        return

    print("[-] QR_DECODE FAILED: No decoder could read the QR code")
    print(f"[-] QR image saved at: {tmp_path}")
    sys.exit(1)


if __name__ == "__main__":
    main()
