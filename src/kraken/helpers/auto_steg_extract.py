#!/usr/bin/env python3
"""auto_steg_extract -- Steganography extraction tool for CTF challenges.

Scans a challenge directory for image files and applies multiple extraction
methods to recover hidden data:
  - LSB extraction (stegano library)
  - EXIF metadata inspection (Pillow)
  - Raw strings search
  - Binwalk embedded file extraction
  - Appended data after image markers (PNG IEND, JPEG FFD9)
  - Per-channel LSB pixel extraction (Pillow)
  - Audio steganography (spectrogram, LSB, DTMF, morse)
  - zsteg integration for comprehensive LSB analysis
  - steghide extraction with password brute-force
  - Multi-bit-plane analysis across channels
  - stegsolve-like bit plane scanning

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff")
AUDIO_EXTENSIONS = (".wav", ".mp3", ".ogg", ".flac", ".aiff", ".au")

DEFAULT_FLAG_PATTERN = r"[a-zA-Z_]{2,}\{[^}]{3,}\}"


def _find_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-pattern matches found in text."""
    flags = []
    pattern = flag_format if flag_format else DEFAULT_FLAG_PATTERN
    for m in re.finditer(pattern, text):
        flags.append(m.group(0))
    return flags


# ---------------------------------------------------------------------------
# Extraction methods
# ---------------------------------------------------------------------------

def _lsb_extract(image_path: str) -> list[str]:
    """Use stegano.lsb.reveal() on PNG/BMP files."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext not in (".png", ".bmp"):
        return []
    try:
        from stegano.lsb import reveal
        secret = reveal(image_path)
        if secret and len(secret) >= 3:
            return [secret]
    except ImportError:
        pass
    except Exception:
        pass
    return []


def _exif_extract(image_path: str) -> list[str]:
    """Read EXIF tags and check common metadata fields for hidden data."""
    results = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return results

    try:
        img = Image.open(image_path)
    except Exception:
        return results

    # Check standard EXIF data
    try:
        exif_data = img._getexif()
        if exif_data:
            target_tags = {"ImageDescription", "UserComment", "Artist",
                           "Copyright", "Comment"}
            tag_name_map = {v: k for k, v in TAGS.items()}
            for tag_name in target_tags:
                tag_id = tag_name_map.get(tag_name)
                if tag_id and tag_id in exif_data:
                    value = exif_data[tag_id]
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")
                    value = str(value).strip()
                    if value and len(value) >= 3:
                        results.append(value)
    except Exception:
        pass

    # Check PIL info dict (covers PNG text chunks, GIF comments, etc.)
    try:
        info = img.info or {}
        for key in ("Comment", "comment", "Description", "description",
                     "Author", "author", "Copyright", "copyright",
                     "flag", "Flag", "FLAG"):
            if key in info:
                value = info[key]
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                value = str(value).strip()
                if value and len(value) >= 3:
                    results.append(value)
    except Exception:
        pass

    return results


def _strings_from_image(image_path: str) -> list[str]:
    """Run the strings command on raw file bytes and scan for flags."""
    results = []
    try:
        proc = subprocess.run(
            ["strings", "-n", "6", image_path],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0 and proc.stdout:
            results.append(proc.stdout)
    except FileNotFoundError:
        # strings command not available; fall back to manual extraction
        try:
            raw = open(image_path, "rb").read()
            # Extract sequences of printable ASCII (length >= 6)
            for m in re.finditer(rb"[\x20-\x7e]{6,}", raw):
                results.append(m.group(0).decode("ascii"))
        except Exception:
            pass
    except Exception:
        pass
    return results


def _binwalk_extract(image_path: str) -> list[str]:
    """Run binwalk -e in a temp directory and scan extracted files for flags."""
    results = []
    tmpdir = tempfile.mkdtemp(prefix="steg_binwalk_")
    try:
        proc = subprocess.run(
            ["binwalk", "-e", "-C", tmpdir, "--run-as=root", image_path],
            capture_output=True, text=True, timeout=60,
        )
        # Also try without --run-as=root in case binwalk rejects it
        if proc.returncode != 0:
            proc = subprocess.run(
                ["binwalk", "-e", "-C", tmpdir, image_path],
                capture_output=True, text=True, timeout=60,
            )

        # Recursively scan all extracted files for text content
        for root, _dirs, files in os.walk(tmpdir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read(1024 * 1024)  # cap at 1 MB
                    # Try decoding as text
                    text = data.decode("utf-8", errors="replace")
                    if text and len(text.strip()) >= 3:
                        results.append(text)
                except Exception:
                    pass
    except FileNotFoundError:
        pass  # binwalk not installed
    except Exception:
        pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return results


def _check_appended_data(image_path: str) -> list[str]:
    """Look for data appended after PNG IEND or JPEG FFD9 markers."""
    results = []
    try:
        raw = open(image_path, "rb").read()
    except Exception:
        return results

    trailer_offset = -1

    # PNG: IEND chunk -- the CRC of the IEND chunk ends at the marker
    iend_marker = b"IEND\xae\x42\x60\x82"
    idx = raw.find(iend_marker)
    if idx != -1:
        trailer_offset = idx + len(iend_marker)
    else:
        # Try alternate form with zero-length chunk
        iend_alt = b"\x00\x00\x00\x00IEND"
        idx = raw.find(iend_alt)
        if idx != -1:
            # Full IEND chunk is 12 bytes: length(4) + "IEND"(4) + CRC(4)
            trailer_offset = idx + 12

    # JPEG: FFD9 end-of-image marker
    if trailer_offset == -1:
        idx = raw.find(b"\xff\xd9")
        if idx != -1:
            trailer_offset = idx + 2

    if trailer_offset != -1 and trailer_offset < len(raw):
        appended = raw[trailer_offset:]
        if len(appended) >= 3:
            # Check if the appended data is mostly printable text
            try:
                text = appended.decode("utf-8", errors="replace")
                printable_count = sum(
                    1 for c in text if c.isprintable() or c in "\n\r\t"
                )
                if printable_count > len(text) * 0.5:
                    results.append(text.strip())
            except Exception:
                pass
            # Also try latin-1 if utf-8 was lossy
            try:
                text = appended.decode("latin-1")
                printable_count = sum(
                    1 for c in text if c.isprintable() or c in "\n\r\t"
                )
                if printable_count > len(text) * 0.5:
                    decoded = text.strip()
                    if decoded not in results:
                        results.append(decoded)
            except Exception:
                pass
    return results


def _pixel_channel_extract(image_path: str) -> list[str]:
    """Extract LSBs from R, G, B channels separately and try to decode."""
    results = []
    try:
        from PIL import Image
    except ImportError:
        return results

    try:
        img = Image.open(image_path).convert("RGB")
    except Exception:
        return results

    width, height = img.size
    # Cap pixel count to avoid excessive processing
    if width * height > 4_000_000:
        return results

    pixels = list(img.getdata())

    for channel_idx, channel_name in enumerate(("R", "G", "B")):
        bits = []
        for pixel in pixels:
            bits.append(pixel[channel_idx] & 1)
            # Stop after collecting enough bits for a reasonable message
            if len(bits) >= 8192:
                break

        # Convert bits to bytes
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for bit in bits[i:i + 8]:
                byte_val = (byte_val << 1) | bit
            if byte_val == 0:
                break
            chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

        text = "".join(chars)
        # Only keep if we got a reasonable amount of printable text
        if len(text) >= 6:
            printable_count = sum(1 for c in text if c.isprintable())
            if printable_count > len(text) * 0.7:
                results.append(text)

    return results


# ---------------------------------------------------------------------------
# zsteg Integration
# ---------------------------------------------------------------------------

def _zsteg_extract(image_path: str) -> list[str]:
    """Run zsteg for comprehensive LSB analysis on PNG/BMP files."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext not in (".png", ".bmp"):
        return []

    results = []

    # Try zsteg with --all flag for exhaustive analysis
    try:
        result = subprocess.run(
            ['zsteg', image_path, '--all'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            results.append(result.stdout)
    except FileNotFoundError:
        # zsteg not installed, try installing via gem
        try:
            subprocess.run(
                ['gem', 'install', 'zsteg'],
                capture_output=True, timeout=60
            )
            result = subprocess.run(
                ['zsteg', image_path, '--all'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                results.append(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    except subprocess.TimeoutExpired:
        # Try with less exhaustive options
        try:
            result = subprocess.run(
                ['zsteg', image_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                results.append(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return results


# ---------------------------------------------------------------------------
# Steghide Extraction with Password Attempts
# ---------------------------------------------------------------------------

def _steghide_extract(image_path: str) -> list[str]:
    """Try steghide extraction with common passwords on JPEG/BMP files."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
        return []

    results = []
    passwords = [
        '', 'password', 'secret', 'flag', 'ctf', 'admin', '123456',
        'hidden', 'steg', 'steganography', 'pass', '1234', 'test',
        'root', 'qwerty', 'letmein', 'abc123', 'monkey', 'master',
    ]

    # Also try the image filename (without extension) as password
    basename = os.path.splitext(os.path.basename(image_path))[0]
    if basename and basename not in passwords:
        passwords.insert(1, basename)

    outfile = tempfile.mktemp(prefix="steghide_", suffix=".txt")
    for pw in passwords:
        try:
            result = subprocess.run(
                ['steghide', 'extract', '-sf', image_path,
                 '-p', pw, '-f', '-xf', outfile],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(f"  [+] steghide extracted with password: '{pw}'")
                try:
                    with open(outfile, 'rb') as f:
                        data = f.read(1024 * 1024)
                    # Try text decode
                    text = data.decode('utf-8', errors='replace')
                    if text.strip():
                        results.append(text.strip())
                except OSError:
                    pass
                finally:
                    try:
                        os.unlink(outfile)
                    except OSError:
                        pass
                break  # Stop after first successful extraction
        except FileNotFoundError:
            break  # steghide not installed
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    # Clean up
    try:
        os.unlink(outfile)
    except OSError:
        pass

    return results


# ---------------------------------------------------------------------------
# Multi-Bit-Plane Analysis
# ---------------------------------------------------------------------------

def _multi_bitplane_extract(image_path: str) -> list[str]:
    """Extract data from multiple bit planes (not just LSB) across channels.

    Checks bits 0-3 of each RGB channel and also cross-channel combinations.
    """
    results = []
    try:
        from PIL import Image
    except ImportError:
        return results

    try:
        img = Image.open(image_path).convert("RGB")
    except Exception:
        return results

    width, height = img.size
    if width * height > 4_000_000:
        return results

    pixels = list(img.getdata())

    # Check individual channel bits 1, 2, 3 (bit 0 is already covered by
    # _pixel_channel_extract)
    for channel_idx in range(3):
        for bit_pos in (1, 2, 3):
            bits = []
            for pixel in pixels:
                bits.append((pixel[channel_idx] >> bit_pos) & 1)
                if len(bits) >= 8192:
                    break

            chars = []
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit in bits[i:i + 8]:
                    byte_val = (byte_val << 1) | bit
                if byte_val == 0:
                    break
                chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

            text = "".join(chars)
            if len(text) >= 6:
                printable_count = sum(1 for c in text if c.isprintable())
                if printable_count > len(text) * 0.7:
                    results.append(text)

    # Cross-channel LSB combination: interleave R0, G0, B0 per pixel
    bits = []
    for pixel in pixels:
        bits.append(pixel[0] & 1)  # R bit 0
        bits.append(pixel[1] & 1)  # G bit 0
        bits.append(pixel[2] & 1)  # B bit 0
        if len(bits) >= 8192:
            break

    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for bit in bits[i:i + 8]:
            byte_val = (byte_val << 1) | bit
        if byte_val == 0:
            break
        chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

    text = "".join(chars)
    if len(text) >= 6:
        printable_count = sum(1 for c in text if c.isprintable())
        if printable_count > len(text) * 0.7:
            results.append(text)

    # Alpha channel LSB (if present)
    try:
        img_rgba = Image.open(image_path).convert("RGBA")
        pixels_rgba = list(img_rgba.getdata())
        bits = []
        for pixel in pixels_rgba:
            if pixel[3] != 255:  # Non-fully-opaque pixel
                bits.append(pixel[3] & 1)
            if len(bits) >= 8192:
                break

        if len(bits) >= 8:
            chars = []
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit in bits[i:i + 8]:
                    byte_val = (byte_val << 1) | bit
                if byte_val == 0:
                    break
                chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

            text = "".join(chars)
            if len(text) >= 6:
                printable_count = sum(1 for c in text if c.isprintable())
                if printable_count > len(text) * 0.7:
                    results.append(text)
    except Exception:
        pass

    return results


# ---------------------------------------------------------------------------
# Audio Steganography
# ---------------------------------------------------------------------------

def _extract_audio_steg(audio_path: str) -> list[str]:
    """Extract hidden data from audio files using multiple techniques."""
    results = []

    # Method 1: Spectrogram analysis -- render spectrogram as image and OCR
    tmpdir = tempfile.mkdtemp(prefix="steg_audio_")
    spec_path = os.path.join(tmpdir, "spectrogram.png")
    try:
        subprocess.run(
            ['sox', audio_path, '-n', 'spectrogram', '-o', spec_path],
            capture_output=True, timeout=30
        )
        if os.path.isfile(spec_path):
            print(f"  [*] Generated spectrogram, checking for text...")
            # Try OCR on the spectrogram
            try:
                ocr_result = subprocess.run(
                    ['tesseract', spec_path, '-', '--psm', '6'],
                    capture_output=True, text=True, timeout=30
                )
                if ocr_result.returncode == 0 and ocr_result.stdout.strip():
                    ocr_text = ocr_result.stdout.strip()
                    if len(ocr_text) >= 3:
                        results.append(ocr_text)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Method 2: Raw strings from audio file
    try:
        proc = subprocess.run(
            ["strings", "-n", "6", audio_path],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0 and proc.stdout:
            results.append(proc.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 3: LSB of audio samples (WAV files)
    ext = os.path.splitext(audio_path)[1].lower()
    if ext == ".wav":
        try:
            with open(audio_path, 'rb') as f:
                data = f.read()

            # Parse WAV header to find data chunk
            # Minimal WAV parser: find 'data' marker
            data_idx = data.find(b'data')
            if data_idx >= 0 and data_idx + 8 < len(data):
                data_size = struct.unpack_from('<I', data, data_idx + 4)[0]
                audio_data = data[data_idx + 8:data_idx + 8 + data_size]

                # Check bits per sample from fmt chunk
                fmt_idx = data.find(b'fmt ')
                bits_per_sample = 16  # default
                if fmt_idx >= 0 and fmt_idx + 24 < len(data):
                    bits_per_sample = struct.unpack_from('<H', data, fmt_idx + 22)[0]

                if bits_per_sample == 16 and len(audio_data) >= 16:
                    # Extract LSB from 16-bit samples
                    bits = []
                    for i in range(0, min(len(audio_data) - 1, 16384), 2):
                        sample = struct.unpack_from('<h', audio_data, i)[0]
                        bits.append(sample & 1)

                    chars = []
                    for i in range(0, len(bits) - 7, 8):
                        byte_val = 0
                        for bit in bits[i:i + 8]:
                            byte_val = (byte_val << 1) | bit
                        if byte_val == 0:
                            break
                        chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

                    text = "".join(chars)
                    if len(text) >= 6:
                        printable_count = sum(1 for c in text if c.isprintable())
                        if printable_count > len(text) * 0.7:
                            results.append(text)

                elif bits_per_sample == 8 and len(audio_data) >= 8:
                    bits = []
                    for i in range(min(len(audio_data), 8192)):
                        bits.append(audio_data[i] & 1)

                    chars = []
                    for i in range(0, len(bits) - 7, 8):
                        byte_val = 0
                        for bit in bits[i:i + 8]:
                            byte_val = (byte_val << 1) | bit
                        if byte_val == 0:
                            break
                        chars.append(chr(byte_val) if 32 <= byte_val < 127 else "")

                    text = "".join(chars)
                    if len(text) >= 6:
                        printable_count = sum(1 for c in text if c.isprintable())
                        if printable_count > len(text) * 0.7:
                            results.append(text)
        except Exception:
            pass

        # Method 4: Try scipy spectrogram analysis
        try:
            import scipy.io.wavfile as wav
            from scipy.signal import spectrogram as scipy_spec
            import numpy as np

            rate, wav_data = wav.read(audio_path)
            if len(wav_data.shape) > 1:
                wav_data = wav_data[:, 0]  # mono

            f, t, Sxx = scipy_spec(wav_data, rate, nperseg=1024)
            # Look for patterns in high frequencies (common hiding location)
            # Check if high-frequency bins have unusual energy patterns
            high_freq_mask = f > rate * 0.4
            if np.any(high_freq_mask):
                high_energy = Sxx[high_freq_mask, :]
                # Binarize: if a time-frequency bin has energy above threshold
                threshold = np.median(high_energy) * 10
                binary = (high_energy > threshold).astype(int)
                # Try to decode binary patterns row by row
                for row in binary:
                    if np.sum(row) > 0:
                        bits = row.tolist()
                        chars = []
                        for i in range(0, len(bits) - 7, 8):
                            byte_val = 0
                            for bit in bits[i:i + 8]:
                                byte_val = (byte_val << 1) | bit
                            if byte_val == 0:
                                break
                            if 32 <= byte_val < 127:
                                chars.append(chr(byte_val))
                        text = "".join(chars)
                        if len(text) >= 6:
                            printable_count = sum(1 for c in text if c.isprintable())
                            if printable_count > len(text) * 0.7:
                                results.append(text)
                                break
        except (ImportError, Exception):
            pass

    # Method 5: Morse code detection (basic amplitude envelope)
    if ext == ".wav":
        try:
            with open(audio_path, 'rb') as f:
                data = f.read()
            data_idx = data.find(b'data')
            if data_idx >= 0 and data_idx + 8 < len(data):
                data_size = struct.unpack_from('<I', data, data_idx + 4)[0]
                audio_data = data[data_idx + 8:data_idx + 8 + min(data_size, 1024 * 1024)]

                fmt_idx = data.find(b'fmt ')
                sample_rate = 44100
                if fmt_idx >= 0 and fmt_idx + 12 < len(data):
                    sample_rate = struct.unpack_from('<I', data, fmt_idx + 12)[0]

                # Basic amplitude envelope analysis for morse-like patterns
                # Compute RMS in short windows
                window_samples = max(int(sample_rate * 0.01), 100)  # 10ms windows
                bits_per_sample = 16
                if fmt_idx >= 0 and fmt_idx + 24 < len(data):
                    bits_per_sample = struct.unpack_from('<H', data, fmt_idx + 22)[0]

                if bits_per_sample == 16:
                    samples = []
                    for i in range(0, len(audio_data) - 1, 2):
                        samples.append(abs(struct.unpack_from('<h', audio_data, i)[0]))

                    # Compute envelope
                    envelope = []
                    for i in range(0, len(samples) - window_samples, window_samples):
                        window = samples[i:i + window_samples]
                        rms = (sum(s * s for s in window) / len(window)) ** 0.5
                        envelope.append(rms)

                    if envelope:
                        threshold = max(envelope) * 0.3
                        # Binarize: signal on/off
                        binary = [1 if e > threshold else 0 for e in envelope]

                        # Detect morse pattern: runs of 1s and 0s
                        # Short run (1-3 units) = dot, long run (4+ units) = dash
                        # This is a heuristic for well-formatted morse
                        morse_str = ""
                        run_val = binary[0]
                        run_len = 1
                        for i in range(1, len(binary)):
                            if binary[i] == run_val:
                                run_len += 1
                            else:
                                if run_val == 1:
                                    if run_len <= 3:
                                        morse_str += "."
                                    else:
                                        morse_str += "-"
                                else:
                                    if run_len >= 6:
                                        morse_str += " "
                                    elif run_len >= 3:
                                        morse_str += "/"
                                run_val = binary[i]
                                run_len = 1

                        if len(morse_str) >= 5:
                            # Decode morse
                            MORSE_CODE = {
                                '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
                                '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
                                '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
                                '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
                                '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
                                '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                                '-.--': 'Y', '--..': 'Z',
                                '-----': '0', '.----': '1', '..---': '2',
                                '...--': '3', '....-': '4', '.....': '5',
                                '-....': '6', '--...': '7', '---..': '8',
                                '----.': '9',
                                '.-.-.-': '.', '--..--': ',', '..--..': '?',
                                '-.--.': '(', '-.--.-': ')', '-....-': '-',
                                '.-..-.': '"', '---...': ':', '-.-.-.': ';',
                                '-..-.': '/', '..--.-': '_',
                                '-.--..': '{', '-.--.-': '}',
                            }
                            words = morse_str.split(' ')
                            decoded_chars = []
                            for word in words:
                                letters = word.split('/')
                                for letter in letters:
                                    letter = letter.strip()
                                    if letter in MORSE_CODE:
                                        decoded_chars.append(MORSE_CODE[letter])
                                decoded_chars.append(' ')

                            decoded_text = ''.join(decoded_chars).strip()
                            if len(decoded_text) >= 3:
                                results.append(decoded_text)
        except Exception:
            pass

    # Method 6: Steghide for audio files
    if ext in (".wav", ".au"):
        steg_results = _steghide_extract(audio_path)
        results.extend(steg_results)

    return results


# ---------------------------------------------------------------------------
# PNG Chunk Analysis
# ---------------------------------------------------------------------------

def _png_chunk_extract(image_path: str) -> list[str]:
    """Parse PNG chunks for hidden text data in non-standard chunks."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext != ".png":
        return []

    results = []
    try:
        with open(image_path, 'rb') as f:
            # Check PNG signature
            sig = f.read(8)
            if sig != b'\x89PNG\r\n\x1a\n':
                return results

            while True:
                chunk_header = f.read(8)
                if len(chunk_header) < 8:
                    break

                length = struct.unpack('>I', chunk_header[:4])[0]
                chunk_type = chunk_header[4:8]

                if length > 10 * 1024 * 1024:  # Safety limit
                    break

                chunk_data = f.read(length)
                crc = f.read(4)

                chunk_type_str = chunk_type.decode('ascii', errors='replace')

                # Text chunks: tEXt, zTXt, iTXt
                if chunk_type in (b'tEXt', b'zTXt', b'iTXt'):
                    try:
                        if chunk_type == b'tEXt':
                            # keyword\0text
                            parts = chunk_data.split(b'\x00', 1)
                            if len(parts) == 2:
                                text = parts[1].decode('latin-1', errors='replace')
                                if text.strip():
                                    results.append(text.strip())
                        elif chunk_type == b'zTXt':
                            # keyword\0compression_method\0compressed_text
                            null_idx = chunk_data.find(b'\x00')
                            if null_idx >= 0 and null_idx + 2 < len(chunk_data):
                                import zlib
                                compressed = chunk_data[null_idx + 2:]
                                try:
                                    text = zlib.decompress(compressed).decode('latin-1', errors='replace')
                                    if text.strip():
                                        results.append(text.strip())
                                except zlib.error:
                                    pass
                        elif chunk_type == b'iTXt':
                            # keyword\0compression_flag\0compression_method\0language\0translated_keyword\0text
                            parts = chunk_data.split(b'\x00', 4)
                            if len(parts) >= 5:
                                text = parts[4].decode('utf-8', errors='replace')
                                if text.strip():
                                    results.append(text.strip())
                    except Exception:
                        pass

                # Non-standard/custom chunks might hide data
                elif chunk_type_str.islower() or not chunk_type_str.isascii():
                    # Ancillary chunk (lowercase first letter)
                    try:
                        text = chunk_data.decode('utf-8', errors='replace')
                        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
                        if len(text) >= 3 and printable > len(text) * 0.5:
                            results.append(text.strip())
                    except Exception:
                        pass

                if chunk_type == b'IEND':
                    break

    except Exception:
        pass

    return results


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def scan_image(image_path: str, flag_format: str = "") -> dict:
    """Run all extraction methods on a single image and return results."""
    methods = {
        "lsb_extract": _lsb_extract,
        "exif_extract": _exif_extract,
        "strings_search": _strings_from_image,
        "binwalk_extract": _binwalk_extract,
        "appended_data": _check_appended_data,
        "pixel_channel_lsb": _pixel_channel_extract,
        "zsteg": _zsteg_extract,
        "steghide": _steghide_extract,
        "multi_bitplane": _multi_bitplane_extract,
        "png_chunks": _png_chunk_extract,
    }

    report = {}
    all_flags = []

    for method_name, method_func in methods.items():
        try:
            raw_results = method_func(image_path)
        except Exception as exc:
            report[method_name] = {"status": "error", "error": str(exc)}
            continue

        flags_found = []
        for text in raw_results:
            flags_found.extend(_find_flags(text, flag_format))

        report[method_name] = {
            "status": "ok",
            "raw_count": len(raw_results),
            "flags": flags_found,
        }
        all_flags.extend(flags_found)

    return {"report": report, "flags": all_flags}


def main():
    parser = argparse.ArgumentParser(
        description="Kraken Steganography Extractor",
    )
    parser.add_argument("challenge_dir", help="Path to challenge directory")
    parser.add_argument(
        "--flag-format", default="", help="Regex pattern for flag format",
    )
    args = parser.parse_args()

    challenge_dir = args.challenge_dir
    flag_format = args.flag_format

    if not os.path.isdir(challenge_dir):
        print(f"[-] Not a directory: {challenge_dir}", file=sys.stderr)
        sys.exit(1)

    # Collect image files
    image_files = []
    audio_files = []
    for name in os.listdir(challenge_dir):
        ext = os.path.splitext(name)[1].lower()
        if ext in IMAGE_EXTENSIONS:
            image_files.append(os.path.join(challenge_dir, name))
        elif ext in AUDIO_EXTENSIONS:
            audio_files.append(os.path.join(challenge_dir, name))

    if not image_files and not audio_files:
        print("[-] No image or audio files found in challenge directory",
              file=sys.stderr)
        sys.exit(1)

    total_files = len(image_files) + len(audio_files)
    print(f"[*] Found {len(image_files)} image(s) and {len(audio_files)} "
          f"audio file(s) to analyze")

    all_flags = []

    for image_path in sorted(image_files):
        print(f"\n[*] Analyzing: {os.path.basename(image_path)}")
        result = scan_image(image_path, flag_format)

        # Print per-method summary
        for method_name, info in result["report"].items():
            status = info.get("status", "unknown")
            if status == "error":
                print(f"  [{method_name}] ERROR: {info.get('error', '?')}")
            else:
                raw_count = info.get("raw_count", 0)
                flags = info.get("flags", [])
                if flags:
                    print(f"  [{method_name}] {raw_count} result(s), "
                          f"{len(flags)} flag(s): {flags}")
                elif raw_count > 0:
                    print(f"  [{method_name}] {raw_count} result(s), no flags")
                else:
                    print(f"  [{method_name}] nothing found")

        all_flags.extend(result["flags"])

    # Process audio files
    for audio_path in sorted(audio_files):
        print(f"\n[*] Analyzing audio: {os.path.basename(audio_path)}")
        try:
            raw_results = _extract_audio_steg(audio_path)
        except Exception as exc:
            print(f"  [audio_steg] ERROR: {exc}")
            raw_results = []

        audio_flags = []
        for text in raw_results:
            audio_flags.extend(_find_flags(text, flag_format))

        if audio_flags:
            print(f"  [audio_steg] {len(raw_results)} result(s), "
                  f"{len(audio_flags)} flag(s): {audio_flags}")
        elif raw_results:
            print(f"  [audio_steg] {len(raw_results)} result(s), no flags")
        else:
            print(f"  [audio_steg] nothing found")

        all_flags.extend(audio_flags)

    # Deduplicate flags
    seen = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    print(f"\n[*] Summary: {len(unique_flags)} unique flag(s) found "
          f"across {total_files} file(s)")

    if unique_flags:
        for flag in unique_flags:
            print(f"  [+] {flag}")
        # Pick the longest match as the best flag
        best_flag = max(unique_flags, key=len)
        print(f"\nEXTRACTED FLAG: {best_flag}")
    else:
        print("\n[-] No flags extracted", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
