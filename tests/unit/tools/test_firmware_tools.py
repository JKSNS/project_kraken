"""Tests for kraken.tools.firmware -- architecture detection and credential scanning."""
import os
import struct
import tempfile

import pytest

from kraken.tools.firmware import detect_architecture, find_hardcoded_credentials


class TestDetectArchitecture:
    """Test binary format and architecture detection."""

    def _write_elf(self, arch_machine: int, bits: int = 64, endian: str = "little") -> str:
        """Create a minimal ELF header for testing."""
        fd, path = tempfile.mkstemp(suffix=".elf")
        ei_class = 2 if bits == 64 else 1
        ei_data = 1 if endian == "little" else 2
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = ei_class
        header[5] = ei_data
        if endian == "little":
            struct.pack_into("<H", header, 18, arch_machine)
        else:
            struct.pack_into(">H", header, 18, arch_machine)
        os.write(fd, bytes(header))
        os.close(fd)
        return path

    @pytest.mark.asyncio
    async def test_elf_x86_64(self):
        path = self._write_elf(62, bits=64)
        try:
            result = await detect_architecture(path)
            assert result.success
            assert result.data["architecture"] == "x86_64"
            assert result.data["bits"] == 64
            assert result.data["format"] == "ELF"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_elf_arm(self):
        path = self._write_elf(40, bits=32)
        try:
            result = await detect_architecture(path)
            assert result.success
            assert result.data["architecture"] == "ARM"
            assert result.data["bits"] == 32
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_elf_mips_big_endian(self):
        path = self._write_elf(8, bits=32, endian="big")
        try:
            result = await detect_architecture(path)
            assert result.success
            assert result.data["architecture"] == "MIPS"
            assert result.data["endianness"] == "big"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_pe_header(self):
        fd, path = tempfile.mkstemp(suffix=".exe")
        header = bytearray(256)
        header[0:2] = b"MZ"
        pe_offset = 128
        struct.pack_into("<I", header, 60, pe_offset)
        header[pe_offset:pe_offset+4] = b"PE\x00\x00"
        struct.pack_into("<H", header, pe_offset + 4, 0x8664)  # x86_64
        os.write(fd, bytes(header))
        os.close(fd)
        try:
            result = await detect_architecture(path)
            assert result.success
            assert result.data["format"] == "PE"
            assert result.data["architecture"] == "x86_64"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_unknown_format(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"not a binary format at all" + b"\x00" * 64)
        os.close(fd)
        try:
            result = await detect_architecture(path)
            assert result.success
            assert result.data["architecture"] == "unknown"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_nonexistent_file(self):
        result = await detect_architecture("/nonexistent/path/binary")
        assert not result.success


class TestFindHardcodedCredentials:
    """Test credential pattern scanning."""

    @pytest.mark.asyncio
    async def test_finds_password(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b'password = "s3cr3t123"\npasswd: "hunter2"')
        os.close(fd)
        try:
            result = await find_hardcoded_credentials(path)
            assert result.success
            assert result.data["count"] >= 1
            assert any(f["type"] == "hardcoded_password" for f in result.data["findings"])
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_finds_api_key(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b'api_key = "sk-1234567890abcdef1234567890abcdef"')
        os.close(fd)
        try:
            result = await find_hardcoded_credentials(path)
            assert result.success
            assert result.data["count"] >= 1
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_finds_private_key(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...')
        os.close(fd)
        try:
            result = await find_hardcoded_credentials(path)
            assert result.success
            assert any(f["type"] == "private_key" for f in result.data["findings"])
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_no_credentials(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"Hello, World! This is a normal binary.")
        os.close(fd)
        try:
            result = await find_hardcoded_credentials(path)
            assert result.success
            assert result.data["count"] == 0
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_nonexistent_file(self):
        result = await find_hardcoded_credentials("/nonexistent/path")
        assert not result.success
