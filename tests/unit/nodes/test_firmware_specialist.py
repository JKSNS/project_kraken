"""Tests for kraken.nodes.firmware_specialist -- firmware indicator analysis."""
import pytest

from kraken.nodes.firmware_specialist import _analyze_firmware_indicators


class TestAnalyzeFirmwareIndicators:
    """Test deterministic firmware indicator analysis (no LLM calls)."""

    def test_uboot_detected(self):
        strings = ["u-boot", "bootcmd=", "bootdelay"]
        result = _analyze_firmware_indicators({}, strings)
        assert result["is_firmware"] is True
        assert any("U-Boot" in h for h in result["firmware_hints"])

    def test_openwrt_detected(self):
        strings = ["openwrt", "busybox", "/etc/config"]
        result = _analyze_firmware_indicators({}, strings)
        assert result["is_firmware"] is True

    def test_embedded_os_linux(self):
        strings = ["linux version 4.19", "vmlinuz"]
        result = _analyze_firmware_indicators({}, strings)
        assert "Linux" in result["embedded_os"]

    def test_embedded_os_freertos(self):
        strings = ["freertos", "xTaskCreate"]
        result = _analyze_firmware_indicators({}, strings)
        assert "FreeRTOS" in result["embedded_os"]

    def test_embedded_os_vxworks(self):
        strings = ["vxworks", "taskSpawn"]
        result = _analyze_firmware_indicators({}, strings)
        assert "VxWorks RTOS" in result["embedded_os"]

    def test_hardware_refs(self):
        strings = ["uart_init", "spi_transfer", "i2c_read", "gpio_set"]
        result = _analyze_firmware_indicators({}, strings)
        assert len(result["hardware_refs"]) >= 3

    def test_boot_indicators(self):
        strings = ["bootloader", "kernel_addr=0x80000000", "dtb"]
        result = _analyze_firmware_indicators({}, strings)
        assert len(result["boot_indicators"]) > 0

    def test_filesystem_hints(self):
        strings = ["squashfs", "jffs2", "cramfs"]
        result = _analyze_firmware_indicators({}, strings)
        assert len(result["firmware_hints"]) >= 2

    def test_network_config(self):
        strings = ["192.168.1.1", "ifconfig", "iptables", "dhcp"]
        result = _analyze_firmware_indicators({}, strings)
        assert len(result["network_config"]) >= 2

    def test_arm_architecture(self):
        binary_info = {"architecture": "ARM"}
        result = _analyze_firmware_indicators(binary_info, [])
        assert result["is_firmware"] is True
        assert any("arm" in h.lower() for h in result["firmware_hints"])

    def test_mips_architecture(self):
        binary_info = {"architecture": "MIPS"}
        result = _analyze_firmware_indicators(binary_info, [])
        assert result["is_firmware"] is True

    def test_firmware_file_type(self):
        binary_info = {"file_type": "firmware image"}
        result = _analyze_firmware_indicators(binary_info, [])
        assert result["is_firmware"] is True

    def test_empty_inputs(self):
        result = _analyze_firmware_indicators({}, [])
        assert result["is_firmware"] is False
        assert result["firmware_hints"] == []
        assert result["embedded_os"] == []
        assert result["hardware_refs"] == []

    def test_non_firmware_binary(self):
        binary_info = {"architecture": "x86_64", "file_type": "ELF 64-bit LSB executable"}
        strings = ["Hello, World!", "main", "printf"]
        result = _analyze_firmware_indicators(binary_info, strings)
        assert result["is_firmware"] is False
