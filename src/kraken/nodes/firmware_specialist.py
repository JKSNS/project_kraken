"""Firmware specialist -- embedded system and firmware RE.

Handles firmware images, embedded binaries, IoT devices.
Deterministic firmware extraction + architecture detection
combined with mid-tier LLM for analysis strategy.
"""
from __future__ import annotations

import json

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig
from kraken.tools.firmware import (
    binwalk_scan,
    binwalk_extract,
    detect_architecture,
    find_hardcoded_credentials,
)
from kraken.logging.structured import get_logger

log = get_logger(__name__)


def _analyze_firmware_indicators(binary_info: dict, strings: list[str]) -> dict:
    """Deterministic firmware indicator analysis."""
    indicators: dict = {
        "is_firmware": False,
        "firmware_hints": [],
        "embedded_os": [],
        "boot_indicators": [],
        "filesystem_hints": [],
        "hardware_refs": [],
        "network_config": [],
    }

    all_strings = " ".join(str(s) for s in strings).lower()

    # Firmware format hints
    fw_hints = {
        "u-boot": "U-Boot bootloader",
        "uboot": "U-Boot bootloader",
        "openwrt": "OpenWrt Linux",
        "busybox": "BusyBox embedded Linux",
        "squashfs": "SquashFS filesystem",
        "jffs2": "JFFS2 filesystem",
        "cramfs": "CramFS filesystem",
        "yaffs": "YAFFS filesystem",
        "ubifs": "UBIFS filesystem",
        "romfs": "ROMFS filesystem",
    }
    for keyword, desc in fw_hints.items():
        if keyword in all_strings:
            indicators["firmware_hints"].append(desc)
            indicators["is_firmware"] = True

    # Embedded OS detection
    os_hints = {
        "linux version": "Linux",
        "vxworks": "VxWorks RTOS",
        "freertos": "FreeRTOS",
        "threadx": "ThreadX",
        "nucleus": "Nucleus RTOS",
        "ecos": "eCos",
        "qnx": "QNX",
        "zephyr": "Zephyr RTOS",
    }
    for keyword, os_name in os_hints.items():
        if keyword in all_strings:
            indicators["embedded_os"].append(os_name)
            indicators["is_firmware"] = True

    # Boot indicators
    boot_hints = ["bootloader", "boot_args", "bootcmd", "bootdelay",
                  "kernel_addr", "ramdisk", "dtb", "device tree"]
    for hint in boot_hints:
        if hint in all_strings:
            indicators["boot_indicators"].append(hint)

    # Hardware references
    hw_refs = {
        "uart": "UART serial",
        "spi": "SPI bus",
        "i2c": "I2C bus",
        "gpio": "GPIO pins",
        "jtag": "JTAG debug",
        "flash": "Flash memory",
        "nand": "NAND flash",
        "nor": "NOR flash",
        "ddr": "DDR memory",
        "pcie": "PCIe bus",
        "usb": "USB interface",
        "ethernet": "Ethernet",
        "wifi": "WiFi",
        "bluetooth": "Bluetooth",
    }
    for keyword, desc in hw_refs.items():
        if keyword in all_strings:
            indicators["hardware_refs"].append(desc)

    # Network configuration
    net_hints = ["ifconfig", "ip addr", "dhcp", "iptables", "192.168",
                 "10.0.", "172.16.", "netmask", "gateway", "dns"]
    for hint in net_hints:
        if hint in all_strings:
            indicators["network_config"].append(hint)

    # File type heuristic
    file_type = binary_info.get("file_type", "").lower()
    if any(x in file_type for x in ["firmware", "flash", "rom", "image"]):
        indicators["is_firmware"] = True

    # Architecture heuristic
    arch = binary_info.get("architecture", "").lower()
    if any(x in arch for x in ["arm", "mips", "risc-v", "powerpc", "xtensa"]):
        indicators["is_firmware"] = True
        indicators["firmware_hints"].append(f"Embedded architecture: {arch}")

    return indicators


async def firmware_specialist(state: KrakenState) -> dict:
    """Analyze firmware image and develop RE strategy."""
    binary_info = state.get("binary_info", {})
    strings = state.get("strings_of_interest", [])
    binary_path = state.get("challenge_path", "")
    description = state.get("challenge_description", "")

    log.info("firmware_specialist_start")

    # Deterministic firmware analysis
    fw_indicators = _analyze_firmware_indicators(binary_info, strings)

    # Run firmware tools
    scan_result = await binwalk_scan(binary_path)
    arch_result = await detect_architecture(binary_path)
    cred_result = await find_hardcoded_credentials(binary_path)

    # Build tool results summary
    scan_data = scan_result.data or {} if scan_result.success else {}
    arch_data = arch_result.data or {} if arch_result.success else {}
    cred_data = cred_result.data or {} if cred_result.success else {}

    # Extract firmware if binwalk found embedded files
    extracted_files = []
    if scan_data.get("count", 0) > 1:
        extract_result = await binwalk_extract(binary_path)
        if extract_result.success and extract_result.data:
            extracted_files = extract_result.data.get("files", [])[:20]

    prompt = f"""Analyze this firmware/embedded binary and develop a reverse engineering strategy.

## Binary Path: {binary_path}
## Description: {description}

## Architecture
{json.dumps(arch_data, indent=2)}

## Firmware Indicators
- Is firmware: {fw_indicators['is_firmware']}
- Firmware hints: {fw_indicators['firmware_hints']}
- Embedded OS: {fw_indicators['embedded_os']}
- Boot indicators: {fw_indicators['boot_indicators']}
- Hardware refs: {fw_indicators['hardware_refs']}

## Binwalk Signature Scan ({scan_data.get('count', 0)} entries)
{json.dumps(scan_data.get('entries', [])[:15], indent=2)}

## Extracted Files ({len(extracted_files)} files)
{json.dumps([{{'name': f['name'], 'size': f['size']}} for f in extracted_files[:10]], indent=2)}

## Hardcoded Credentials ({cred_data.get('count', 0)} found)
{json.dumps(cred_data.get('findings', [])[:10], indent=2)}

## Strings of Interest
{json.dumps(strings[:30], indent=2)}

Identify:
1. Firmware type and purpose
2. Key files to analyze (config files, binaries, scripts)
3. Attack surface (hardcoded creds, debug interfaces, crypto keys)
4. Reverse engineering approach
5. Potential vulnerabilities

Respond with JSON:
{{
    "firmware_type": "router|iot|industrial|camera|other",
    "purpose": "what the firmware does",
    "key_targets": ["files or components to focus on"],
    "attack_surface": ["vulnerability classes identified"],
    "re_approach": "step-by-step analysis strategy",
    "credentials_found": "summary of hardcoded credentials",
    "notes": "additional observations"
}}"""

    cfg = ModelConfig()
    content = await direct_generate(prompt, "mid", cfg)

    analysis = {}
    try:
        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0]
        analysis = json.loads(json_str)
    except (json.JSONDecodeError, IndexError):
        analysis = {"raw_analysis": content}

    analysis["fw_indicators"] = fw_indicators
    analysis["arch_info"] = arch_data
    analysis["scan_entries"] = scan_data.get("count", 0)
    analysis["credentials_count"] = cred_data.get("count", 0)

    log.info(
        "firmware_specialist_complete",
        is_firmware=fw_indicators["is_firmware"],
        architecture=arch_data.get("architecture", "unknown"),
        scan_entries=scan_data.get("count", 0),
        credentials=cred_data.get("count", 0),
        firmware_type=analysis.get("firmware_type", "unknown"),
    )

    # Build strategy summary
    parts = [f"Firmware: {analysis.get('firmware_type', 'unknown')}"]
    if arch_data.get("architecture", "unknown") != "unknown":
        parts.append(f"Arch: {arch_data['architecture']}")
    if fw_indicators["embedded_os"]:
        parts.append(f"OS: {', '.join(fw_indicators['embedded_os'][:2])}")
    if cred_data.get("count", 0) > 0:
        parts.append(f"Creds: {cred_data['count']} found")
    if analysis.get("re_approach"):
        parts.append(analysis["re_approach"][:80])
    strategy = " | ".join(parts)

    return {
        "strategy_hypothesis": strategy,
        "angr_results": {
            **(state.get("angr_results", {})),
            "firmware_analysis": analysis,
        },
        "recent_actions": [{
            "action": "firmware_specialist",
            "reasoning": f"Firmware analysis: {analysis.get('firmware_type', 'unknown')}",
            "result_summary": strategy,
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
