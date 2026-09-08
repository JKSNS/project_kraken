"""Lightweight ELF disassembler using pyelftools + capstone.

Fallback when Ghidra is unavailable. Extracts function disassembly
from ELF binaries using the symbol table and capstone disassembler.
"""
from __future__ import annotations

from kraken.tools.base import ToolResult
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def disassemble_elf(binary_path: str) -> ToolResult:
    """Disassemble an ELF binary into per-function assembly listings.

    Returns a ToolResult with data containing:
      - functions: dict mapping function_name -> disassembly string
      - sections: list of section info dicts
      - entry_point: hex string of entry point address
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    except ImportError as e:
        return ToolResult(
            tool="disasm", success=False,
            error=f"Missing dependency: {e}. Install pyelftools and capstone.",
        )

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)

            # Determine architecture
            arch = elf.header.e_machine
            bits = elf.elfclass
            entry = elf.header.e_entry

            if arch == "EM_X86_64" or bits == 64:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
            cs.detail = True

            # Collect sections
            sections_info = []
            text_section = None
            for section in elf.iter_sections():
                info = {
                    "name": section.name,
                    "type": section["sh_type"],
                    "addr": hex(section["sh_addr"]),
                    "size": section["sh_size"],
                }
                sections_info.append(info)
                if section.name == ".text":
                    text_section = section

            # Collect symbols (function boundaries)
            func_symbols = []
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_size"] > 0:
                        func_symbols.append({
                            "name": symbol.name,
                            "addr": symbol["st_value"],
                            "size": symbol["st_size"],
                        })

            # Sort by address
            func_symbols.sort(key=lambda s: s["addr"])

            # Disassemble each function
            functions = {}
            for sym in func_symbols:
                name = sym["name"] or f"sub_{sym['addr']:x}"
                addr = sym["addr"]
                size = sym["size"]

                # Find the section containing this function
                func_section = None
                for section in elf.iter_sections():
                    s_addr = section["sh_addr"]
                    s_size = section["sh_size"]
                    if s_addr <= addr < s_addr + s_size:
                        func_section = section
                        break

                if func_section is None:
                    continue

                # Read bytes
                offset_in_section = addr - func_section["sh_addr"]
                section_data = func_section.data()
                if offset_in_section + size > len(section_data):
                    size = len(section_data) - offset_in_section
                func_bytes = section_data[offset_in_section:offset_in_section + size]

                # Disassemble
                lines = []
                for insn in cs.disasm(func_bytes, addr):
                    lines.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")

                if lines:
                    functions[f"{name}@{addr:#x}"] = "\n".join(lines)

            # If no symbols, disassemble .text as a single block
            if not functions and text_section is not None:
                text_data = text_section.data()
                text_addr = text_section["sh_addr"]
                lines = []
                for insn in cs.disasm(text_data, text_addr):
                    lines.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
                if lines:
                    functions[f".text@{text_addr:#x}"] = "\n".join(lines)

            log.info(
                "disasm_complete",
                num_functions=len(functions),
                total_lines=sum(f.count("\n") + 1 for f in functions.values()),
            )

            return ToolResult(
                tool="disasm",
                success=True,
                data={
                    "functions": functions,
                    "sections": sections_info,
                    "entry_point": hex(entry),
                    "arch": str(arch),
                    "bits": bits,
                },
            )

    except Exception as e:
        log.warning("disasm_failed", error=str(e))
        return ToolResult(tool="disasm", success=False, error=str(e))
