"""Hex encoding/decoding and endianness utilities."""

import struct


def byte_to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return data.hex()


def hex_to_byte(hex_str: str) -> bytearray:
    """Convert hex string to byte array."""
    if len(hex_str) % 2 != 0:
        raise ValueError("uneven hex length")
    return bytearray(bytes.fromhex(hex_str))


def swap_endianness(data: bytearray) -> None:
    """Swap endianness of 32-bit words in place (big-endian -> little-endian)."""
    offset = 0
    while offset < len(data):
        value = struct.unpack_from('>I', data, offset)[0]
        struct.pack_into('<I', data, offset, value)
        offset += 4
