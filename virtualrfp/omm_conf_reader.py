"""
OMM configuration file reader.

Parses the pipe-delimited OMM configuration file format with MD5 checksum validation.
"""

import hashlib
from typing import Optional


# Hidden bytes appended to MD5 calculation
HIDDEN_MD5_DATA = bytes([
    0x16, 0xFF, 0x50, 0x01, 0x13, 0xC0, 0x73, 0x34, 0x93,
    0x37, 0x70, 0x14, 0xFF, 0x4C, 0x20, 0x2E, 0x0B, 0x28,
    0x21, 0x0C, 0xBC, 0xC2, 0x60, 0xC0, 0x7F, 0x21, 0x3B,
    0xD6, 0x15, 0x38, 0x83, 0x05, 0xA0, 0x00, 0xFF, 0x11, 0x97,
    0x57, 0x18, 0xC9, 0x27, 0x8F, 0xF8, 0xFF, 0xA5, 0x72,
    0x89, 0x29, 0x12, 0x16, 0xE9, 0x34, 0xFF, 0xCD, 0x8B,
    0xFF, 0xF4, 0xB6, 0x10, 0x9B, 0x00, 0x8C, 0x03, 0x96, 0x32,
    0x0D, 0x7F, 0x60, 0xFE, 0xFF, 0xDE, 0x72, 0x2E, 0x16,
    0xA6, 0xBF, 0xA0, 0x10, 0x83, 0xF0, 0xAC, 0x6A, 0x4B,
    0x0C, 0xFF, 0xFF, 0x5F, 0xFE, 0xCB, 0x07, 0xB9, 0x5F, 0x53,
    0x1D, 0x48, 0x3C,
])

BYTE_ORDER_MARK = bytes([0xEF, 0xBB, 0xBF])
LINE_BREAK = bytes([0x0D, 0x0A])  # \r\n


class OmmConfHeader:
    """Header for a section of the OMM config file."""

    def __init__(self, columns: list):
        self._columns = [c.rstrip() for c in columns]
        self._indexed = {}
        for i in range(1, len(self._columns)):
            name = self._columns[i]
            if name not in self._indexed:
                self._indexed[name] = i - 1

    def index_of(self, name: str) -> Optional[int]:
        return self._indexed.get(name)

    def name_of(self, index: int) -> str:
        return self._columns[index + 1]


class OmmConfEntry:
    """A single entry/row in a section of the OMM config."""

    def __init__(self, header: OmmConfHeader, values: list):
        self._header = header
        self._values = values

    @property
    def entry_type(self) -> str:
        return self._values[0]

    def get(self, field: str) -> Optional[str]:
        """Get a field value by column name."""
        idx = self._header.index_of(field)
        if idx is None:
            return None
        return self.get_by_index(idx)

    def get_by_index(self, i: int) -> str:
        """Get a field value by column index."""
        return self._values[i + 1].strip()

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.get_by_index(key)
        return self.get(key)


class OmmConfReader:
    """Reader for OMM configuration files."""

    def __init__(self, filename: str):
        self._filename = filename
        self._sections: dict[str, list[OmmConfEntry]] = {}
        self._parsed = False

    def parse(self) -> None:
        """Parse the configuration file with MD5 validation."""
        md5 = hashlib.md5()
        md5.update(BYTE_ORDER_MARK)

        header = None
        previous = None

        with open(self._filename, 'r', encoding='utf-8-sig') as f:
            lines = f.read().splitlines()

        for current in lines:
            if len(current) == 0:
                header = None
            elif current.lstrip('-') == '' or all(c == '-' for c in current):
                if previous is None:
                    raise ValueError("omm_conf cannot start with separator line ---")
                header = OmmConfHeader(previous.split('|'))
            elif header is not None:
                values = current.split('|')
                entry = OmmConfEntry(header, values)
                section_name = entry.entry_type
                if section_name not in self._sections:
                    self._sections[section_name] = []
                self._sections[section_name].append(entry)

            if previous is not None:
                md5.update(previous.encode('utf-8'))
                md5.update(LINE_BREAK)
            previous = current

        # Final block includes hidden data
        md5.update(HIDDEN_MD5_DATA)
        checksum = md5.hexdigest()
        if previous != checksum:
            raise ValueError(f"invalid checksum: expected {checksum}, got {previous}")

        self._parsed = True

    def get_section(self, section: str) -> list[OmmConfEntry]:
        """Get all entries for a section."""
        if not self._parsed:
            self.parse()
        return self._sections.get(section, [])

    def get_value(self, section: str, field: str, value: str) -> Optional[OmmConfEntry]:
        """Find an entry where the given field matches the given value."""
        entries = self.get_section(section)
        for entry in entries:
            current = entry.get(field)
            if current == value:
                return entry
            if current is None:
                break
        return None
