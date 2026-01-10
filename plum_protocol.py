import struct
from dataclasses import dataclass
from typing import ClassVar, Any

## @package plum_protocol
#  @brief Data structures and low-level protocol definitions.
#  @details Contains constants, CRC computation logic, and dataclasses
#  representing boiler parameters and network frames.

# --- CONSTANTS ---
## Start byte of a frame
START_BYTE = 0x68
## Stop byte of a frame
STOP_BYTE = 0x16

# Data Types Mapping (Spec 1.4.2)
## Dictionary mapping binary type codes to human-readable names and sizes.
DATA_TYPES = {
    0x01: ("SHORT INT", 1), 0x02: ("INT", 2), 0x03: ("LONG INT", 4),
    0x04: ("BYTE", 1), 0x05: ("WORD", 2), 0x06: ("DWORD", 4),
    0x07: ("SHORT REAL", 4), 0x09: ("LONG REAL", 8), 0x0A: ("BOOLEAN", 1),
    0x0C: ("STRING", 0)
}

def compute_crc16(data: bytes) -> int:
    """
    @brief Computes the CRC-16 (Cyclic Redundancy Check).
    @details Uses the 0x1021 polynomial (CRC-CCITT).
    
    @param data The binary data (bytes) to checksum.
    @return int The calculated CRC as an unsigned 16-bit integer.
    """
    crc = 0x0000
    poly = 0x1021
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000: crc = (crc << 1) ^ poly
            else: crc <<= 1
            crc &= 0xFFFF
    return crc

@dataclass
class BoilerParameter:
    """
    @class BoilerParameter
    @brief Representation of a boiler parameter.
    @details Stores metadata extracted during the scan (type, unit, exponent)
    and handles raw value formatting.
    """
    index: int ##< Unique numeric ID of the parameter.
    name: str ##< Human-readable name.
    unit: str ##< Physical unit (e.g., "°C", "%", "kg").
    exponent: int ##< Exponent for decimal conversion
    info_byte: int ##< Byte containing permission flags and type code.
    value: Any = None  ##< Current value of the parameter (optional).

    @property
    def is_modifiable(self) -> bool:
        """
        @brief Checks if the parameter is writable.
        @return bool True if bit 5 of the info byte is set.
        """
        return bool((self.info_byte >> 5) & 1)

    @property
    def is_readable(self) -> bool:
        """
        @brief Checks if the parameter is readable.
        @return bool True if bit 4 of the info byte is set.
        """
        return bool((self.info_byte >> 4) & 1)

    @property
    def data_type_code(self) -> int:
        """
        @brief Extracts the type code from the lower bits.
        @return int Type code (Bits 0-3).
        """
        return self.info_byte & 0x0F

    @property
    def type_name(self) -> str:
        """
        @brief Gets the human-readable data type name.
        @return str The type name (e.g., "FLOAT", "BYTE") or "UNK".
        """
        return DATA_TYPES.get(self.data_type_code, ("UNK", 0))[0]

    def format_value(self, raw_value) -> float | int | str:
        """"
        @brief Applies the exponent to the raw value if necessary.
        
        @param raw_value The raw value received from the network (often int).
        @return The formatted value (often float) or raw value if no exponent.
        """
        if isinstance(raw_value, (int, float)) and self.exponent != 0:
            # Code U2 for exponent (handles negatives)
            exp = self.exponent
            return raw_value * (10 ** exp)
        return raw_value

    def __str__(self):
        """
        @brief String representation for debugging.
        """
        flags = ""
        if self.is_modifiable: flags += "W" # Write
        if self.is_readable: flags += "R"   # Read

        unit_str = f"[{self.unit}]" if self.unit else ""
        return f"ID {self.index:<4} | {flags:<2} | {self.type_name:<10} | {self.name} {unit_str}"

@dataclass
class BoilerFrame:
    """
    @class BoilerFrame
    @brief Representation of a complete network frame.
    @details Encapsulates destination, source, function code, and payload.
    Handles serialization (to_bytes) and deserialization (from_bytes).
    """
    dest: int ##< Destination address (e.g., 1 for boiler).
    src: int ##< Source address (e.g., 100 for touchscreen).
    func: int ##< Function code (Command).
    data: bytes ##< Payload data.

    def to_bytes(self) -> bytes:
        """
        @brief Converts the object into a byte sequence ready for network transmission.
        @details Structure: [Start] [Len] [Dest] [Src] [Func] [Data] [CRC] [Stop].
        
        @return bytes The complete binary frame.
        """
        # L = Dest(2) + Src(2) + Func(1) + Data(n)
        l_val = 2 + 2 + 1 + len(self.data)

        # Header (Little Endian)
        header = struct.pack("<HHHB", l_val, self.dest, self.src, self.func)
        body = header + self.data

        # CRC (Big Endian >H on network !)
        crc = compute_crc16(body)

        return struct.pack("B", START_BYTE) + body + struct.pack(">H", crc) + struct.pack("B", STOP_BYTE)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BoilerFrame':
        """
        @brief Creates a BoilerFrame instance from the frame body.
        @details Warning: `data` must contain only the body (no start/stop/crc/len).
        
        @param data bytes The frame body (Dest + Src + Func + Payload).
        @return BoilerFrame A new instance.
        """
        # Body structure received: Dest(2) Src(2) Func(1) Payload(n)
        dest = struct.unpack("<H", data[0:2])[0]
        src = struct.unpack("<H", data[2:4])[0]
        func = data[4]
        payload = data[5:]
        return cls(dest, src, func, payload)
