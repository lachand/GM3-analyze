import struct
from dataclasses import dataclass
from typing import ClassVar, Any

# --- CONSTANTES ---
START_BYTE = 0x68
STOP_BYTE = 0x16

# Mapping des types selon Spec 1.4.2
DATA_TYPES = {
    0x01: ("SHORT INT", 1), 0x02: ("INT", 2), 0x03: ("LONG INT", 4),
    0x04: ("BYTE", 1), 0x05: ("WORD", 2), 0x06: ("DWORD", 4),
    0x07: ("SHORT REAL", 4), 0x09: ("LONG REAL", 8), 0x0A: ("BOOLEAN", 1),
    0x0C: ("STRING", 0)
}

def compute_crc16(data: bytes) -> int:
    """CRC-16/CCITT (Poly 0x1021)"""
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
    Classe générique représentant un paramètre de la chaudière.
    Contient toutes les métadonnées pour l'affichage et l'interaction.
    """
    index: int
    name: str
    unit: str
    exponent: int
    info_byte: int
    value: Any = None  # Pour stocker la valeur courante plus tard

    @property
    def is_modifiable(self) -> bool:
        """Bit 5: Option to modify parameter"""
        return bool((self.info_byte >> 5) & 1)

    @property
    def is_readable(self) -> bool:
        """Bit 4: Option to read parameter"""
        return bool((self.info_byte >> 4) & 1)

    @property
    def data_type_code(self) -> int:
        """Bits 0-3"""
        return self.info_byte & 0x0F

    @property
    def type_name(self) -> str:
        return DATA_TYPES.get(self.data_type_code, ("UNK", 0))[0]

    def format_value(self, raw_value) -> float | int | str:
        """Applique l'exposant si nécessaire."""
        if isinstance(raw_value, (int, float)) and self.exponent != 0:
            # Code U2 pour l'exposant (gestion des négatifs)
            exp = self.exponent
            return raw_value * (10 ** exp)
        return raw_value

    def __str__(self):
        flags = ""
        if self.is_modifiable: flags += "W" # Write
        if self.is_readable: flags += "R"   # Read

        unit_str = f"[{self.unit}]" if self.unit else ""
        return f"ID {self.index:<4} | {flags:<2} | {self.type_name:<10} | {self.name} {unit_str}"

@dataclass
class BoilerFrame:
    """Représentation d'une trame réseau."""
    dest: int
    src: int
    func: int
    data: bytes

    def to_bytes(self) -> bytes:
        # L = Dest(2) + Src(2) + Func(1) + Data(n)
        l_val = 2 + 2 + 1 + len(self.data)

        # Header (Little Endian)
        header = struct.pack("<HHHB", l_val, self.dest, self.src, self.func)
        body = header + self.data

        # CRC (Big Endian >H sur le réseau !)
        crc = compute_crc16(body)

        return struct.pack("B", START_BYTE) + body + struct.pack(">H", crc) + struct.pack("B", STOP_BYTE)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BoilerFrame':
        # data doit être le body (sans start/stop/crc/len)
        # Structure Body reçue: Dest(2) Src(2) Func(1) Payload(n)
        dest = struct.unpack("<H", data[0:2])[0]
        src = struct.unpack("<H", data[2:4])[0]
        func = data[4]
        payload = data[5:]
        return cls(dest, src, func, payload)
