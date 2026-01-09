import socket
import struct
import time
import json
import re
from plum_const import CMD_SCAN, TYPE_MAP

IP = "192.168.1.38"
PORT = 8899
OUTPUT_FILE = "device_map.json"

# Filtres
ALWAYS_KEEP = ["uid", "wifi", "ip", "boiler", "pression", "lambda", "fan", "power", "work", "fuel", "feeder"]
DHW_KEYWORDS = ["dhw", "ecs", "cwu", "sanitary", "hot_water", "tank", "circulation"]

class AutoDiscovery:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.raw_defs = []

    def _crc16(self, data: bytes) -> int:
        crc = 0x0000
        poly = 0x1021
        for b in data:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000: crc = (crc << 1) ^ poly
                else: crc <<= 1
                crc &= 0xFFFF
        return crc

    def _slugify(self, text: str) -> str:
        text = text.lower()
        text = re.sub(r'\[.*?\]', '', text)
        text = re.sub(r'\s+', '_', text)
        text = re.sub(r'[^a-z0-9_]', '', text)
        return text.strip('_')

    def scan_definitions(self):
        print(f"1. SCAN DES DÉFINITIONS...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.ip, self.port))
            index = 0
            empty_streak = 0
            while index < 1500 and empty_streak < 15:
                payload = struct.pack("<BH", 10, index)
                l_val = 2 + 2 + 1 + len(payload)
                header = struct.pack("<HHHB", l_val, 1, 0, CMD_SCAN)
                body = header + payload
                chk = self._crc16(body)
                frame = b'\x68' + body + struct.pack(">H", chk) + b'\x16'

                try:
                    s.send(frame)
                    valid_batch = False
                    start_t = time.time()
                    buffer = bytearray()
                    while time.time() - start_t < 1.0:
                        try:
                            chunk = s.recv(2048)
                            if not chunk: break
                            buffer.extend(chunk)
                            if b'\x68' in buffer:
                                idx = buffer.index(b'\x68')
                                if idx > 0: del buffer[:idx]
                                if len(buffer) >= 3:
                                    l = struct.unpack("<H", buffer[1:3])[0]
                                    if len(buffer) >= l + 6:
                                        resp = buffer[:l+6]
                                        del buffer[:l+6]
                                        if resp[7] == 0x81:
                                            pl = resp[8:-3]
                                            if len(pl) > 3:
                                                valid_batch = True
                                                count = pl[0]
                                                curr_id = struct.unpack("<H", pl[1:3])[0]
                                                cursor = 3
                                                for _ in range(count):
                                                    if cursor >= len(pl): break
                                                    try:
                                                        end_n = pl.index(b'\x00', cursor)
                                                        name = pl[cursor:end_n].decode('utf-8','replace')
                                                        cursor = end_n + 1
                                                        end_u = pl.index(b'\x00', cursor)
                                                        unit = pl[cursor:end_u].decode('utf-8','replace')
                                                        cursor = end_u + 1
                                                        exp = struct.unpack("b", pl[cursor:cursor+1])[0]
                                                        info = pl[cursor+1]
                                                        t_code = info & 0x0F
                                                        cursor += 2
                                                        self.raw_defs.append({
                                                            "id": curr_id,
                                                            "name": name,
                                                            "slug": self._slugify(name),
                                                            "type": TYPE_MAP.get(t_code, "RAW"),
                                                            "unit": unit,
                                                            "exponent": exp
                                                        })
                                                        curr_id += 1
                                                    except: break
                                            break
                        except socket.timeout: pass
                except Exception: pass

                if valid_batch:
                    empty_streak = 0
                    index = self.raw_defs[-1]["id"] + 1
                else:
                    empty_streak += 1
                    index += 10
                    print(".", end="", flush=True)
        finally:
            s.close()
            print(f"\n   -> {len(self.raw_defs)} définitions trouvées.")

    def generate_json(self):
        print(f"2. GÉNÉRATION DU JSON...")
        final_map = {}
        for p in self.raw_defs:
            slug = p["slug"]
            keep = False
            if any(k in slug for k in ALWAYS_KEEP): keep = True
            elif any(k in slug for k in DHW_KEYWORDS): keep = True
            elif "thermostat" in slug and "temp" in slug: keep = True
            match_circuit = re.search(r'circuit(\d+)', slug)
            if match_circuit: keep = True

            if keep:
                final_map[slug] = {
                    "id": p["id"],
                    "type": p["type"],
                    "unit": p.get("unit", ""),
                    "exponent": p["exponent"],
                    "name_orig": p["name"]
                }
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(final_map, f, indent=4)
        print(f"✅ Fichier '{OUTPUT_FILE}' généré.")

if __name__ == "__main__":
    auto = AutoDiscovery(IP, PORT)
    auto.scan_definitions()
    auto.generate_json()
