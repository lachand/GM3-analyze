import asyncio
import json
import struct
import logging
import socket
import time
from typing import Any, Dict, Optional

# Configuration Logger
logger = logging.getLogger("PlumDevice")
logger.addHandler(logging.NullHandler())

# Constantes
DEST_ID = 1
SOURCE_ID = 100
CMD_READ_VAL = 0x43
CMD_WRITE_FORCE = 0x29

class PlumDevice:
    def __init__(self, ip: str, port: int = 8899, map_file: str = "device_map.json"):
        self.ip = ip
        self.port = port
        self.map_file = map_file
        self.params_map: Dict[str, Any] = {}
        self.session_id = 10

    def load_map(self):
        try:
            with open(self.map_file, 'r') as f:
                self.params_map = json.load(f)
            logger.info(f"Mapping chargé: {len(self.params_map)} paramètres.")
        except FileNotFoundError:
            logger.error(f"Fichier {self.map_file} introuvable.")
            raise

    async def close(self):
        """Rien à faire en mode synchrone, le socket est fermé à chaque appel."""
        pass

    # --- MÉTHODES UTILITAIRES ---
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

    def _encode(self, value: Any, param_def: dict) -> bytes:
        ptype = param_def['type']
        exp = param_def['exponent']
        if isinstance(value, (int, float)) and exp != 0:
            value = int(round(value / (10 ** exp)))
        try:
            if ptype == "STRING": return str(value).encode('utf-8') + b'\x00'
            elif ptype == "FLOAT": return struct.pack("<f", float(value))
            elif ptype in ["BYTE", "SHORT_INT", "BOOL"]: return struct.pack("B", int(value))
            elif ptype in ["INT", "WORD"]: return struct.pack("<h", int(value))
            elif ptype in ["DWORD", "LONG_INT"]: return struct.pack("<i", int(value))
            else: return None
        except: return None

    def _decode(self, data: bytes, param_def: dict) -> Any:
        ptype = param_def['type']
        exp = param_def['exponent']
        try:
            val = None
            if ptype == "STRING":
                if b'\x00' in data: val = data[:data.index(b'\x00')].decode('utf-8', 'ignore')
                else: val = data.decode('utf-8', 'ignore')
            elif ptype == "FLOAT" and len(data) >= 4:
                val = struct.unpack("<f", data[:4])[0]
                val = round(val, 2)
            elif ptype in ["BYTE", "SHORT_INT", "BOOL"] and len(data) >= 1:
                val = data[0]
            elif ptype in ["INT", "WORD"] and len(data) >= 2:
                val = struct.unpack("<h", data[:2])[0]
            elif ptype in ["DWORD", "LONG_INT"] and len(data) >= 4:
                val = struct.unpack("<i", data[:4])[0]

            if val is not None and isinstance(val, (int, float)) and exp != 0:
                val = val * (10 ** exp)
                val = round(val, 2)
            return val
        except: return None

    # --- MÉTHODES PUBLIQUES ASYNCHRONES (WRAPPER) ---

    async def get_value(self, slug: str, retries: int = 5) -> Any:
        """Lecture avec boucle de tentatives robuste."""
        param = self.params_map.get(slug)
        if not param: return None
        pid = param['id']

        # logger.info(f"Lecture '{slug}' (ID {pid})...")

        for attempt in range(1, retries + 1):
            # On lance le moteur synchrone dans un thread pour ne pas bloquer HA
            val = await asyncio.to_thread(self._sync_get_value, pid, param)

            if val is not None:
                # Succès !
                if attempt > 1:
                    logger.info(f"✅ Récupéré '{slug}' au bout de {attempt} essais.")
                return val

            # Gestion de l'échec
            if attempt < retries:
                wait_time = 0.1 * attempt # Backoff progressif : 0.5s, 1.0s, 1.5s...
                logger.warning(f"⚠️ '{slug}' Timeout (Essai {attempt}/{retries}). Retry dans {wait_time}s...")
                await asyncio.sleep(wait_time)

        logger.error(f"❌ ABANDON '{slug}' après {retries} tentatives.")
        return None

    async def set_value(self, slug: str, value: Any, password: str = "", user: str = "USER-000") -> bool:
        """Écriture avec tentatives multiples."""
        param = self.params_map.get(slug)
        if not param: return False
        pid = param['id']
        encoded = self._encode(value, param)
        if not encoded: return False

        user_bytes = (user.encode('utf-8') + b'\x00') if user else b'\x00'
        pass_bytes = (password.encode('utf-8') + b'\x00') if password else b'\x00'
        full_payload = user_bytes + pass_bytes + b'\x01' + struct.pack("<H", pid) + encoded

        # 3 Essais pour l'écriture
        for attempt in range(1, 4):
            success = await asyncio.to_thread(self._sync_set_value, pid, full_payload)
            if success:
                logger.info(f"✅ Écriture '{slug}' OK.")
                return True

            logger.warning(f"⚠️ Echec écriture '{slug}' (Essai {attempt}/3). Retry...")
            await asyncio.sleep(1.0)

        return False

    # --- MOTEUR SYNCHRONE (WORKER) ---

    def _sync_get_value(self, pid: int, param: dict) -> Any:
        """Exécuté dans un thread : Logique bloquante pure."""
        # On change de session ID à chaque tentative physique
        self.session_id = (self.session_id + 1) % 65000

        payload = struct.pack("<HB BH", self.session_id, 1, 1, pid)
        frame = self._build_frame(CMD_READ_VAL, payload)

        # Transaction réseau
        resp = self._socket_transaction(frame, CMD_READ_VAL)

        if resp and len(resp) > 2:
            rec_sess = struct.unpack("<H", resp[0:2])[0]
            # On valide la session (0 est souvent utilisé par la chaudière comme wildcard)
            if rec_sess == self.session_id or rec_sess == 0:
                return self._decode(resp[7:], param)
        return None

    def _sync_set_value(self, pid: int, payload: bytes) -> bool:
        self.session_id = (self.session_id + 1) % 65000
        frame = self._build_frame(CMD_WRITE_FORCE, payload)
        resp = self._socket_transaction(frame, CMD_WRITE_FORCE)
        return resp is not None

    def _build_frame(self, cmd, payload):
        l_val = 2 + 2 + 1 + len(payload)
        header = struct.pack("<HHHB", l_val, DEST_ID, SOURCE_ID, cmd)
        body = header + payload
        chk = self._crc16(body)
        return b'\x68' + body + struct.pack(">H", chk) + b'\x16'

    def _socket_transaction(self, frame: bytes, expected_cmd: int) -> Optional[bytes]:
        """
        Ouvre/Parle/Ecoute/Ferme.
        Timeout strict de 2.0s.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Timeout vital : C'est lui qui empêche le blocage infini
            sock.settimeout(2.0)

            sock.connect((self.ip, self.port))
            sock.send(frame)

            buffer = bytearray()
            start_time = time.time()

            # On lit par paquets tant qu'on a du temps
            while time.time() - start_time < 2.0:
                try:
                    chunk = sock.recv(2048)
                    if not chunk: break
                    buffer.extend(chunk)

                    # Parsing rapide dans le flux
                    if b'\x68' in buffer:
                        idx = buffer.find(b'\x68')
                        # Check header dispo
                        if idx != -1 and len(buffer) > idx + 8:
                            cmd_rec = buffer[idx+7]
                            # Check si c'est la réponse attendue (CMD | 0x80)
                            if cmd_rec == (expected_cmd | 0x80):
                                # On retourne le payload brut (sans header, sans CRC/End)
                                # idx + 8 (Header) ... Fin - 3 (CRC + 0x16)
                                return buffer[idx+8 : -3]

                except socket.timeout:
                    break # On arrête la boucle si recv timeout

            return None

        except Exception:
            # En cas d'erreur de socket (connexion refusée, route, etc)
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except: pass
