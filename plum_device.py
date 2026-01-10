import asyncio
import json
import struct
import logging
import socket
import time
from typing import Any, Dict, Optional

# Logger Configuration
logger = logging.getLogger("PlumDevice")
logger.addHandler(logging.NullHandler())

# Constants
DEST_ID = 1
SOURCE_ID = 100
CMD_READ_VAL = 0x43
CMD_WRITE_FORCE = 0x29

class PlumDevice:
    """
    @class PlumDevice
    @brief Main interface to communicate with the Plum boiler.
    @details Manages socket connection, value encoding/decoding, and retry logic.
    Uses a hybrid approach: public methods are `async`, but delegate blocking
    network operations to synchronous methods via `asyncio.to_thread`.
    """
    def __init__(self, ip: str, port: int = 8899, map_file: str = "device_map.json"):
        """
        @brief Constructor.
        @param ip IP address of the boiler or ecoNET module.
        @param port TCP port (default 8899).
        @param map_file Path to the JSON parameter mapping file.
        """
        self.ip = ip
        self.port = port
        self.map_file = map_file
        self.params_map: Dict[str, Any] = {}
        self.session_id = 10

    def load_map(self):
        """
        @brief Loads parameter definitions from the JSON file.
        @throws FileNotFoundError If the file does not exist.
        """
        try:
            with open(self.map_file, 'r') as f:
                self.params_map = json.load(f)
            logger.info(f"Mapping loaded: {len(self.params_map)} parameters.")
        except FileNotFoundError:
            logger.error(f"Unable to find {self.map_file}.")
            raise

    async def close(self):
        """
        @brief Closes resources.
        @details No action needed in ephemeral synchronous mode (socket closes per call).
        """
        pass

    # --- UTILITY METHODS ---
    def _crc16(self, data: bytes) -> int:
        """
        @brief Internal CRC16 calculation.
        @param data Binary data.
        @return int Checksum.
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

    def _encode(self, value: Any, param_def: dict) -> bytes:
        """
        @brief Encodes a Python value into bytes based on parameter definition.
        @param value The value to write (int, float, str).
        @param param_def Dictionary describing the parameter (type, exponent).
        @return bytes or None on error.
        """
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
        """
        @brief Decodes a binary response into a Python value.
        @param data Received bytes.
        @param param_def Parameter definition.
        @return Any Typed value (float, int, str) or None.
        """
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

    # --- PUBLIC ASYNC METHODS (WRAPPERS) ---

    async def get_value(self, slug: str, retries: int = 5) -> Any:
        """
        @brief Reads a parameter with robust error handling (Async).
        @details Wraps the synchronous `_sync_get_value` call in a thread.
        
        @param slug Textual identifier of the parameter (e.g., "temp_boiler").
        @param retries Max attempts before failure (default 5).
        @return Any The read value or None if failed.
        """
        param = self.params_map.get(slug)
        if not param: return None
        pid = param['id']

        for attempt in range(1, retries + 1):
            val = await asyncio.to_thread(self._sync_get_value, pid, param)

            if val is not None:
                if attempt > 1:
                    logger.info(f"Finded'{slug}' with {attempt} tries.")
                return val

            if attempt < retries:
                wait_time = 0.1 * attempt # Backoff progressif : 0.5s, 1.0s, 1.5s...
                logger.warning(f"'{slug}' Timeout (try {attempt}/{retries}). Retry in {wait_time}s...")
                await asyncio.sleep(wait_time)

        logger.error(f"ABORTED '{slug}' after {retries} tries.")
        return None

    async def set_value(self, slug: str, value: Any, password: str = "", user: str = "USER-000") -> bool:
        """
        @brief Writes a value (Async).
        
        @param slug Parameter identifier.
        @param value New value to write.
        @param password Installer/Service password (often "4095").
        @param user User identifier (default "USER-000").
        @return bool True on success, False otherwise.
        """
        param = self.params_map.get(slug)
        if not param: return False
        pid = param['id']
        encoded = self._encode(value, param)
        if not encoded: return False

        user_bytes = (user.encode('utf-8') + b'\x00') if user else b'\x00'
        pass_bytes = (password.encode('utf-8') + b'\x00') if password else b'\x00'
        full_payload = user_bytes + pass_bytes + b'\x01' + struct.pack("<H", pid) + encoded

        for attempt in range(1, 4):
            success = await asyncio.to_thread(self._sync_set_value, pid, full_payload)
            if success:
                logger.info(f"Writing '{slug}' OK.")
                return True

            logger.warning(f"Error writing '{slug}' (Try {attempt}/3). Retry...")
            await asyncio.sleep(1.0)

        return False

    # --- SYNCHRONOUS ENGINE (WORKER) ---

    def _sync_get_value(self, pid: int, param: dict) -> Any:
        """
        @brief Blocking implementation of read operation (Executed in a thread).
        @details Manages SessionID and frame construction.
        @param pid Numeric ID of the parameter.
        @param param Full definition for decoding.
        @return Any Decoded value or None.
        """
        # Change session ID for each physical attempt
        self.session_id = (self.session_id + 1) % 65000

        payload = struct.pack("<HB BH", self.session_id, 1, 1, pid)
        frame = self._build_frame(CMD_READ_VAL, payload)

        resp = self._socket_transaction(frame, CMD_READ_VAL)

        if resp and len(resp) > 2:
            rec_sess = struct.unpack("<H", resp[0:2])[0]
            if rec_sess == self.session_id or rec_sess == 0:
                return self._decode(resp[7:], param)
        return None

    def _sync_set_value(self, pid: int, payload: bytes) -> bool:
        """
        @brief Blocking implementation of write operation.
        """
        self.session_id = (self.session_id + 1) % 65000
        frame = self._build_frame(CMD_WRITE_FORCE, payload)
        resp = self._socket_transaction(frame, CMD_WRITE_FORCE)
        return resp is not None

    def _build_frame(self, cmd, payload):
        """
        @brief Builds a raw frame with Header and CRC.
        """
        l_val = 2 + 2 + 1 + len(payload)
        header = struct.pack("<HHHB", l_val, DEST_ID, SOURCE_ID, cmd)
        body = header + payload
        chk = self._crc16(body)
        return b'\x68' + body + struct.pack(">H", chk) + b'\x16'

    def _socket_transaction(self, frame: bytes, expected_cmd: int) -> Optional[bytes]:
        """
        @brief Handles low-level TCP transaction: Connect -> Send -> Receive -> Close.
        @details Uses a strict 2.0s timeout to prevent infinite blocking.
        
        @param frame Binary frame to send.
        @param expected_cmd Command expected in response (to filter stream).
        @return bytes Response payload or None if timeout/error.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)

            sock.connect((self.ip, self.port))
            sock.send(frame)

            buffer = bytearray()
            start_time = time.time()

            while time.time() - start_time < 2.0:
                try:
                    chunk = sock.recv(2048)
                    if not chunk: break
                    buffer.extend(chunk)

                    if b'\x68' in buffer:
                        idx = buffer.find(b'\x68')
                        if idx != -1 and len(buffer) > idx + 8:
                            cmd_rec = buffer[idx+7]
                            if cmd_rec == (expected_cmd | 0x80):
                                return buffer[idx+8 : -3]

                except socket.timeout:
                    break

            return None

        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except: pass
