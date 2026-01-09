import asyncio
import struct
import logging
from typing import Optional, List
from plum_protocol import BoilerFrame, START_BYTE, STOP_BYTE, compute_crc16

logger = logging.getLogger(__name__)

class AsyncPlumTransport:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._buffer = bytearray()

    async def connect(self):
        logger.debug(f"Connecting to {self.host}:{self.port}")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()

    async def send_frame(self, frame: BoilerFrame):
        if not self.writer:
            raise ConnectionError("Not connected")

        packet = frame.to_bytes()
        # Flush input buffer before sending (Strategy from working script)
        self._buffer.clear()
        # Note: real socket flush is hard in asyncio without reading,
        # but clearing our parser buffer helps.

        self.writer.write(packet)
        await self.writer.drain()

    async def read_frame(self, timeout: float = 2.0) -> Optional[BoilerFrame]:
        """Lit le flux jusqu'à obtenir une trame valide."""
        if not self.reader:
            raise ConnectionError("Not connected")

        start_time = asyncio.get_running_loop().time()

        while (asyncio.get_running_loop().time() - start_time) < timeout:
            try:
                # Lecture par petits blocs
                chunk = await asyncio.wait_for(self.reader.read(1024), timeout=0.5)
                if not chunk:
                    return None
                self._buffer.extend(chunk)

                # Parsing
                while True:
                    try:
                        start_idx = self._buffer.index(START_BYTE)
                    except ValueError:
                        self._buffer.clear()
                        break # Pas de start byte, on attend plus de data

                    # On aligne le buffer
                    if start_idx > 0:
                        del self._buffer[:start_idx]

                    # Header minimum : 68 L L
                    if len(self._buffer) < 3:
                        break

                    l_val = struct.unpack("<H", self._buffer[1:3])[0]
                    total_len = l_val + 6 # 68 + L(2) + Content(L) + CRC(2) + 16

                    if len(self._buffer) < total_len:
                        break # Trame incomplète, on attend

                    # Extraction
                    frame_bytes = self._buffer[:total_len]

                    # Validation CRC
                    # Body pour CRC = L(2) + Content(L) => indices 1 à 1+2+L
                    body_end = 1 + 2 + l_val
                    body = frame_bytes[1:body_end]

                    received_crc = struct.unpack(">H", frame_bytes[body_end:body_end+2])[0]

                    if compute_crc16(body) == received_crc and frame_bytes[-1] == STOP_BYTE:
                        # Trame Valide !
                        # On extrait le contenu interne: Dest, Src, Func, Data
                        # Body contient: L(2) Dest(2) Src(2) Func(1) Payload...
                        # On passe body[2:] à from_bytes car from_bytes attend Dest...
                        valid_frame = BoilerFrame.from_bytes(body[2:])

                        del self._buffer[:total_len] # Consomme
                        return valid_frame
                    else:
                        # CRC invalide, on jette le StartByte et on réessaie
                        del self._buffer[0]

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Transport error: {e}")
                return None

        return None
