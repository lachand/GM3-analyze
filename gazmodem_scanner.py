## @file gazmodem_scanner.py
#  @brief Advanced GUI Scanner for GazModem/PLUM Industrial Protocol.
#  @details This application allows reverse-engineering of heating systems using the GazModem protocol.
#           It features a passive sniffer, an active smart scanner, and data export.
#  @author Assistant (Generated via Gemini)
#  @version 0.4
#  @date 2025-12-18
#  @copyright MIT License

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import struct
import time
import threading
import csv
import queue
from typing import Dict, Tuple, Optional, List, Set, Any, Union

# --- GLOBAL CONFIGURATION ---

## @var DEFAULT_IP
#  @brief Default IP address of the EcoNet/PLUM converter.
DEFAULT_IP: str = "192.168.1.38"

## @var DEFAULT_PORT
#  @brief Default TCP port for the connection (Standard is 8899).
DEFAULT_PORT: int = 8899

## @var MY_SA
#  @brief Source Address used by the scanner.
#  @details 0 usually represents the Touch Panel (Master).
#           If scanning fails, try 100 (Thermostat) or 250 (Computer).
MY_SA: int = 0

## @var SNIFF_DURATION
#  @brief Duration of the passive sniffing phase in seconds.
SNIFF_DURATION: int = 30

## @var MAX_EMPTY_STREAK
#  @brief Threshold of consecutive empty parameters to trigger a skip.
#  @details If 100 consecutive parameters return no data, the scanner moves to the next device.
MAX_EMPTY_STREAK: int = 100

# --- PROTOCOL DEFINITIONS ---

## @var TYPE_DEFS
#  @brief Dictionary mapping Protocol Data Types to Python structures.
#  @details Structure: { ID: (Name, Size_Bytes, Struct_Format, Is_Float) }
TYPE_DEFS: Dict[int, Tuple[str, int, Optional[str], bool]] = {
    0:  ("None", 0, None, False),
    1:  ("SHORT INT", 1, "<b", False),
    2:  ("INT", 2, "<h", False),
    3:  ("LONG INT", 4, "<i", False),
    4:  ("BYTE", 1, "<B", False),
    5:  ("WORD", 2, "<H", False),
    6:  ("DWORD", 4, "<I", False),
    7:  ("SHORT REAL", 4, "<f", True),
    8:  ("None", 0, None, False),
    9:  ("LONG REAL", 8, "<d", True),
    10: ("BOOLEAN", 1, "<B", False),
    11: ("BCD", 1, "<B", False),
    12: ("STRING", 0, "s", False),
    13: ("INT 64", 8, "<q", False),
    14: ("UINT 64", 8, "<Q", False)
}

class GazModemBackend:
    """
    @brief Backend logic handler for network communications.
    @details This class runs in a separate thread to prevent UI freezing.
             It handles TCP connection, Packet Sniffing, CRC calculation, and Active Scanning.
    """

    START: int = 0x68 ##< Protocol Start Byte
    STOP: int = 0x16  ##< Protocol Stop Byte

    def __init__(self, ip: str, port: int, log_queue: queue.Queue, result_queue: queue.Queue):
        """
        @brief Initializes the Backend.
        @param ip Target IP Address.
        @param port Target TCP Port.
        @param log_queue Thread-safe queue for status messages.
        @param result_queue Thread-safe queue for scan results.
        """
        self.ip: str = ip
        self.port: int = int(port)
        self.log_queue: queue.Queue = log_queue
        self.result_queue: queue.Queue = result_queue
        self.sock: Optional[socket.socket] = None
        self.running: bool = False
        self.active_devices: Set[int] = set()

    def _log(self, msg: str, progress: Optional[float] = None) -> None:
        """
        @brief Sends a formatted log message to the UI.
        @param msg The text message to display.
        @param progress Optional float (0-100) to update the progress bar.
        """
        self.log_queue.put(("STATUS", msg, progress))

    def _crc(self, data: bytes) -> int:
        """
        @brief Calculates the CRC-16/XMODEM (Polynomial 0x1021).
        @param data The raw byte sequence to verify.
        @return The calculated 16-bit CRC integer.
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

    def connect(self) -> bool:
        """
        @brief Establishes the TCP connection to the converter.
        @return True if connection successful, False otherwise.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(1.0)
            self.sock.connect((self.ip, self.port))
            return True
        except Exception as e:
            self._log(f"Connection Error: {e}")
            return False

    def start_process(self) -> None:
        """
        @brief Main execution loop of the scanner thread.
        @details Steps:
                 1. Connect.
                 2. Passive Sniffing (30s).
                 3. Device Enumeration.
                 4. Active Scanning (Smart Scan).
                 5. Cleanup.
        """
        self.running = True
        if not self.connect():
            self.running = False
            return

        # --- PHASE 1: SNIFFING ---
        self._log(f"PHASE 1: Network Sniffing ({SNIFF_DURATION}s)...")
        start_time = time.time()
        buf = bytearray()

        while time.time() - start_time < SNIFF_DURATION and self.running:
            remaining = int(SNIFF_DURATION - (time.time() - start_time))
            # 50% of the progress bar is allocated to sniffing
            prog = ((SNIFF_DURATION - remaining) / SNIFF_DURATION) * 50
            self._log(f"Listening... {remaining}s remaining", prog)

            try:
                if self.sock:
                    chunk = self.sock.recv(4096)
                    if chunk:
                        buf.extend(chunk)
                        # Process buffer
                        while len(buf) > 8:
                            if buf[0] != self.START:
                                buf.pop(0); continue
                            try:
                                l_val = struct.unpack("<H", buf[1:3])[0]
                                tot = 1 + 2 + l_val + 3
                                if len(buf) < tot: break

                                dest = struct.unpack("<H", buf[3:5])[0]
                                src = struct.unpack("<H", buf[5:7])[0]

                                # Filter addresses
                                if src not in [65535, MY_SA]: self.active_devices.add(src)
                                if dest not in [65535, MY_SA]: self.active_devices.add(dest)

                                del buf[:tot]
                            except: buf.pop(0)
            except: pass

        if not self.running: return

        # Fallback mechanism
        if not self.active_devices:
            self.active_devices = {1, 100}
            self._log("No traffic detected. Forcing scan on IDs 1 and 100.")
        else:
            self._log(f"Devices detected: {list(self.active_devices)}")

        # --- PHASE 2: SCANNING ---
        devs = sorted(list(self.active_devices))
        total = len(devs)

        for i, dev in enumerate(devs):
            if not self.running: break
            base_prog = 50 + (i / total * 50)
            self._log(f"PHASE 2: Scanning Device {dev} ({i+1}/{total})", base_prog)

            self._scan_smart(dev, 0, 1000)

        self._log("SCAN COMPLETED!", 100)
        self.running = False
        if self.sock: self.sock.close()

    def _scan_smart(self, target: int, start: int, end: int) -> None:
        """
        @brief Scans a memory range on a specific device.
        @details Implements logic to skip large empty memory blocks to save time.
        @param target The device address to scan.
        @param start Start index.
        @param end End index.
        """
        empty_streak = 0

        for idx in range(start, end):
            if not self.running: break

            # Log every 10 items to avoid spamming the UI queue
            if idx % 10 == 0:
                self._log(f"Device {target} : Index {idx}...", None)

            if empty_streak >= MAX_EMPTY_STREAK:
                self._log(f"Device {target} : Empty zone detected. Skipping device.", None)
                break

            time.sleep(0.01) # Throttling

            if self.sock:
                # Flush buffer
                self.sock.settimeout(0.01)
                try:
                    while self.sock.recv(4096): pass
                except: pass

                # Build Request: [Start] [Len] [Dest] [Src] [Cmd=0x02] [Data] [CRC] [Stop]
                req = struct.pack("<BH", 1, idx)
                l = len(req) + 5
                h = struct.pack("<HHHB", l, target, MY_SA, 0x02) + req
                frame = struct.pack("B", self.START) + h + struct.pack(">H", self._crc(h)) + struct.pack("B", self.STOP)

                found = False
                try:
                    self.sock.send(frame)
                    self.sock.settimeout(0.2)
                    resp = self.sock.recv(1024)

                    # Parsing
                    if len(resp) > 8 and self.START in resp:
                        start_pos = resp.find(self.START)
                        # Ensure we have enough bytes for header
                        if start_pos >= 0 and len(resp) > start_pos + 8:
                            # Strict check: Function Code must be 0x82 (Read Response)
                            if resp[start_pos+7] == 0x82:
                                payload = resp[start_pos+8:-3]
                                res = self._decode(target, idx, payload)
                                if res:
                                    self.result_queue.put(res)
                                    found = True
                                    empty_streak = 0
                except: pass

                if not found:
                    empty_streak += 1

    def _decode(self, addr: int, idx: int, data: bytes) -> Optional[Dict[str, Any]]:
        """
        @brief Decodes a binary payload based on the protocol definition.
        @param addr Device address.
        @param idx Parameter index.
        @param data Raw binary payload from the response.
        @return Dictionary containing decoded fields (Name, Val, Exp, Unit, etc.) or None.
        """
        try:
            cursor = 3
            def read_str(buf: bytes, pos: int) -> Tuple[str, int]:
                end = buf.find(b'\x00', pos)
                if end == -1: return "", len(buf)
                s = buf[pos:end].decode('latin-1', 'ignore').strip()
                return s, end + 1

            name, cursor = read_str(data, cursor)
            unit, cursor = read_str(data, cursor)

            if not name or name == "?": return None
            if len(data) < cursor + 2: return None

            info_raw = data[cursor]
            exp_raw_byte = bytes([data[cursor+1]])
            cursor += 2

            type_id = info_raw & 0x0F
            rw_bit = bool(info_raw & 0x20)

            exponent = struct.unpack("<b", exp_raw_byte)[0]
            if abs(exponent) > 6: exponent = 0

            type_name, size, fmt, is_float = TYPE_DEFS.get(type_id, ("UNK", 0, None, False))

            val_str = "---"
            if size > 0 and len(data) >= cursor + size:
                raw_bytes = data[cursor : cursor + size]
                if fmt:
                    val = struct.unpack(fmt, raw_bytes)[0]

                    if is_float:
                        val_str = f"{val:.2f}"
                    elif type_id == 10:
                        val_str = "ON" if val else "OFF"
                    elif type_id == 12:
                        val_str = "TXT"
                    else:
                        if exponent != 0:
                            val_str = f"{val * (10 ** exponent):g}"
                        else:
                            val_str = f"{val}"

            return {
                "addr": addr, "idx": idx, "name": name,
                "val": val_str, "exp": exponent, "unit": unit,
                "type": type_name, "rw": "RW" if rw_bit else "RO"
            }
        except: return None

class AppGUI:
    """
    @brief Main Tkinter Window Class.
    @details Manages the UI components, Event Loop, and updates from the Backend thread.
    """
    def __init__(self, root: tk.Tk):
        """
        @brief Initializes the GUI.
        @param root The root Tkinter object.
        """
        self.root = root
        self.root.title("GazModem Scanner")
        self.root.geometry("1150x750")

        self.log_queue: queue.Queue = queue.Queue()
        self.result_queue: queue.Queue = queue.Queue()
        self.backend: Optional[GazModemBackend] = None
        self._setup_ui()
        self._check_queues()

    def _setup_ui(self) -> None:
        """
        @brief Configures all widgets, frames, and tables.
        """
        style = ttk.Style()
        style.configure("Bold.TLabel", font=("Arial", 10, "bold"))
        style.configure("Big.TButton", font=("Arial", 11))

        # --- TOP PANEL ---
        top = ttk.LabelFrame(self.root, text="Configuration", padding=10)
        top.pack(fill="x", padx=10, pady=5)

        ttk.Label(top, text="IP Address:").grid(row=0, column=0, padx=5)
        self.ip_ent = ttk.Entry(top, width=15)
        self.ip_ent.insert(0, DEFAULT_IP)
        self.ip_ent.grid(row=0, column=1, padx=5)

        ttk.Label(top, text="Port:").grid(row=0, column=2, padx=5)
        self.port_ent = ttk.Entry(top, width=6)
        self.port_ent.insert(0, str(DEFAULT_PORT))
        self.port_ent.grid(row=0, column=3, padx=5)

        self.btn_scan = ttk.Button(top, text="▶ START SCAN", style="Big.TButton", command=self.start_scan)
        self.btn_scan.grid(row=0, column=4, padx=20)

        self.btn_stop = ttk.Button(top, text="⏹ STOP", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=5, padx=5)

        self.btn_export = ttk.Button(top, text="💾 EXPORT CSV", command=self.export_csv)
        self.btn_export.grid(row=0, column=6, padx=20)

        # --- STATUS PANEL ---
        stat = ttk.Frame(self.root, padding=5)
        stat.pack(fill="x", padx=10)
        self.lbl_stat = ttk.Label(stat, text="Ready", style="Bold.TLabel")
        self.lbl_stat.pack(side="left", fill="x", expand=True)
        self.prog = ttk.Progressbar(stat, length=300, mode="determinate")
        self.prog.pack(side="right")

        # --- DATA TABLE ---
        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("addr", "idx", "name", "val", "exp", "unit", "type", "rw")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        col_conf = [("addr","Addr",50), ("idx","Idx",50), ("name","Name",240),
                    ("val","Value",90), ("exp","Exp",40), ("unit","Unit",60),
                    ("type","Type",90), ("rw","Access",50)]
        for c, t, w in col_conf:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="center" if c in ["addr","idx","exp","rw"] else "w")

        self.tree.tag_configure('highlight', background='#d4f8d4')

    def start_scan(self) -> None:
        """@brief Callback for the Start button."""
        ip = self.ip_ent.get()
        port = self.port_ent.get()
        for i in self.tree.get_children(): self.tree.delete(i)
        self.btn_scan.config(state="disabled"); self.btn_stop.config(state="normal")
        self.prog['value'] = 0
        self.backend = GazModemBackend(ip, int(port), self.log_queue, self.result_queue)
        t = threading.Thread(target=self.backend.start_process)
        t.daemon = True
        t.start()

    def stop_scan(self) -> None:
        """@brief Callback for the Stop button."""
        if self.backend: self.backend.running = False; self.lbl_stat.config(text="Stopping...")
        self.btn_scan.config(state="normal"); self.btn_stop.config(state="disabled")

    def export_csv(self) -> None:
        """@brief Callback for the Export button."""
        fn = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not fn: return
        try:
            with open(fn, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f, delimiter=';')
                w.writerow(["Address", "Index", "Name", "Value", "Exponent", "Unit", "Type", "Access"])
                for i in self.tree.get_children(): w.writerow(self.tree.item(i)['values'])
            messagebox.showinfo("Success", "CSV file saved successfully!")
        except Exception as e: messagebox.showerror("Error", str(e))

    def _check_queues(self) -> None:
        """@brief Periodically checks for updates from the backend thread."""
        try:
            while True:
                t, m, p = self.log_queue.get_nowait()
                if t == "STATUS":
                    self.lbl_stat.config(text=m)
                    if p is not None: self.prog['value'] = p
                    if m == "SCAN COMPLETED!": self.stop_scan()
        except queue.Empty: pass

        try:
            while True:
                r = self.result_queue.get_nowait()
                tag = "highlight" if ("15.7" in str(r['val']) or "21.2" in str(r['val'])) else ""
                self.tree.insert("", "end", values=(r['addr'], r['idx'], r['name'], r['val'], r['exp'], r['unit'], r['type'], r['rw']), tags=(tag,))
                self.tree.yview_moveto(1)
        except queue.Empty: pass
        self.root.after(100, self._check_queues)

if __name__ == "__main__":
    root = tk.Tk()
    AppGUI(root)
    root.mainloop()
