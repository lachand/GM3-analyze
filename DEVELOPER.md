# Developer Documentation

**Project:** GazModem Scanner
**Language:** Python 3.x (Standard Library + Tkinter)

---

## Software Architecture

The application is built upon a **Producer-Consumer** multithreaded pattern to decouple the Graphical User Interface (GUI) from blocking network I/O operations.

### Components Details

1.  **`AppGUI` (Frontend - Main Thread)**
    * **Role:** Manages the visual layout, user inputs, and displays the data table.
    * **Thread Safety:** Tkinter is not thread-safe. All updates coming from the backend must be retrieved via `_check_queues()` using `queue.get_nowait()`.
    * **Polling:** Checks for new data every 100ms using `root.after()`.

2.  **`GazModemBackend` (Backend - Worker Thread)**
    * **Role:** Handles the protocol logic, socket management, and binary parsing.
    * **Lifecycle:**
        1.  **Connect:** Opens a TCP socket to the EcoNet converter.
        2.  **Phase 1 (Sniffing):** Passively reads traffic to discover device addresses.
        3.  **Phase 2 (Scanning):** Iterates through discovered addresses and indexes (0-1000).
    * **Logic:** Implements the "Smart Skip" feature (`MAX_EMPTY_STREAK`) to ignore unused memory blocks and optimize scan time.

---

## Protocol Specifications (GazModem / PLUM)

The protocol relies on RS485 frames encapsulated in transparent TCP packets. The system usually acts as a Master-Slave bus.

### Frame Structure

**Endianness:** All multi-byte fields are **Little Endian** (denoted as `<` in Python `struct` format).

| Offset | Field | Size | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | **START** | 1B | Frame Start Delimiter (`0x68`) |
| `0x01` | **LEN** | 2B | Total Frame Length (Header + Payload + CRC + Stop) |
| `0x03` | **DEST** | 2B | Destination Address (e.g., `1`=Boiler, `32`=Mixer) |
| `0x05` | **SRC** | 2B | Source Address (e.g., `0`=TouchPanel, `100`=Thermostat) |
| `0x07` | **CMD** | 1B | Function Code (Command ID) |
| `0x08` | **DATA** | N | Variable Payload |
| `N-2` | **CRC** | 2B | CRC-16 Checksum |
| `N-1` | **STOP** | 1B | Frame Stop Delimiter (`0x16`) |

### Key Function Codes

* **`0x02` (READ_REQ):** Request to read a parameter.
    * Payload: `[0x01] [Index (2 Bytes)]`
* **`0x82` (READ_RESP):** Response containing parameter definition and value.
* **`0x03` (WRITE_REQ):** Request to write a value (*Not yet implemented*).
* **`0x09` (PING):** Identification/Heartbeat request.

### CRC Calculation

The checksum algorithm is **CRC-16/XMODEM**.
* **Polynomial:** `0x1021`
* **Initial Value:** `0x0000`

---

## Data Payload Decoding

This is the core logic for interpreting the `0x82` response frames.

### Payload Structure

A read response (`0x82`) contains a serialized structure:

1.  **Name:** Null-terminated String (Latin-1 encoded).
2.  **Unit:** Null-terminated String (Latin-1 encoded).
3.  **Info Byte:** 1 Byte.
    * `Bits 0-3`: Type ID (see table below).
    * `Bit 5`: Access Flag (1 = Read/Write, 0 = Read Only).
4.  **Exponent:** 1 Byte (**Signed**).
    * Crucial for scaling values.
    * Formula: $FinalValue = RawValue \times 10^{Exponent}$
5.  **Raw Value:** N Bytes (Depends on Type ID).

### Data Types Table

Mapped in `TYPE_DEFS` in the source code.

| ID | Name | Python Struct Format | Size (Bytes) | Note |
|:---|:---|:---|:---|:---|
| 1 | SHORT INT | `<b` | 1 | Signed 8-bit |
| 2 | INT | `<h` | 2 | Signed 16-bit |
| 3 | LONG INT | `<i` | 4 | Signed 32-bit |
| 4 | BYTE | `<B` | 1 | Unsigned 8-bit |
| 5 | WORD | `<H` | 2 | Unsigned 16-bit |
| 6 | DWORD | `<I` | 4 | Unsigned 32-bit |
| 7 | SHORT REAL | `<f` | 4 | IEEE 754 Float |
| 10 | BOOLEAN | `<B` | 1 | `0`=OFF, `>0`=ON |
| 12 | STRING | `s` | Var | Null-terminated |

---

## Development & Contribution

### Setup

No external requirements are needed. The project uses the Python Standard Library.

```bash
python3 gazmodem_scanner.py
```

### Coding Standards

* **Type Hinting:** All functions must use Python `typing` annotations.
* **Documentation:** Use Doxygen-style docstrings (`## @brief`, `## @param`) for automatic documentation generation.
* **Naming Conventions:**
    * Classes: `CamelCase`
    * Functions/Variables: `snake_case`
    * Constants: `UPPER_CASE`

### Testing

To simulate network traffic without physical hardware, developers can implement a **Mock Socket** class inside `GazModemBackend` to replay captured hex frames:

```python
class MockSocket:
    def recv(self, bufsize):
        # Return a pre-recorded hex sequence
        return bytes.fromhex("68 0C 00 20 00 64 00 82 ... 16")
    
    def send(self, data):
        pass
```

### References

Protocol knowledge is derived from reverse-engineering efforts and community documentation found on PLUM EcoNet compatible devices (EcoMax 350/850/860 controllers).
