# Technical Logic & Step-by-Step Operation

This document explains the internal workflow of the **GazModem Scanner**. It details how the tool connects, discovers devices, and decodes the proprietary binary protocol.

## Architecture

The application is split into two main components:
1.  **The Backend (`GazModemBackend`):** A dedicated thread handling TCP sockets, binary parsing, and protocol logic.
2.  **The Frontend (`AppGUI`):** A Tkinter interface that receives data via thread-safe `Queues`.

---

## Step-by-Step Workflow

### Step 1: Connection & Handshake
The tool opens a raw TCP socket to the converter.
* **Timeout:** Set to 1.0s to prevent hanging on lost packets.
* **Socket Mode:** Blocking mode is used within the thread.

### Step 2: Phase 1 - Passive Sniffing (30s)
Before sending any command, the tool listens to existing traffic between the Boiler (Master) and its peripherals (Thermostats, Mixers).

1.  **Buffer Accumulation:** Incoming TCP chunks are merged into a byte buffer.
2.  **Frame Parsing:** The tool looks for valid frames matching the structure:
    `[START 0x68] [LEN] [DEST] [SRC] [CMD] ... [STOP 0x16]`
3.  **Address Extraction:** It extracts the `Source (SRC)` and `Destination (DEST)` addresses from every valid frame.
4.  **Discovery:** New addresses are added to a `Set` (e.g., `{1, 32, 100}`).

> **Why?** Sending requests to non-existent addresses causes timeouts and slows down the scan significantly. Sniffing ensures we only target active devices.

### Step 3: Phase 2 - Active Smart Scanning
The tool iterates through every discovered device address.

**The Loop:**
For every index from `0` to `1000`:
1.  **Request:** Sends a **Read Command (0x02)** to the target.
    * payload: `[0x01] [Index (2 bytes)]`
2.  **Response:** Waits for a packet with Function Code **0x82** (Read Success).
3.  **Smart Skip:**
    * If `100` consecutive requests result in empty responses or timeouts, the scanner assumes the memory map has ended for this device and jumps to the next device.

### Step 4: Decoding Logic
This is the core of the reverse-engineering capability.

When a payload is received, it is parsed as follows:
1.  **Metadata:** Reads the `Name` and `Unit` (Strings).
2.  **Type & Flags:** Reads the `Info` byte.
    * Lower 4 bits: **Type ID** (Int, Float, Byte...).
    * Bit 5: **Read/Write** flag.
3.  **Exponent Handling (Crucial):**
    * Reads the signed byte following the Info byte.
    * *Correction:* If the exponent is absurd (e.g., > 6 or < -6), it is forced to 0. This prevents the "Billions Value" bug caused by dirty memory.
4.  **Value Construction:**
    * Raw bytes are unpacked according to the `Type ID` (e.g., IEEE754 for Floats).
    * Final Value = `RawValue * (10 ^ Exponent)`.

### Step 5: Visualization
* Data is pushed to the `result_queue`.
* The GUI polls this queue every 100ms.
* **Highlighting:** If a value contains "15.7" or "21.2" (strings), the row is tagged in green to alert the user of a potential temperature candidate.

## Protocol Frame Structure

A standard GazModem frame looks like this:

| Byte | Field | Description |
| :--- | :--- | :--- |
| 0 | **START** | Always `0x68` |
| 1-2 | **LEN** | Length of payload + headers |
| 3-4 | **DEST** | Destination Address (e.g., `32`) |
| 5-6 | **SRC** | Source Address (e.g., `0` or `100`) |
| 7 | **CMD** | Function Code (e.g., `0x02` Read) |
| ... | **DATA** | Payload |
| N-2 | **CRC** | CRC-16 (Polynomial 0x1021) |
| N-1 | **STOP** | Always `0x16` |
