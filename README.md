# GazModem Scanner

**An reverse-engineering tool for PLUM / GazModem industrial heating networks.**

## Documentation
Documentation available at :

## Overview

GazModem Scanner Pro is a graphical utility designed to analyze RS485-over-Ethernet networks used by **EcoMax, EcoNet, and EcoSter** heating controllers (PLUM protocol).

It helps home automation enthusiasts and integrators find the specific memory addresses (indexes) of heating parameters (temperatures, statuses, settings) to control them via Home Assistant, Domoticz, or custom scripts.

## Key Features

* **Passive Sniffer (Phase 1):** Listens to the network traffic to automatically detect active devices (Boiler, Thermostats, Extension Modules) without flooding the bus.
* **Smart Active Scanner (Phase 2):** Interrogates detected devices to map their memory parameters.
* **Intelligent Skipping:** Automatically detects empty memory ranges and skips them to save time.
* **Decoding:** Handles the specific GazModem binary format, including:
    * Automatic Type Detection (Float, Int, String, Bitmask).
    * **Signed Exponent Correction:** Fixes common issues where values appear as billions due to exponent interpretation errors.
* **Live Visualization:** Real-time data table with automatic highlighting of probable temperature values (e.g., 21.2°C).
* **CSV Export:** Export the full mapping for analysis in Excel.

## Installation

### Prerequisites
* Python 3.8 or higher.
* Tkinter (usually included with Python).

### Running the Tool
1.  Clone this repository or download the script.
2.  Run the main script:
    ```bash
    python gazmodem_scanner.py
    ```

## Usage Guide

1.  **Configuration:**
    * **IP:** Enter the IP address of your EcoNet module or RS485 converter (Default: `192.168.1.38`).
    * **Port:** Enter the TCP port (Default: `8899`).

2.  **Start Scan:**
    * Click **▶ START SCAN**.
    * The tool will first listen for **30 seconds** (Phase 1).
    * It will then actively scan every detected device (Phase 2).

3.  **Analyze:**
    * Look for rows highlighted in **Green**. These indicate values close to typical room temperatures (15°C - 25°C), often indicating the target parameter you are looking for.

4.  **Export:**
    * Click **EXPORT CSV** to save the results.

## Disclaimer

This tool interacts with industrial heating hardware. While the scanner uses "Read-Only" commands (0x02), the author assumes no responsibility for any damage or malfunction caused to your heating system. Use at your own risk.
