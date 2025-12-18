# GazModem Scanner Project Roadmap

This document outlines the strategic vision for the evolution of the GazModem Scanner. The goal is to evolve from a raw analysis tool into a structured, safe, and complete home automation integration solution.

## Phase 1: Foundation & Analysis (Completed)
*Essential features for network discovery and raw data extraction.*
- [x] **Passive Sniffer:** Automatic discovery of active devices (Master, Mixers, Thermostats) via network listening.
- [x] **Active Scanner:** Interrogation of parameters with intelligent skipping of empty memory zones.
- [x] **Decoding:** Handling of specific binary types (Float, Int, String) and **Signed Exponent Correction**.
- [x] **GUI:** Multithreaded Tkinter interface with real-time logs.
- [x] **Export:** CSV export capability for offline analysis.
- [x] **Documentation:** Developer & User guides.

## Phase 2: Contextualization & Mapping (Current Focus)
*Goal: Move from a "flat list of parameters" to a structured view of the heating system. Identify "What is What".*

- [ ] **Circuit & Module Discovery:**
    - Specifically scan addresses reserved for Hydraulic Modules and Mixers (typically `30` to `50`).
    - Distinguish between the **Main Boiler** (Addr `1`) and **Expansion Modules** (Addr `30+`).
- [ ] **Circuit Naming (Name Extraction):**
    - Automatically identify the **Circuit Name** (e.g., *"Floor Heating"*, *"Radiators"*, *"Hot Water"*).
    - Usually stored at specific indexes (e.g., Index `0` often holds the UID or Name).
    - Display the human-readable name in the UI instead of just "Device 32".
- [ ] **Hierarchical UI (Grouping):**
    - Refactor the Table View to group parameters by **Device/Circuit**.
    - Use **Tabs** or **Collapsible Sections** for each detected circuit (e.g., Tab 1: Boiler, Tab 2: Mixer A, Tab 3: Thermostat).
- [ ] **Topology Mapping:**
    - Generate a visual map or a JSON tree representing the system topology (Master -> connected Modules).

## Phase 3: Interaction & Control (Short Term)
*Goal: Enable safe modification of identified parameters.*

- [ ] **Write Module (GUI):**
    - Add a context menu (Right-Click) on parameters: *"Modify Value"*.
    - Implement Command `0x03` (Write) securely.
    - **Safety Check:** Strictly enforce `RW` (Read/Write) flag verification before sending commands.
- [ ] **Profile Management:**
    - Ability to save/load "Known Good Configurations" (Parameter maps) to avoid full rescans.
    - Export specific parameter sets (e.g., "Winter Settings") to JSON.

## Phase 4: Headless Integration (Medium Term)
*Goal: Run the tool as a service on a server (Raspberry Pi, Docker).*

- [ ] **CLI Mode (Command Line):**
    - Decouple `Backend` logic from `AppGUI`.
    - Allow running scans via arguments: `python gazmodem.py --scan --ip ... --output system_map.json`.
- [ ] **MQTT Gateway:**
    - Create `gazmodem2mqtt.py`.
    - Publish decoded values to an MQTT Broker (for Home Assistant, Jeedom, Node-RED).
    - Subscribe to topics (e.g., `gazmodem/set/mixer_temp`) to control the boiler remotely.
- [ ] **Home Assistant Auto-Discovery:**
    - Automatically generate Home Assistant configuration payloads based on the Phase 2 mapping.

## Phase 5: Ecosystem & Web (Long Term)
- [ ] **Web Interface:**
    - Replace Tkinter with a lightweight Web UI (FastAPI/Flask + Vue.js) for mobile access.
- [ ] **Crowdsourced Database:**
    - Create a central repository of CSV "Device Definitions" shared by the community to support various boiler models out-of-the-box.

## Technical Backlog
- **Refactoring:** Transition from `threading` to `asyncio` for more efficient network I/O handling.
- **Security:** Add support for password-protected EcoNet modules (authentication frames).
- **Testing:** Implement Unit Tests mocking the TCP socket to validate decoding logic without physical hardware.
