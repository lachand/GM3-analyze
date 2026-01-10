## @package plum_const
#  @brief Global constants and command codes.
#  @details Contains Plum protocol opcodes and data type mappings.

# Command Codes
CMD_SCAN = 0x01             ##< Command to scan parameters.
CMD_READ_VAL = 0x43         ##< Command to read a value.
CMD_WRITE_VAL = 0x44        ##< Old write command.
CMD_WRITE_VAL_V3 = 0x45     ##< Write command with session (V3).
CMD_WRITE_FORCE = 0x29      ##< Forced write command (Panel mode).

# PLUM Data Types
## Mapping from Type ID to Type Name (Spec V1)
TYPE_MAP = {
    0: "BYTE",
    1: "WORD",
    2: "DWORD",
    3: "BYTE",       # Often boolean
    4: "SHORT_INT",
    5: "INT",
    6: "LONG_INT",
    7: "FLOAT",
    8: "STRING",
}
