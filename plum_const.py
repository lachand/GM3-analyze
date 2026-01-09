# Codes Commandes
CMD_SCAN = 0x01
CMD_READ_VAL = 0x43
CMD_WRITE_VAL = 0x44      # Old write
CMD_WRITE_VAL_V3 = 0x45   # Write with Session
CMD_WRITE_FORCE = 0x29    # Write Panel style (Celui qui marche pour vous)

# Types de données PLUM
TYPE_MAP = {
    0: "BYTE",
    1: "WORD",
    2: "DWORD",
    3: "BYTE",       # Souvent booléen
    4: "SHORT_INT",
    5: "INT",
    6: "LONG_INT",
    7: "FLOAT",
    8: "STRING",
}
