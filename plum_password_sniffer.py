import socket
import struct
import time
import sys

# Configuration
IP = "192.168.1.38"
PORT = 8899

CMD_WRITE_FORCE = 0x29
CMD_WRITE_APP = 0x45
CMD_WRITE_OLD = 0x44

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def extract_strings(payload):
    strings = []
    parts = payload.split(b'\x00')
    for p in parts:
        try:
            decoded = p.decode('utf-8')
            if len(decoded) >= 3 and decoded.isprintable():
                strings.append(decoded)
        except: pass
    return strings

def run_sniffer():
    print("="*60)
    print("PLUM PASSWORD SNIFFER")
    print("="*60)
    print("INSTRUCTIONS :")
    print("1. The script will connect.")
    print("2. Go to your thermostat.")
    print("3. Change a value")
    print("4. Check back here to see if the password is displayed.")
    print("-" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        log("Connection...")
        sock.connect((IP, PORT))
        log("Connected. listening...")

        buffer = bytearray()
        last_heartbeat = time.time()

        while True:
            if time.time() - last_heartbeat > 5.0:
                try:
                    ping = b'\x68\x0b\x00\x00\x01\x00\xc9\x01\x0e\x16'
                    sock.send(ping)
                    last_heartbeat = time.time()
                    sys.stdout.write(".")
                    sys.stdout.flush()
                except Exception as e:
                    log(f"\nHeartbeat error: {e}")
                    break

            try:
                chunk = sock.recv(4096)
                if not chunk:
                    log("\nDeconnected.")
                    break

                buffer.extend(chunk)

                if len(buffer) > 10000:
                    del buffer[:]
                    continue

                while b'\x68' in buffer:
                    idx = buffer.find(b'\x68')
                    if idx > 0: del buffer[:idx]

                    if len(buffer) < 8: break

                    l_payload = struct.unpack("<H", buffer[1:3])[0]
                    total_len = l_payload + 6

                    if len(buffer) >= total_len:
                        frame = buffer[:total_len]
                        del buffer[:total_len]

                        if frame[-1] == 0x16:
                            cmd = frame[7]

                            if cmd in [CMD_WRITE_FORCE, CMD_WRITE_APP, CMD_WRITE_OLD]:
                                print("\n\n" + "🚨"*20)
                                log(f" Writing frame detected (CMD {hex(cmd)})")

                                payload = frame[8:-3]
                                strs = extract_strings(payload)

                                print(f"   Datas finded : {strs}")

                                user = "Unknown"
                                password = "Unknown"

                                # Heuristique simple :
                                # Souvent : [USER] [PASS] [Reste...]
                                if len(strs) >= 1: user = strs[0]
                                if len(strs) >= 2: password = strs[1]

                                print("-" * 40)
                                print(f"   👤 USER  : {user}")
                                print(f"   🔑 PASSWORD : {password}")
                                print("-" * 40)

            except socket.timeout:
                continue
            except Exception as e:
                log(f"\nReading error: {e}")
                break

    except KeyboardInterrupt:
        print("\nManual interruption.")
    finally:
        sock.close()

if __name__ == "__main__":
    run_sniffer()
