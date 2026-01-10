import asyncio
import logging
from plum_device import PlumDevice

# --- CONFIGURATION ---
IP = "192.168.1.38"

PROBES = [
    {"name": "Boiler (Global)", "slug": "tempboiler"},
    {"name": "Hot domestic water",   "slug": "tempcwu"}, #CWU => Translation of HDW in Polish
    {"name": "Circuit 1", "slug": "tempcircuit1"},
    {"name": "Circuit 2", "slug": "tempcircuit2"},
    {"name": "Circuit 3", "slug": "tempcircuit3"},
    {"name": "Circuit 4", "slug": "tempcircuit4"},
    {"name": "Circuit 5", "slug": "tempcircuit5"},
    {"name": "Buffer", "slug": "tempbufordown"},
    {"name": "Feeder", "slug": "tempfeeder"},
    {"name": "Circulation",  "slug": "circulationtempstart"},
    {"name": "Weather",          "slug": "tempwthr"}
]

async def main():
    print(f"{'='*60}")
    print(f"🔍 SCANNING ACTIVE CIRCUITS (IP: {IP})")
    print(f"{'='*60}")

    logging.getLogger("PlumDevice").setLevel(logging.WARNING)

    boiler = PlumDevice(IP)

    try:
        print("Scanning values...", end="", flush=True)
        boiler.load_map()
        print(" OK.\n")

        print(f"{'CIRCUIT / PROBE':<30} | {'STATUT':<12} | {'VALUE':<10}")
        print("-" * 60)

        detected_count = 0

        for probe in PROBES:
            name = probe['name']
            slug = probe['slug']

            if slug not in boiler.params_map:
                continue

            val = await boiler.get_value(slug, retries=4)

            if val is not None and val != 0.0 and val != 999.0:
                status = "✅ ACTIVE"
                unit = boiler.params_map[slug].get('unit', '°C')
                print(f"{name:<30} | {status:<12} | {val} {unit}")
                detected_count += 1
            else:
                status = "❌ INACTIVE"
                if val is None:
                    val_str = "Timeout"
                elif val == 999.0:
                    val_str = "Err 999"
                else:
                    val_str = str(val)

                print(f"{name:<30} | {status:<12} | ({val_str})")

            await asyncio.sleep(0.5)

        print("-" * 60)
        print(f"\nResults : {detected_count} active circuits/probe.")

    except Exception as e:
        print(f"\nCritical error : {e}")
    finally:
        await boiler.close()

if __name__ == "__main__":
    asyncio.run(main())
