import asyncio
from plum_device import PlumDevice

# --- CONFIG ---
IP = "192.168.1.38"
USER = "USER-000"
PASS = "4095"

import logging
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

async def main():
    print("=== Test ===", flush=True)
    boiler = PlumDevice(IP)

    try:
        print("[1] Loading parameters...", end="", flush=True)
        boiler.load_map()
        print(" OK.", flush=True)

        print("[2] Scanning ...", flush=True)
        slugs = list(boiler.params_map.keys())
        targets = [s for s in slugs if any(k in s for k in ["uid", "tempcwu", "circuit2", "dhw", "boiler", "mix2", "mixer2", "weather", "heatsource"])]
        targets.sort()

        comfort_slug = None

        for i, slug in enumerate(targets):
            print(f"   [{i+1}/{len(targets)}] Lecture {slug:<25} ... ", end="", flush=True)

            val = None
            max_global_retries = 3
            current_try = 0

            while current_try < max_global_retries:
                current_try += 1
                try:
                    val = await asyncio.wait_for(boiler.get_value(slug), timeout=6.0)

                    if val is not None:
                        unit = boiler.params_map[slug].get('unit', '')
                        print(f"✅ {val} {unit}", flush=True)
                        break # SUCCÈS : On sort de la boucle while
                    else:
                        if current_try < max_global_retries:
                            await asyncio.sleep(1.0)
                        else:
                            current_try
                            #print(f"❌ (Abandon)", flush=True)

                except asyncio.TimeoutError:
                    # C'est le cas "🛑 BLOCK"
                    #print(f"🛑 BLOCK (Timeout Externe) ", end="", flush=True)

                    # Si c'était le dernier essai, on arrête
                    if current_try == max_global_retries:
                        #print("-> ABANDON.", flush=True)
                        current_try
                    else:
                        print("-> retrying...", end="", flush=True)
                        await boiler.close()
                        await asyncio.sleep(0.1)

                except Exception as e:
                    print(f"{e}", flush=True)
                    break

            if "comfort" in slug and "circuit2" in slug:
                comfort_slug = slug

            await asyncio.sleep(0.1)

        print("\n[3] Writing test...", flush=True)
        if comfort_slug:
            print(f"   Target : {comfort_slug}", flush=True)
            try:
                new_val = float(input("   Enter a new value : "))
                print(f"   Sending...", end="", flush=True)

                ok = await boiler.set_value(comfort_slug, new_val, user=USER, password=PASS)

                if ok:
                    print(" SUCCES.", flush=True)
                    print("   Reading in 3s...", flush=True)
                    await asyncio.sleep(3.0)
                    verif = await boiler.get_value(comfort_slug)
                    print(f"   Valeur relue : {verif}", flush=True)
                else:
                    print(" ERROR.", flush=True)
            except ValueError:
                print(" Invalid value.")
        else:
            print("   No 'comfort' parameter found", flush=True)

    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        await boiler.close()

if __name__ == "__main__":
    asyncio.run(main())
