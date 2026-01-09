import asyncio
from plum_device import PlumDevice

# --- CONFIG ---
IP = "192.168.1.38"
USER = "USER-000"
PASS = "4095"

import logging
# Activez les logs DEBUG pour tout voir
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

async def main():
    print("=== TEST VALIDÉ ===", flush=True)
    boiler = PlumDevice(IP)

    try:
        print("[1] Chargement Map...", end="", flush=True)
        boiler.load_map()
        print(" OK.", flush=True)

        print("[2] Scan (Timeout large)...", flush=True)
        slugs = list(boiler.params_map.keys())
        targets = [s for s in slugs if any(k in s for k in ["uid", "tempcwu", "circuit2", "dhw", "boiler", "mix2", "mixer2", "weather", "heatsource"])]
        targets.sort()

        comfort_slug = None

        for i, slug in enumerate(targets):
            print(f"   [{i+1}/{len(targets)}] Lecture {slug:<25} ... ", end="", flush=True)

            val = None
            max_global_retries = 3  # On s'autorise 3 "Kill & Retry"
            current_try = 0

            while current_try < max_global_retries:
                current_try += 1
                try:
                    # TENTATIVE AVEC TIMEOUT EXTERNE
                    # On laisse 6 secondes max.
                    # (C'est suffisant pour que la librairie fasse 2 ou 3 essais internes)
                    val = await asyncio.wait_for(boiler.get_value(slug), timeout=6.0)

                    if val is not None:
                        unit = boiler.params_map[slug].get('unit', '')
                        print(f"✅ {val} {unit}", flush=True)
                        break # SUCCÈS : On sort de la boucle while
                    else:
                        # Cas où la librairie a fini ses essais mais n'a rien trouvé (return None)
                        if current_try < max_global_retries:
                            #print(f"⚠️ (Null -> Retry) ", end="", flush=True)
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
                        print("-> On tue et on relance...", end="", flush=True)
                        # On force le nettoyage (même si en mode hybride c'est moins critique)
                        await boiler.close()
                        await asyncio.sleep(0.1) # Petite pause avant de relancer

                except Exception as e:
                    print(f"💥 {e}", flush=True)
                    break # Erreur grave, on passe au suivant

            # Repérage auto du paramètre confort
            if "comfort" in slug and "circuit2" in slug:
                comfort_slug = slug

            # Pause entre deux paramètres différents
            await asyncio.sleep(0.1)

        # --- TEST ECRITURE ---
        print("\n[3] Test Écriture...", flush=True)
        if comfort_slug:
            print(f"   Cible : {comfort_slug}", flush=True)
            try:
                new_val = float(input("   Entrez nouvelle valeur : "))
                print(f"   Envoi...", end="", flush=True)

                ok = await boiler.set_value(comfort_slug, new_val, user=USER, password=PASS)

                if ok:
                    print(" ✅ SUCCÈS.", flush=True)
                    print("   Relecture dans 3s...", flush=True)
                    await asyncio.sleep(3.0)
                    verif = await boiler.get_value(comfort_slug)
                    print(f"   Valeur relue : {verif}", flush=True)
                else:
                    print(" ❌ ÉCHEC.", flush=True)
            except ValueError:
                print(" Valeur invalide.")
        else:
            print("   Pas de paramètre 'comfort' trouvé.", flush=True)

    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        # Maintenant cette méthode existe et ne plantera plus
        await boiler.close()

if __name__ == "__main__":
    asyncio.run(main())
