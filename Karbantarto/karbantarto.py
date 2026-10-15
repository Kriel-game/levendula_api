import asyncio
import os
import httpx
from pathlib import Path
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
import json
import sys
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# A Backend mappa hozzáadása a rendszer útvonalaihoz, hogy lássuk a modelleket
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Backend.database import SessionLocal
from Backend.models import SecurityEvent, Base
# Pontosan megmutatjuk neki, hol van a Backend mappában lévő .env fájl
env_path = Path(__file__).parent.parent / "Backend" / ".env"
load_dotenv(dotenv_path=env_path)

RENDER_API_KEY = os.getenv("RENDER_API_KEY")
RENDER_API_URL = "https://api.render.com/v1"

# A Render API által elvárt fejlécek (hitelesítés)
HEADERS = {
    "Authorization": f"Bearer {RENDER_API_KEY}",
    "Accept": "application/json"
}


def create_backup():
    """
    Kiolvassa az aktuális adatbázis összes rekordját, és kimenti egy tartós JSON fájlba.
    """
    print("\n[Mentés] Adatok kiolvasása a jelenlegi adatbázisból...")
    db = SessionLocal()
    try:
        events = db.query(SecurityEvent).all()
        backup_data = []

        for event in events:
            backup_data.append({
                "id": event.id,
                "ip_address": event.ip_address,
                "timestamp": event.timestamp,
                "http_method": event.http_method,
                "request_url": event.request_url,
                "status_code": event.status_code,
                "severity": event.severity,
                "reason": event.reason
            })

        # Időbélyeggel ellátott fájlnév (pl. mentes_20261015_183000.json)
        backup_filename = f"mentes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        backup_path = Path(__file__).parent / backup_filename

        # Fájlba írás UTF-8 kódolással
        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, ensure_ascii=False, indent=4)

        print(f"[Mentés] Sikeres mentés! {len(backup_data)} rekord mentve ide: {backup_filename}")
        return backup_path

    except Exception as e:
        print(f"[Mentés] KRITIKUS HIBA a mentés során: {e}")
        return None
    finally:
        db.close()


def restore_backup(backup_path, new_db_url):
    """
    Újraépíti az adatbázis sémát egy üres példányban, majd betölti a JSON mentést.
    """
    # Biztonsági okokból a jelszót levágjuk a kiírásnál (a @ jel utáni részt mutatjuk)
    safe_url = new_db_url.split('@')[-1] if '@' in new_db_url else new_db_url
    print(f"\n[Visszaállítás] Adatok betöltése az új példányba ({safe_url})...")

    # Új kapcsolat kiépítése a FRISS adatbázishoz
    new_engine = create_engine(new_db_url)
    NewSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=new_engine)

    try:
        # 1. Létrehozzuk az üres táblákat (séma helyreállítása)
        Base.metadata.create_all(bind=new_engine)

        # 2. JSON beolvasása
        with open(backup_path, "r", encoding="utf-8") as f:
            backup_data = json.load(f)

        db = NewSessionLocal()

        # 3. Adatok feltöltése
        for item in backup_data:
            event = SecurityEvent(
                id=item["id"],  # Megtartjuk az eredeti ID-ket a kapcsolatok miatt
                ip_address=item["ip_address"],
                timestamp=item["timestamp"],
                http_method=item["http_method"],
                request_url=item["request_url"],
                status_code=item["status_code"],
                severity=item["severity"],
                reason=item["reason"]
            )
            db.add(event)

        db.commit()
        print(f"[Visszaállítás] Sikeres! {len(backup_data)} rekord betöltve az új adatbázisba.")
        return True

    except Exception as e:
        print(f"[Visszaállítás] Hiba történt: {e}")
        return False
    finally:
        if 'db' in locals():
            db.close()


WEB_SERVICE_ID = "srv-db8hc7nf3r2c73fcip30"


async def perform_database_rotation():
    """
    6.3. Automatizált csere végrehajtása
    """
    print("\n[Karbantartó] *** AUTOMATIKUS ADATBÁZIS CSERE INDUL ***")

    # 1. Kimentjük a meglévő adatokat a biztonságos JSON fájlunkba
    backup_path = create_backup()
    if not backup_path:
        print("[Karbantartó] Mentés sikertelen, megszakítás!")
        return

    async with httpx.AsyncClient(timeout=120.0) as client:
        # 2. Megkeressük a jelenlegi adatbázist
        db_resp = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)
        if db_resp.status_code == 200 and len(db_resp.json()) > 0:
            old_db_id = db_resp.json()[0]['postgres']['id']
            print(f"[Karbantartó] Régi adatbázis törlése ({old_db_id}) a limit miatt...")
            # Töröljük a régit, hogy helyet csináljunk az újnak
            await client.delete(f"{RENDER_API_URL}/postgres/{old_db_id}", headers=HEADERS)
            await asyncio.sleep(15)  # Várunk kicsit, hogy a Render felszabadítsa a szervert

        # 3. Vadonatúj adatbázis létrehozása (Frankfurt régióban)
        new_name = f"levendula-db-{datetime.now().strftime('%H%M%S')}"
        print(f"[Karbantartó] Új PostgreSQL adatbázis létrehozása ({new_name})...")

        payload = {
            "name": new_name,
            "plan": "free",
            "postgresVersion": "15",
            "region": "fra"
        }
        create_resp = await client.post(f"{RENDER_API_URL}/postgres", headers=HEADERS, json=payload)

        if create_resp.status_code != 201:
            print(f"[Karbantartó] Hiba a létrehozásnál: {create_resp.text}")
            return

        new_db = create_resp.json()
        new_db_id = new_db['id']

        # Kapcsolati linkek kinyerése
        ext_url = new_db['connectionInfo']['externalConnectionString'].replace("postgres://", "postgresql://", 1)
        int_url = new_db['connectionInfo']['internalConnectionString'].replace("postgres://", "postgresql://", 1)

        print("[Karbantartó] Várakozás az új adatbázis felállására (ez kb. 1-2 perc)...")
        for _ in range(30):
            status_resp = await client.get(f"{RENDER_API_URL}/postgres/{new_db_id}", headers=HEADERS)
            if status_resp.json().get("status") == "available":
                break
            await asyncio.sleep(10)

        # 4. Adatok visszaállítása a mentésből
        success = restore_backup(backup_path, ext_url)
        if not success:
            print("[Karbantartó] A visszaállítás sikertelen volt.")
            return

        # 5. A FastAPI webszerver átállítása az új adatbázisra (A NAGY TRÜKK!)
        print(f"[Karbantartó] A webszerver (API) összekötése az új adatbázissal...")
        env_payload = [
            {"key": "DATABASE_URL", "value": int_url}  # A belső (internal) link sokkal gyorsabb a felhőn belül
        ]
        env_resp = await client.put(
            f"{RENDER_API_URL}/services/{WEB_SERVICE_ID}/env-vars",
            headers=HEADERS,
            json=env_payload
        )

        if env_resp.status_code == 200:
            print("[Karbantartó] *** SIKERES CSERE! ***")
            print("A régi adatbázist megsemmisítettük. A rendszer egy vadonatúj adatbázison fut megszakítás nélkül!")
        else:
            print(f"[Karbantartó] Hiba az átállításnál: {env_resp.text}")

async def check_database_status():
    """
    6.1. Időzített, aszinkron állapotellenőrzés
    Lekérdezi a Renderen lévő PostgreSQL adatbázisok állapotát.
    """
    print("\n[Karbantartó] Adatbázis állapotának ellenőrzése indul...")

    async with httpx.AsyncClient() as client:
        try:
            # Lekérdezzük a fiókhoz tartozó PostgreSQL adatbázisokat
            response = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)

            if response.status_code == 200:
                db_list = response.json()
                print(f"[Karbantartó] Sikeres lekérdezés! {len(db_list)} adatbázis található.")

                # Itt fogjuk majd kielemezni, hogy lejár-e hamarosan a 30 napos adatbázis
                for db in db_list:
                    db_info = db.get("postgres", {})
                    print(f" - Név: {db_info.get('name')}, Állapot: {db_info.get('status')}, ID: {db_info.get('id')}")
            else:
                print(f"[Karbantartó] Hiba az API hívásnál: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"[Karbantartó] Hálózati hiba történt: {e}")


async def main():
    print("Levendula Karbantartó Rendszer indul...")

    # Aszinkron ütemező létrehozása
    scheduler = AsyncIOScheduler()

    # Beállítjuk, hogy a check_database_status függvény 1 percenként lefusson
    scheduler.add_job(check_database_status, 'interval', minutes=1)
    # Beállítjuk, hogy a perform_database_rotation (A csere) fusson le tesztként, mondjuk 1 perc múlva
    # scheduler.add_job(perform_database_rotation, 'interval', minutes=2)
    scheduler.start()
    print("Időzítő elindítva. Első ellenőrzés 1 perc múlva... Leállítás: Ctrl+C")

    # Egy végtelen ciklus, ami életben tartja a főprogramot
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        # A modern Python belépési pontja
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\nKarbantartó rendszer leállítva.")