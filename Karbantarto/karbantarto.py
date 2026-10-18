import asyncio
import os
import json
import sys
from pathlib import Path
from datetime import datetime
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# =====================================================================
# AUTOMATIZÁLT FELHŐS ADATBÁZIS-KARBANTARTÓ ÉS MENTŐ RENDSZER
# Szerepe: A 6. fejezet követelményeit megvalósító önálló háttérszolgáltatás.
# Három fő feladatot lát el:
# 1. Időzített, aszinkron állapotellenőrzés a Render REST API-n keresztül (6.1).
# 2. Tiszta Python alapú adatbázis-mentés (JSON export) és séma/adat visszaállítás (6.2).
# 3. Automatizált adatbázis-rotáció (törlés, új példány igénylése, migráció és
#    a FastAPI webszerver környezeti változójának dinamikus átkötése) (6.3).
# =====================================================================

# Hozzáadjuk a projekt gyökérmappáját a Python keresési útvonalához (sys.path),
# hogy a Karbantarto mappából futtatva is elérjük a 'Backend' csomag modelljeit.
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Backend.database import SessionLocal
from Backend.models import SecurityEvent, Base

# Betöltjük a Backend mappában található .env fájlt (benne a DATABASE_URL és RENDER_API_KEY)
env_path = project_root / "Backend" / ".env"
load_dotenv(dotenv_path=env_path)

RENDER_API_KEY = os.getenv("RENDER_API_KEY")
RENDER_API_URL = "https://api.render.com/v1"
WEB_SERVICE_ID = "srv-db8hc7nf3r2c73fcip30"

# Hitelesítési fejléc (Bearer Token) a Render REST API hívásokhoz
HEADERS = {
    "Authorization": f"Bearer {RENDER_API_KEY}",
    "Accept": "application/json"
}


def create_backup():
    """
    6.2. Biztonsági mentés (Export):
    Kiolvassa az aktuális adatbázis összes 'SecurityEvent' rekordját SQLAlchemy-vel,
    és elmenti őket egy időbélyeggel ellátott, hordozható JSON fájlba.
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

        backup_filename = f"mentes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        backup_path = Path(__file__).parent / backup_filename

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
    6.2. Adatvisszaállítás (Import és Sémaépítés):
    Kapcsolódik az újonnan létrehozott üres adatbázishoz, felépíti a táblaszerkezetet
    (Base.metadata.create_all), majd visszatölti a JSON mentésben lévő rekordokat.
    """
    safe_url = new_db_url.split('@')[-1] if '@' in new_db_url else new_db_url
    print(f"\n[Visszaállítás] Adatok betöltése az új példányba ({safe_url})...")

    new_engine = create_engine(new_db_url)
    NewSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=new_engine)

    try:
        # 1. Táblák (séma) létrehozása az új adatbázisban
        Base.metadata.create_all(bind=new_engine)

        # 2. Mentett adatok beolvasása a JSON fájlból
        with open(backup_path, "r", encoding="utf-8") as f:
            backup_data = json.load(f)

        db = NewSessionLocal()

        # 3. Rekordok beszúrása az eredeti azonosítók (ID) megtartásával
        for item in backup_data:
            event = SecurityEvent(
                id=item["id"],
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


async def perform_database_rotation():
    """
    6.3. Automatizált adatbázis-csere (Rotáció):
    Végrehajtja a teljes migrációs ciklust: mentés -> régi törlése -> új létrehozása ->
    adatok visszatöltése -> a FastAPI webszerver DATABASE_URL változójának frissítése.
    """
    print("\n[Karbantartó] *** AUTOMATIKUS ADATBÁZIS CSERE INDUL ***")

    # 1. Biztonsági mentés készítése; ha sikertelen, nem nyúlunk az éles adatbázishoz!
    backup_path = create_backup()
    if not backup_path:
        print("[Karbantartó] Mentés sikertelen, a csere biztonsági okokból megszakítva!")
        return

    async with httpx.AsyncClient(timeout=120.0) as client:
        # 2. Jelenlegi adatbázis lekérdezése és törlése
        db_resp = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)
        if db_resp.status_code == 200 and len(db_resp.json()) > 0:
            old_db_id = db_resp.json()[0]['postgres']['id']
            print(f"[Karbantartó] Régi adatbázis törlése ({old_db_id})...")
            await client.delete(f"{RENDER_API_URL}/postgres/{old_db_id}", headers=HEADERS)
            await asyncio.sleep(15)

        # 3. Új PostgreSQL példány igénylése a Render API-tól
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
            print(f"[Karbantartó] Hiba a létrehozásnál (Render kvóta / cooldown): {create_resp.text}")
            return

        new_db = create_resp.json()
        new_db_id = new_db['id']

        ext_url = new_db['connectionInfo']['externalConnectionString'].replace("postgres://", "postgresql://", 1)
        int_url = new_db['connectionInfo']['internalConnectionString'].replace("postgres://", "postgresql://", 1)

        # Várakozás (polling), amíg az új adatbázis eléri az 'available' állapotot
        print("[Karbantartó] Várakozás az új adatbázis felállására...")
        for _ in range(30):
            status_resp = await client.get(f"{RENDER_API_URL}/postgres/{new_db_id}", headers=HEADERS)
            if status_resp.json().get("status") == "available":
                break
            await asyncio.sleep(10)

        # 4. Mentett adatok visszatöltése az új adatbázisba a külső (External) linken keresztül
        success = restore_backup(backup_path, ext_url)
        if not success:
            print("[Karbantartó] A visszaállítás sikertelen volt.")
            return

        # 5. A FastAPI webszerver környezeti változójának (DATABASE_URL) frissítése a belső (Internal) linkre
        print("[Karbantartó] A webszerver (API) összekötése az új adatbázissal...")
        env_payload = [
            {"key": "DATABASE_URL", "value": int_url}
        ]
        env_resp = await client.put(
            f"{RENDER_API_URL}/services/{WEB_SERVICE_ID}/env-vars",
            headers=HEADERS,
            json=env_payload
        )

        if env_resp.status_code == 200:
            print("[Karbantartó] *** SIKERES CSERE! ***")
        else:
            print(f"[Karbantartó] Hiba az átállításnál: {env_resp.text}")


async def check_database_status():
    """
    6.1. Időzített, aszinkron állapotellenőrzés:
    Nem-blokkoló (async/await) HTTP kéréssel lekérdezi a Render API-tól
    az adatbázisok aktuális státuszát.
    """
    print("\n[Karbantartó] Adatbázis állapotának ellenőrzése indul...")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)

            if response.status_code == 200:
                db_list = response.json()
                print(f"[Karbantartó] Sikeres lekérdezés! {len(db_list)} adatbázis található.")

                for db in db_list:
                    db_info = db.get("postgres", {})
                    print(f" - Név: {db_info.get('name')}, Állapot: {db_info.get('status')}, ID: {db_info.get('id')}")
            else:
                print(f"[Karbantartó] Hiba az API hívásnál: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"[Karbantartó] Hálózati hiba történt: {e}")


async def main():
    """
    A karbantartó szolgáltatás fő aszinkron eseményhurka.
    Elindít egy kezdeti biztonsági mentést, majd beütemezi a rendszeres állapotellenőrzést.
    """
    print("Levendula Karbantartó Rendszer indul...")

    # Induláskor készítünk egy azonnali biztonsági mentést az aktuális állapotról
    create_backup()

    # Aszinkron ütemező (APScheduler) konfigurálása és indítása
    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_database_status, 'interval', minutes=1)
    # Ha élesíteni szeretnéd az automatikus rotációt, vedd ki a kommentet:
    # scheduler.add_job(perform_database_rotation, 'interval', days=28)

    scheduler.start()
    print("Időzítő elindítva. Első állapotellenőrzés 1 perc múlva... Leállítás: Ctrl+C")

    # Végtelen ciklus, amely életben tartja az aszinkron háttérfolyamatot
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\nKarbantartó rendszer szabályosan leállítva.")