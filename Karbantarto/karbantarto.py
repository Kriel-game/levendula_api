import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Add the project root so running this file directly can import Backend modules.
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Backend.database import Base, SessionLocal  # noqa: E402
from Backend.models import SecurityEvent  # noqa: E402

env_path = project_root / "Backend" / ".env"
load_dotenv(dotenv_path=env_path)

RENDER_API_KEY = os.getenv("RENDER_API_KEY")
RENDER_API_URL = "https://api.render.com/v1"
WEB_SERVICE_ID = os.getenv("RENDER_WEB_SERVICE_ID")
try:
    CHECK_INTERVAL_MINUTES = int(os.getenv("CHECK_INTERVAL_MINUTES", "1"))
    if CHECK_INTERVAL_MINUTES < 1:
        raise ValueError
except ValueError:
    logger.warning("Érvénytelen CHECK_INTERVAL_MINUTES; az 1 perces alapérték lesz használva.")
    CHECK_INTERVAL_MINUTES = 1

HEADERS = {
    "Authorization": f"Bearer {RENDER_API_KEY or ''}",
    "Accept": "application/json",
}


def _log_exception(message, exc):
    # Omit exception text because database and HTTP errors may contain credentials.
    logger.exception(
        "%s (%s)",
        message,
        type(exc).__name__,
        exc_info=(type(exc), Exception(type(exc).__name__), exc.__traceback__),
    )


def create_backup():
    """Export all SecurityEvent rows into a timestamped JSON backup."""
    logger.info("Mentés: adatok kiolvasása az adatbázisból.")
    db = SessionLocal()
    try:
        events = db.query(SecurityEvent).all()
        backup_data = [
            {
                "id": event.id,
                "ip_address": event.ip_address,
                "timestamp": event.timestamp,
                "http_method": event.http_method,
                "request_url": event.request_url,
                "status_code": event.status_code,
                "severity": event.severity,
                "reason": event.reason,
            }
            for event in events
        ]
        backup_filename = f"mentes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        backup_path = Path(__file__).parent / backup_filename
        with open(backup_path, "w", encoding="utf-8") as backup_file:
            json.dump(backup_data, backup_file, ensure_ascii=False, indent=4)
        logger.info("Mentés sikeres: %s rekord mentve (%s).", len(backup_data), backup_filename)
        return backup_path
    except Exception as exc:
        _log_exception("Kritikus hiba a mentés során", exc)
        return None
    finally:
        db.close()


def restore_backup(backup_path, new_db_url):
    """Create the target schema and import records from a JSON backup."""
    logger.info("Visszaállítás: adatok betöltése a céladatbázisba.")
    new_engine = None
    db = None
    try:
        new_engine = create_engine(new_db_url)
        new_session_local = sessionmaker(
            autocommit=False, autoflush=False, bind=new_engine
        )
        Base.metadata.create_all(bind=new_engine)
        with open(backup_path, "r", encoding="utf-8") as backup_file:
            backup_data = json.load(backup_file)

        db = new_session_local()
        for item in backup_data:
            db.add(
                SecurityEvent(
                    id=item["id"],
                    ip_address=item["ip_address"],
                    timestamp=item["timestamp"],
                    http_method=item["http_method"],
                    request_url=item["request_url"],
                    status_code=item["status_code"],
                    severity=item["severity"],
                    reason=item["reason"],
                )
            )
        db.commit()
        logger.info("Visszaállítás sikeres: %s rekord betöltve.", len(backup_data))
        return True
    except Exception as exc:
        if db is not None:
            db.rollback()
        _log_exception("Hiba történt a visszaállítás során", exc)
        return False
    finally:
        if db is not None:
            db.close()
        if new_engine is not None:
            new_engine.dispose()


async def perform_database_rotation():
    """Back up, replace, and restore the managed PostgreSQL database."""
    logger.info("Automatikus adatbázis-csere indul.")
    if not RENDER_API_KEY or not WEB_SERVICE_ID:
        logger.error("A rotációhoz hiányzik a Render API-kulcs vagy a webszolgáltatás-azonosító.")
        return

    backup_path = create_backup()
    if not backup_path:
        logger.error("A mentés sikertelen; az adatbázis-csere megszakítva.")
        return

    async with httpx.AsyncClient(timeout=120.0) as client:
        db_response = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)
        if db_response.status_code == 200 and db_response.json():
            old_db_id = db_response.json()[0]["postgres"]["id"]
            logger.warning("A régi adatbázis törlése indul.")
            await client.delete(f"{RENDER_API_URL}/postgres/{old_db_id}", headers=HEADERS)
            await asyncio.sleep(15)

        new_name = f"levendula-db-{datetime.now().strftime('%H%M%S')}"
        logger.info("Új PostgreSQL adatbázis létrehozása indul.")
        payload = {
            "name": new_name,
            "plan": "free",
            "postgresVersion": "15",
            "region": "fra",
        }
        create_response = await client.post(
            f"{RENDER_API_URL}/postgres", headers=HEADERS, json=payload
        )
        if create_response.status_code != 201:
            logger.error(
                "Az adatbázis létrehozása sikertelen (HTTP %s).",
                create_response.status_code,
            )
            return

        new_db = create_response.json()
        new_db_id = new_db["id"]
        connection_info = new_db["connectionInfo"]
        external_url = connection_info["externalConnectionString"].replace(
            "postgres://", "postgresql://", 1
        )
        internal_url = connection_info["internalConnectionString"].replace(
            "postgres://", "postgresql://", 1
        )

        logger.info("Várakozás az új adatbázis elérhetővé válására.")
        for _ in range(30):
            status_response = await client.get(
                f"{RENDER_API_URL}/postgres/{new_db_id}", headers=HEADERS
            )
            if status_response.json().get("status") == "available":
                break
            await asyncio.sleep(10)

        if not restore_backup(backup_path, external_url):
            logger.error("Az adatbázis-visszaállítás sikertelen.")
            return

        logger.info("A webszerver összekötése az új adatbázissal.")
        env_response = await client.put(
            f"{RENDER_API_URL}/services/{WEB_SERVICE_ID}/env-vars",
            headers=HEADERS,
            json=[{"key": "DATABASE_URL", "value": internal_url}],
        )
        if env_response.status_code == 200:
            logger.info("Az adatbázis-csere sikeres.")
        else:
            logger.error(
                "Az adatbázis-átállítás sikertelen (HTTP %s).",
                env_response.status_code,
            )


async def check_database_status():
    """Query managed database status without modifying any database or service."""
    if not RENDER_API_KEY:
        logger.error("A Render API-kulcs nincs beállítva; az állapotellenőrzés nem futtatható.")
        return
    logger.info("Adatbázis-állapot ellenőrzése indul.")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{RENDER_API_URL}/postgres", headers=HEADERS)
            if response.status_code == 200:
                db_list = response.json()
                logger.info("Az állapotlekérdezés sikeres; %s adatbázis található.", len(db_list))
                for database in db_list:
                    db_info = database.get("postgres", {})
                    logger.info(
                        "Adatbázis állapota: név=%s, állapot=%s.",
                        db_info.get("name"),
                        db_info.get("status"),
                    )
            else:
                logger.error("Az állapotlekérdezés sikertelen (HTTP %s).", response.status_code)
        except Exception as exc:
            _log_exception("Hálózati hiba történt az állapotellenőrzés során", exc)


async def main():
    """Start periodic read-only database status checks."""
    logger.info("Levendula karbantartó rendszer indul.")
    create_backup()

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        check_database_status, "interval", minutes=CHECK_INTERVAL_MINUTES
    )
    scheduler.start()
    logger.info(
        "Időzítő elindítva; első állapotellenőrzés %s perc múlva. Leállítás: Ctrl+C.",
        CHECK_INTERVAL_MINUTES,
    )
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        scheduler.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Levendula adatbázis-karbantartó")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Kizárólag állapotellenőrzés, adatbázis-módosítás nélkül.",
    )
    args = parser.parse_args()
    try:
        asyncio.run(check_database_status() if args.check_only else main())
    except KeyboardInterrupt:
        logger.info("A karbantartó leállítása kérve.")
