"""Biztonságos Render-adatbázis-ellenőrző, mentő és cserélő segédprogram."""

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Konfiguráció, naplózás és titokszűrés
# A karbantartó segédprogram kizárólag a folyamatnak átadott
# környezeti változókat használhatja.
os.environ["PYTHON_DOTENV_DISABLED"] = "true"

from Backend.database import Base, SessionLocal  # noqa: E402
from Backend.models import SecurityEvent  # noqa: E402
from Backend.security_engine import SecurityRuleEngine  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

RENDER_API_URL = "https://api.render.com/v1"
STATE_PATH = Path(__file__).with_name("rotation_state.json")
LOCK_PATH = Path(__file__).with_name("rotation.lock")
REQUEST_TIMEOUT = 15.0
MAX_RETRIES = 3
POLL_INTERVAL_SECONDS = 5
ROTATION_TIMEOUT_SECONDS = 600


# Hiba- és Render API-kezelés
class RotationError(RuntimeError):
    """Biztonságosan megjeleníthető rotációs hiba.

    Nem tartalmaz válaszadatokból származó titkokat.
    """


class RenderAPI:
    """Titokszűrt, újrapróbálkozó aszinkron kliens a Render API-hoz."""

    def __init__(self, api_key, client=None):
        """Létrehozza a hitelesített Render API-klienst."""
        if not api_key:
            raise RotationError("A Render API-kulcs nincs konfigurálva.")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        }
        self.client = client

    async def request(self, method, path, *, json_body=None, allow_statuses=()):
        """Kérést küld, és kezeli a hibákat, illetve az ismétlést."""
        retryable = not (method.upper() == "POST" and path == "/postgres")
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                response = await self.client.request(
                    method,
                    f"{RENDER_API_URL}{path}",
                    headers=self.headers,
                    json=json_body,
                    timeout=REQUEST_TIMEOUT,
                )
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt + 1 == MAX_RETRIES or not retryable:
                    raise RotationError("A Render API-kérés időtúllépés miatt sikertelen.") from None
                # Az ismételhető kérések növekvő várakozással ismétlődnek.
                await asyncio.sleep(2**attempt)
                continue
            except httpx.RequestError as exc:
                last_error = exc
                if attempt + 1 == MAX_RETRIES or not retryable:
                    raise RotationError("Hálózati hiba történt a Render API elérésekor.") from None
                await asyncio.sleep(2**attempt)
                continue

            if response.status_code in allow_statuses:
                return response
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if (response.status_code == 429 or retryable) and attempt + 1 < MAX_RETRIES:
                    # A szerver Retry-After értéke legfeljebb 10 másodperc.
                    retry_after = response.headers.get("Retry-After")
                    try:
                        delay = min(max(float(retry_after), 0), 10) if retry_after else 2**attempt
                    except ValueError:
                        delay = 2**attempt
                    await asyncio.sleep(delay)
                    continue
            if response.status_code in (401, 403):
                raise RotationError(f"A Render API hozzáférést megtagadta (HTTP {response.status_code}).")
            if response.status_code in (402, 409, 422):
                raise RotationError(
                    f"A Render API kvóta-, terv- vagy konfigurációs hibát jelzett (HTTP {response.status_code}); "
                    "fizetős csomagra váltás nem történik."
                )
            if response.status_code >= 400:
                raise RotationError(f"A Render API-kérés sikertelen (HTTP {response.status_code}).")
            return response

        raise RotationError("A Render API-kérés az újrapróbálkozások után sem sikerült.") from last_error


# Időbélyegek, rekordok és biztonsági mentések
def _utc_now():
    """Visszaadja az aktuális időpontot UTC-időzónában."""
    return datetime.now(timezone.utc)


def _parse_utc(value):
    """ISO-formátumú értéket alakít UTC-időponttá, különben None-t ad."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _as_utc_timestamp(value):
    """A mentésben használt időbélyeget egységes UTC-formára alakítja."""
    parsed = _parse_utc(value)
    if parsed:
        return parsed.isoformat().replace("+00:00", "Z")
    for pattern in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            parsed = datetime.strptime(value, pattern).astimezone(timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z")
        except (TypeError, ValueError):
            continue
    return value


def _event_dict(event):
    """Az adatbázis-eseményt menthető, normalizált szótárrá alakítja."""
    return {
        "id": event.id,
        "ip_address": event.ip_address,
        "timestamp": _as_utc_timestamp(event.timestamp),
        "http_method": event.http_method,
        "request_url": event.request_url,
        "status_code": event.status_code,
        "severity": event.severity,
        "reason": event.reason,
    }


def _read_backup(backup_path):
    """Beolvassa és ellenőrzi a mentés metaadatait és rekordjait."""
    with open(backup_path, "r", encoding="utf-8") as backup_file:
        payload = json.load(backup_file)
    if isinstance(payload, list):
        events = payload
        metadata = {"record_count": len(events)}
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = payload["events"]
        metadata = payload.get("metadata", {})
    else:
        raise RotationError("A mentés formátuma érvénytelen.")
    if metadata.get("record_count") != len(events):
        raise RotationError("A mentés metaadata és rekordszáma nem egyezik.")
    required_fields = {
        "id", "ip_address", "timestamp", "http_method", "request_url",
        "status_code", "severity", "reason",
    }
    if any(not isinstance(item, dict) or not required_fields.issubset(item) for item in events):
        raise RotationError("A mentés egy vagy több rekordja hiányos.")
    normalized_events = []
    for item in events:
        normalized_events.append(
            {
                "id": int(item["id"]),
                "ip_address": item["ip_address"],
                "timestamp": _as_utc_timestamp(item["timestamp"]),
                "http_method": item["http_method"],
                "request_url": item["request_url"],
                "status_code": int(item["status_code"]),
                "severity": item["severity"],
                "reason": item["reason"],
            }
        )
    return metadata, normalized_events


def create_backup(source_db_id=None, backup_dir=None):
    """Teljes, metaadatokat tartalmazó pillanatkép készítése.

    A rekordadatokat nem naplózza.
    """
    directory = Path(backup_dir or os.getenv("BACKUP_DIR", Path(__file__).parent / "backups"))
    directory.mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        records = db.query(SecurityEvent).order_by(SecurityEvent.id.asc()).all()
        events = [_event_dict(event) for event in records]
    finally:
        db.close()
    metadata = {
        "created_at_utc": _utc_now().isoformat().replace("+00:00", "Z"),
        "source_db_id": source_db_id or os.getenv("RENDER_DB_ID"),
        "record_count": len(events),
    }
    path = directory / f"backup_{_utc_now().strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}.json"
    temporary_path = path.with_suffix(".tmp")
    with open(temporary_path, "w", encoding="utf-8") as backup_file:
        json.dump({"metadata": metadata, "events": events}, backup_file, ensure_ascii=False, indent=2)
        backup_file.flush()
        os.fsync(backup_file.fileno())
    os.replace(temporary_path, path)
    logger.info("Mentés elkészült: %s rekord; fájl=%s.", len(events), path.name)
    return path


def restore_backup(backup_path, new_db_url):
    """Séma létrehozása és típushelyes rekordok visszaállítása.

    A PostgreSQL-szekvenciát is összehangolja.
    """
    metadata, events = _read_backup(backup_path)
    target_engine = create_engine(
        new_db_url,
        connect_args={"check_same_thread": False} if new_db_url.startswith("sqlite") else {},
    )
    db = None
    try:
        Base.metadata.create_all(bind=target_engine)
        target_session = sessionmaker(autocommit=False, autoflush=False, bind=target_engine)
        db = target_session()
        existing_rows = db.query(SecurityEvent).order_by(SecurityEvent.id.asc()).all()
        if existing_rows:
            if [_event_dict(row) for row in existing_rows] != events:
                raise RotationError(
                    "A céladatbázis nem üres, és nem egyezik a mentéssel; biztonságos folytatás leállítva."
                )
            logger.info("A mentés már vissza van állítva; a meglévő rekordok megmaradnak.")
        else:
            for item in events:
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
        if target_engine.dialect.name == "postgresql":
            # A PostgreSQL-szekvenciát a legnagyobb ID-hoz igazítjuk.
            db.execute(
                text(
                    "SELECT setval(pg_get_serial_sequence('security_events', 'id'), "
                    "COALESCE((SELECT MAX(id) FROM security_events), 1), true)"
                )
            )
            db.commit()
        logger.info("Visszaállítás befejeződött: %s rekord.", metadata["record_count"])
        return True
    except Exception:
        if db is not None:
            db.rollback()
        raise
    finally:
        if db is not None:
            db.close()
        target_engine.dispose()


def verify_restored_data(backup_path, database_url):
    """Ellenőrzi a visszaállított mezőket és a szabálymotor eredményét."""
    _, expected = _read_backup(backup_path)
    verify_engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
    )
    verify_session = sessionmaker(bind=verify_engine)
    try:
        with verify_session() as db:
            actual_rows = db.query(SecurityEvent).order_by(SecurityEvent.id.asc()).all()
            actual = [_event_dict(row) for row in actual_rows]
        if actual != expected:
            logger.error("A visszaállított rekordok mezői nem egyeznek a mentéssel.")
            return False
        rule_engine = SecurityRuleEngine()
        for record in actual:
            evaluated = rule_engine.evaluate_request(
                {
                    "ip": record["ip_address"],
                    "timestamp": record["timestamp"],
                    "method": record["http_method"],
                    "url": record["request_url"],
                    "status": record["status_code"],
                }
            )
            # A jelenlegi séma a `reason` mezőben tárolja az esemény típusát.
            if evaluated["severity"] != record["severity"] or evaluated["reason"] != record["reason"]:
                logger.error("A visszaállított rekord szabálymotor-eredménye eltér a tárolt értéktől.")
                return False
        return True
    finally:
        verify_engine.dispose()


# Zárolás és tartós állapotfájl-kezelés
def _load_state():
    """Beolvassa és ellenőrzi a rotáció állapotfájlját."""
    if not STATE_PATH.exists():
        return {}
    with open(STATE_PATH, "r", encoding="utf-8") as state_file:
        state = json.load(state_file)
    if not isinstance(state, dict):
        raise RotationError("A rotációs állapotfájl sérült; kézi ellenőrzés szükséges.")
    return state


def _save_state(state):
    """Atomi fájlcserével, tartósan menti a rotáció aktuális állapotát."""
    temporary_path = STATE_PATH.with_suffix(".tmp")
    with open(temporary_path, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file, ensure_ascii=False, indent=2)
        state_file.flush()
        os.fsync(state_file.fileno())
    os.replace(temporary_path, STATE_PATH)


def _pid_is_running(pid):
    """Megállapítja, hogy fut-e folyamat a megadott folyamatazonosítóval."""
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _acquire_lock():
    """Kizárólagos zárolást szerez, és eltávolítja a beragadt zárolást."""
    if LOCK_PATH.exists():
        try:
            with open(LOCK_PATH, "r", encoding="utf-8") as lock_file:
                lock = json.load(lock_file)
        except (OSError, json.JSONDecodeError):
            raise RotationError("A rotációs zárolófájl nem olvasható; kézi ellenőrzés szükséges.")
        if _pid_is_running(lock.get("pid")):
            raise RotationError("Másik adatbázis-csere már fut.")
        LOCK_PATH.unlink()
    try:
        descriptor = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise RotationError("Másik adatbázis-csere már fut.") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as lock_file:
        json.dump({"pid": os.getpid(), "started_at_utc": _utc_now().isoformat()}, lock_file)


def _release_lock():
    """Eltávolítja a saját folyamathoz tartozó zárolófájlt."""
    try:
        with open(LOCK_PATH, "r", encoding="utf-8") as lock_file:
            lock = json.load(lock_file)
        if lock.get("pid") == os.getpid():
            LOCK_PATH.unlink(missing_ok=True)
    except (OSError, json.JSONDecodeError):
        logger.error("A rotációs zárolófájl nem távolítható el; kézi ellenőrzés szükséges.")


# Konfiguráció és adatbázis-kapcsolatok ellenőrzése
def _require_config(name):
    """Lekéri a kötelező környezeti beállítást, vagy érthető hibát jelez."""
    value = os.getenv(name)
    if not value:
        raise RotationError(f"Hiányzó konfiguráció: {name}.")
    return value


def _backup_directory():
    """Létrehozza és íráspróbával ellenőrzi a mentési könyvtárat."""
    path = Path(os.getenv("BACKUP_DIR", Path(__file__).parent / "backups"))
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RotationError("A mentési útvonal nem könyvtár.")
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix=".rotation-check-", delete=True):
            pass
    except OSError:
        raise RotationError("A mentési könyvtár nem írható.") from None
    return path


def _verify_source_database_connection():
    """Ellenőrzi, hogy a forrás-adatbázis lekérdezhető-e."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise RotationError(
            f"A forrás adatbázis nem érhető el ({type(exc).__name__}); normál rotáció nem indul."
        ) from None
    finally:
        db.close()


def _database_entries(payload):
    """Egységesíti a Render adatbázis-listájának válaszelemeit."""
    if not isinstance(payload, list):
        raise RotationError("A Render adatbázis-lista válasza érvénytelen.")
    return [entry.get("postgres", entry) for entry in payload if isinstance(entry, dict)]


async def _list_databases(api):
    """Lekéri a Render-fiók adatbázisainak listáját."""
    response = await api.request("GET", "/postgres")
    return _database_entries(response.json())


async def _find_database(api, database_id):
    """Azonosító alapján megkeresi az adatbázist a Render listájában."""
    databases = await _list_databases(api)
    return next((entry for entry in databases if entry.get("id") == database_id), None)


def _extract_env_variables(payload):
    """A Render válaszából kulcs-érték szótárat készít."""
    items = payload.get("envVars", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise RotationError("A backend környezeti változóinak válasza érvénytelen.")
    variables = {}
    for item in items:
        item = item.get("envVar", item) if isinstance(item, dict) else {}
        if "key" not in item or "value" not in item:
            raise RotationError("A Render nem adott vissza minden környezeti változóértéket; frissítés megszakítva.")
        variables[item["key"]] = item["value"]
    return variables


# Állapotellenőrzés és aszinkron Render-műveletek
async def check_database_status():
    """Lekéri és naplózza az adatbázisok állapotát és tervezett dátumait."""
    api_key = os.getenv("RENDER_API_KEY")
    if not api_key:
        logger.error("A Render API-kulcs nincs beállítva; az állapotellenőrzés nem futtatható.")
        return None
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        api = RenderAPI(api_key, client)
        databases = await _list_databases(api)
    if not databases:
        logger.info("A Render-fiókban nem található adatbázis; csere nem indul.")
        return []
    now = _utc_now()
    for database in databases:
        expires_at = _parse_utc(database.get("expiresAt") or database.get("expirationDate"))
        maintenance_at = _parse_utc(database.get("maintenanceAt") or database.get("scheduledMaintenanceAt"))
        logger.info(
            "Adatbázis-állapot: azonosító=%s, állapot=%s, lejárat_utc=%s, karbantartás_utc=%s.",
            database.get("id", "ismeretlen"),
            database.get("status", "ismeretlen"),
            expires_at.isoformat() if expires_at else "nincs",
            maintenance_at.isoformat() if maintenance_at else "nincs",
        )
        if expires_at and expires_at <= now:
            logger.warning("Az adatbázis lejárati időpontja elmúlt; automatikus csere nem indul.")
        if maintenance_at and maintenance_at <= now:
            logger.warning("A tervezett karbantartási időpont elérkezett; automatikus csere nem indul.")
    return databases


async def _set_backend_maintenance(api, service_id, backend_url, token, enabled):
    """A backend karbantartási módját és a Render-beállítást is módosítja."""
    headers = {"X-Maintenance-Token": token}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            f"{backend_url.rstrip('/')}/api/admin/maintenance",
            headers=headers,
            json={"enabled": enabled},
        )
    if response.status_code != 200:
        raise RotationError(f"A backend karbantartási módja nem állítható (HTTP {response.status_code}).")

    env_response = await api.request("GET", f"/services/{service_id}/env-vars")
    variables = _extract_env_variables(env_response.json())
    variables["MAINTENANCE_MODE"] = "true" if enabled else "false"
    await api.request(
        "PUT",
        f"/services/{service_id}/env-vars",
        json_body=[{"key": key, "value": value} for key, value in variables.items()],
    )
    return variables


async def _start_deploy(api, service_id):
    """Elindítja a backend telepítését, és visszaadja annak azonosítóját."""
    response = await api.request(
        "POST",
        f"/services/{service_id}/deploys",
        json_body={"clearCache": "do_not_clear"},
    )
    data = response.json()
    deploy_id = data.get("id") or data.get("deploy", {}).get("id")
    if not deploy_id:
        raise RotationError("A Render telepítési azonosítója hiányzik.")
    return deploy_id


async def _wait_for_deploy(api, service_id, deploy_id):
    """A megadott telepítés sikeres éles állapotáig vár, határidővel."""
    deadline = time.monotonic() + ROTATION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await api.request("GET", f"/services/{service_id}/deploys/{deploy_id}")
        state = response.json().get("status")
        if state == " live " or state == "live":
            return
        if state in {"build_failed", "update_failed", "canceled", "deactivated"}:
            raise RotationError(f"A backend telepítése sikertelen (állapot: {state.strip()}).")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RotationError("A backend telepítésének várakozási ideje lejárt.")


async def _restore_maintenance_mode(api, service_id, backend_url, token):
    """Hiba esetén bekapcsolja a karbantartást a backendben és a Renderben."""
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            f"{backend_url.rstrip('/')}/api/admin/maintenance",
            headers={"X-Maintenance-Token": token},
            json={"enabled": True},
        )
    if response.status_code != 200:
        raise RotationError("A backend nem erősítette meg a karbantartási mód visszaállítását.")
    env_response = await api.request("GET", f"/services/{service_id}/env-vars")
    variables = _extract_env_variables(env_response.json())
    variables["MAINTENANCE_MODE"] = "true"
    await api.request(
        "PUT",
        f"/services/{service_id}/env-vars",
        json_body=[{"key": key, "value": value} for key, value in variables.items()],
    )
    deploy_id = await _start_deploy(api, service_id)
    await _wait_for_deploy(api, service_id, deploy_id)
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            f"{backend_url.rstrip('/')}/api/admin/maintenance",
            headers={"X-Maintenance-Token": token},
            json={"enabled": True},
        )
    if response.status_code != 200:
        raise RotationError("A backend nem erősítette meg a karbantartási mód visszaállítását.")


async def _wait_database_deleted(api, database_id):
    """Megvárja a régi adatbázis törlését vagy inaktívvá válását."""
    deadline = time.monotonic() + ROTATION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await api.request(
            "GET", f"/postgres/{database_id}", allow_statuses=(404,)
        )
        if response.status_code == 404:
            return
        state = response.json().get("status")
        if state in {"deleted", "deactivated"}:
            return
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RotationError("A régi adatbázis törlésének várakozási ideje lejárt.")


async def _create_or_recover_database(api, state, owner_id, plan, region, postgres_version):
    """Létrehozza, vagy azonosítja a már korábban létrehozott adatbázist."""
    if state.get("new_db_id"):
        return state["new_db_id"], state.get("new_db_details", {})
    name = state.get("new_db_name")
    if not name:
        name = f"levendula-db-{_utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        state["new_db_name"] = name
        state["phase"] = "creating_database"
        _save_state(state)
    else:
        # A mentett nevet keressük, hogy folytatáskor ne jöjjön létre másolat.
        matching = [item for item in await _list_databases(api) if item.get("name") == name]
        if len(matching) == 1 and matching[0].get("id"):
            state["new_db_id"] = matching[0]["id"]
            state["phase"] = "database_created"
            _save_state(state)
            return state["new_db_id"], matching[0]
        if len(matching) > 1:
            raise RotationError("A mentett adatbázisnévhez több példány tartozik; automatikus folytatás leállítva.")
        if state.get("phase") == "creating_database":
            raise RotationError("A korábbi létrehozás eredménye bizonytalan; duplikáció elkerülése miatt leállítva.")

    try:
        response = await api.request(
            "POST",
            "/postgres",
            json_body={
                "name": name,
                "ownerId": owner_id,
                "plan": plan,
                "region": region,
                "postgresVersion": postgres_version,
            },
        )
    except RotationError as exc:
        if not (
            "időtúllépés" in str(exc)
            or "Hálózati hiba" in str(exc)
            or "HTTP 5" in str(exc)
        ):
            raise
        matching = [item for item in await _list_databases(api) if item.get("name") == name]
        if len(matching) != 1 or not matching[0].get("id"):
            raise RotationError("A létrehozási kérés eredménye bizonytalan; további példány nem jön létre.") from None
        database = matching[0]
    else:
        database_payload = response.json()
        database = database_payload.get("postgres", database_payload)
        if not database.get("id"):
            raise RotationError("A Render nem adott vissza azonosítót az új adatbázishoz.")
    state["new_db_id"] = database["id"]
    state["new_db_details"] = {
        "name": database.get("name", name),
        "status": database.get("status"),
    }
    state["phase"] = "database_created"
    _save_state(state)
    return state["new_db_id"], database


async def _wait_database_available(api, database_id):
    """Megvárja az új adatbázis elérhetőségét, és jelzi a hibás állapotot."""
    deadline = time.monotonic() + ROTATION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await api.request("GET", f"/postgres/{database_id}")
        data = response.json()
        database = data.get("postgres", data)
        if database.get("status") == "available":
            return database
        if database.get("status") in {"failed", "deleted", "deactivated"}:
            raise RotationError("Az új adatbázis nem vált elérhetővé.")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RotationError("Az új adatbázis elérhetővé válásának várakozási ideje lejárt.")


def _connection_strings(database):
    """Ellenőrzi és egységesíti az adatbázis kapcsolati URL-jeit."""
    connection_info = database.get("connectionInfo", {})
    internal_url = connection_info.get("internalConnectionString")
    external_url = connection_info.get("externalConnectionString") or internal_url
    if not internal_url or not external_url:
        raise RotationError("Az új adatbázis kapcsolati adatai hiányoznak.")
    return (
        internal_url.replace("postgres://", "postgresql://", 1),
        external_url.replace("postgres://", "postgresql://", 1),
    )


def _verify_backup_locally(backup_path):
    """Ideiglenes SQLite-adatbázisba állítja vissza és ellenőrzi a mentést."""
    with tempfile.TemporaryDirectory(prefix="levendula-rotation-") as directory:
        db_path = Path(directory) / "restore_check.sqlite"
        sqlite_url = "sqlite:///" + db_path.as_posix()
        restore_backup(backup_path, sqlite_url)
        if not verify_restored_data(backup_path, sqlite_url):
            raise RotationError("A helyi SQLite visszaállítás tartalmi ellenőrzése sikertelen.")


async def _verify_live_backend(backend_url, token, backup_path):
    """Ellenőrzi az éles adatok egyezését és az írási végpontok működését."""
    _, expected = _read_backup(backup_path)
    headers = {"X-Maintenance-Token": token}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{backend_url.rstrip('/')}/api/events",
            params={"limit": max(100, len(expected) + 1)},
        )
        if response.status_code == 404 and not expected:
            actual = []
        elif response.status_code != 200:
            raise RotationError(f"A backend esemény-olvasása sikertelen (HTTP {response.status_code}).")
        else:
            actual = response.json()
    actual = sorted(actual, key=lambda event: event.get("id", 0))
    expected = sorted(expected, key=lambda event: event["id"])
    if actual != expected:
        raise RotationError("Az éles backend eseményei nem egyeznek a végső mentéssel.")
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        probe = await client.post(
            f"{backend_url.rstrip('/')}/api/admin/probe-write", headers=headers
        )
        if probe.status_code != 200 or probe.json().get("writable") is not True:
            raise RotationError(f"A védett próbaírás sikertelen (HTTP {probe.status_code}).")
        import_response = await client.post(
            f"{backend_url.rstrip('/')}/api/logs/import",
            json={"logs": ['192.0.2.1 - - [10/Sep/2026:16:05:12 +0000] "GET /maintenance-check HTTP/1.1" 200 1']},
        )
        if import_response.status_code != 503:
            raise RotationError(
                f"A normál írási végpont nem utasította el a kérést karbantartás alatt "
                f"(HTTP {import_response.status_code})."
            )


# Ötlépéses adatbázis-csere és vészhelyzeti helyreállítás
async def perform_database_rotation(
    *, source_db_id=None, allow_delete=None, recover_from_backup=None, allow_recovery=False, resume=False
):
    """Végrehajtja az engedélyezett, tartós állapotú adatbáziscserét."""
    _acquire_lock()
    try:
        api_key = _require_config("RENDER_API_KEY")
        service_id = _require_config("RENDER_WEB_SERVICE_ID")
        owner_id = _require_config("RENDER_OWNER_ID")
        plan = _require_config("RENDER_DB_PLAN").lower()
        region = _require_config("RENDER_DB_REGION")
        postgres_version = _require_config("RENDER_POSTGRES_VERSION")
        backend_url = _require_config("BACKEND_BASE_URL")
        maintenance_token = _require_config("MAINTENANCE_TOKEN")
        if plan != "free":
            raise RotationError("A biztonságos csere kizárólag kifejezetten megadott Free tervvel engedélyezett.")
        backup_dir = _backup_directory()
        source_db_id = source_db_id or os.getenv("RENDER_DB_ID")
        if not source_db_id:
            raise RotationError("Hiányzik a forrás adatbázis azonosítója (RENDER_DB_ID vagy --source-db-id).")
        recovering = recover_from_backup is not None
        if recovering and not allow_recovery:
            raise RotationError("Mentésből helyreállításhoz a --allow-recovery engedély is szükséges.")
        if recovering and not Path(recover_from_backup).is_file():
            raise RotationError("A megadott helyreállítási mentés nem létezik.")

        state = _load_state()
        if state and not resume:
            raise RotationError("Meglévő rotációs állapot található; a biztonságos folytatáshoz használd a --resume kapcsolót.")
        if resume and not state:
            raise RotationError("Nincs folytatható rotációs állapot.")
        if state and state.get("recovery_mode"):
            if not allow_recovery:
                raise RotationError("A mentésből indított rotáció folytatásához is --allow-recovery szükséges.")
            recovering = True
            recover_from_backup = recover_from_backup or state.get("backup_path")
        if not recovering and allow_delete != source_db_id:
            if not (resume and state.get("delete_authorized_for") == source_db_id):
                raise RotationError("A régi adatbázis törléséhez --allow-delete <azonosító> szükséges.")
        if state and state.get("source_db_id") != source_db_id:
            raise RotationError("Az állapotfájl forrásazonosítója eltér a megadott forrástól.")
        if state.get("phase") == "complete":
            logger.info("A mentett adatbázis-csere már befejeződött.")
            return
        if not state:
            state = {
                "run_id": uuid.uuid4().hex,
                "source_db_id": source_db_id,
                "started_at_utc": _utc_now().isoformat(),
                "phase": "preflight",
                "recovery_mode": recovering,
                "delete_authorized_for": source_db_id if allow_delete == source_db_id else None,
            }
            _save_state(state)

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            api = RenderAPI(api_key, client)
            current_source = await _find_database(api, source_db_id)
            phase = state.get("phase")
            source_may_be_deleted = state.get("delete_requested") or phase in {
                "locally_verified", "old_deleted", "creating_database", "database_created",
                "database_restored", "deploying_backend", "backend_deployed", "verified",
            }
            if phase == "locally_verified" and not state.get("delete_requested"):
                source_may_be_deleted = False
            if not recovering and current_source is None and not source_may_be_deleted:
                raise RotationError("A forrás adatbázis nem található Renderben.")
            if (
                not recovering
                and current_source is not None
                and current_source.get("status") != "available"
                and not source_may_be_deleted
            ):
                raise RotationError("A forrás adatbázis nem elérhető; cserét csak ellenőrzött mentésből lehet végezni.")
            if not recovering and phase in {"preflight", "preflight_complete"}:
                _verify_source_database_connection()
            if state.get("phase") == "preflight":
                state["phase"] = "preflight_complete"
                _save_state(state)

            if state.get("phase") not in {"backup_complete", "locally_verified", "old_deleted", "database_created", "database_restored", "backend_deployed", "verified"}:
                await _set_backend_maintenance(api, service_id, backend_url, maintenance_token, True)
                os.environ["MAINTENANCE_MODE"] = "true"
                if recovering:
                    metadata, _ = _read_backup(recover_from_backup)
                    state["backup_path"] = str(Path(recover_from_backup).resolve())
                    logger.warning(
                        "Helyreállítás régi mentésből (%s); azóta keletkezett változások hiányozhatnak.",
                        metadata.get("created_at_utc", "ismeretlen időpont"),
                    )
                else:
                    state["backup_path"] = str(create_backup(source_db_id, backup_dir))
                state["phase"] = "backup_complete"
                _save_state(state)

            backup_path = Path(state["backup_path"])
            if not backup_path.is_file():
                raise RotationError("A rotációhoz szükséges mentés hiányzik.")
            _read_backup(backup_path)
            if state["phase"] == "backup_complete":
                # A mentést helyileg állítjuk vissza és ellenőrizzük, mielőtt
                # a forrás-adatbázis törölhetővé válik.
                _verify_backup_locally(backup_path)
                state["phase"] = "locally_verified"
                _save_state(state)

            if state["phase"] == "locally_verified":
                if not recovering:
                    if allow_delete != source_db_id:
                        raise RotationError("A törlési engedély nem egyezik a forrás adatbázis ID-jával.")
                    state["delete_requested"] = True
                    _save_state(state)
                    await api.request("DELETE", f"/postgres/{source_db_id}", allow_statuses=(404,))
                    await _wait_database_deleted(api, source_db_id)
                state["phase"] = "old_deleted"
                _save_state(state)

            if state["phase"] in {"old_deleted", "creating_database"}:
                new_db_id, _ = await _create_or_recover_database(
                    api, state, owner_id, plan, region, postgres_version
                )
                state["new_db_id"] = new_db_id
                database = await _wait_database_available(api, new_db_id)
                internal_url, external_url = _connection_strings(database)
                state["phase"] = "database_created"
                _save_state(state)
            elif state["phase"] in {"database_created", "database_restored", "backend_deployed", "verified"}:
                new_db_id = state["new_db_id"]
                database = await _wait_database_available(api, new_db_id)
                internal_url, external_url = _connection_strings(database)

            if state["phase"] == "database_created":
                restore_backup(backup_path, external_url)
                if not verify_restored_data(backup_path, external_url):
                    raise RotationError("Az új adatbázis visszaállított adatainak ellenőrzése sikertelen.")
                state["phase"] = "database_restored"
                _save_state(state)

            if state["phase"] == "database_restored":
                env_response = await api.request("GET", f"/services/{service_id}/env-vars")
                variables = _extract_env_variables(env_response.json())
                variables["DATABASE_URL"] = internal_url
                variables["MAINTENANCE_MODE"] = "true"
                await api.request(
                    "PUT",
                    f"/services/{service_id}/env-vars",
                    json_body=[{"key": key, "value": value} for key, value in variables.items()],
                )
                deploy_id = await _start_deploy(api, service_id)
                state["deploy_id"] = deploy_id
                state["phase"] = "deploying_backend"
                _save_state(state)
                await _wait_for_deploy(api, service_id, deploy_id)
                state["phase"] = "backend_deployed"
                _save_state(state)

            if state["phase"] == "deploying_backend":
                await _wait_for_deploy(api, service_id, state["deploy_id"])
                state["phase"] = "backend_deployed"
                _save_state(state)

            if state["phase"] == "backend_deployed":
                await _verify_live_backend(backend_url, maintenance_token, backup_path)
                state["phase"] = "verified"
                state["active_db_id"] = state["new_db_id"]
                _save_state(state)

            if state["phase"] == "verified":
                try:
                    final_env_response = await api.request(
                        "GET", f"/services/{service_id}/env-vars"
                    )
                    final_variables = _extract_env_variables(final_env_response.json())
                    final_variables["DATABASE_URL"] = internal_url
                    final_variables["MAINTENANCE_MODE"] = "false"
                    await api.request(
                        "PUT",
                        f"/services/{service_id}/env-vars",
                        json_body=[
                            {"key": key, "value": value}
                            for key, value in final_variables.items()
                        ],
                    )
                    final_deploy_id = await _start_deploy(api, service_id)
                    await _wait_for_deploy(api, service_id, final_deploy_id)
                    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as backend_client:
                        response = await backend_client.post(
                            f"{backend_url.rstrip('/')}/api/admin/maintenance",
                            headers={"X-Maintenance-Token": maintenance_token},
                            json={"enabled": False},
                        )
                    if response.status_code != 200:
                        raise RotationError("Az ellenőrzések után a karbantartási mód nem kapcsolható ki.")
                    os.environ["MAINTENANCE_MODE"] = "false"
                    state["phase"] = "complete"
                    state["completed_at_utc"] = _utc_now().isoformat()
                    _save_state(state)
                except Exception as exc:
                    # Hiba esetén a karbantartás aktív marad a helyreállítás
                    # sikeres ellenőrzéséig.
                    try:
                        await _restore_maintenance_mode(
                            api, service_id, backend_url, maintenance_token
                        )
                    except Exception as recovery_exc:
                        logger.error(
                            "A karbantartási mód visszaállítása is hibás (%s).",
                            type(recovery_exc).__name__,
                        )
                    os.environ["MAINTENANCE_MODE"] = "true"
                    raise RotationError(
                        f"A rotáció záró lépése hibás ({type(exc).__name__}); "
                        "a karbantartási mód visszaállítása megkísérelve."
                    ) from None
                logger.info("Adatbázis-csere befejeződött; aktív adatbázis ID rögzítve.")
    finally:
        _release_lock()


# CLI-vezérlés és ütemezett állapotellenőrzés
async def _run_schedule():
    """A konfigurált időközönként, csak olvasással ellenőrzi az állapotot."""
    try:
        interval = max(1, int(os.getenv("CHECK_INTERVAL_MINUTES", "1")))
    except ValueError:
        raise RotationError("A CHECK_INTERVAL_MINUTES csak pozitív egész lehet.") from None
    while True:
        await check_database_status()
        await asyncio.sleep(interval * 60)


def _parse_args():
    """Létrehozza és beolvassa a parancssori kapcsolókat."""
    parser = argparse.ArgumentParser(description="Levendula adatbázis-karbantartó")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-only", action="store_true", help="Csak állapotellenőrzés; nem módosít.")
    mode.add_argument("--schedule", action="store_true", help="Ismételt, kizárólag olvasó állapotellenőrzés.")
    mode.add_argument("--rotate", action="store_true", help="Engedélyezett adatbázis-csere végrehajtása.")
    parser.add_argument("--allow-delete", nargs="?", const="__SOURCE_DB_ID__", help="Törlés engedélyezése pontos forrás ID-ra.")
    parser.add_argument("--source-db-id", help="A cserélendő forrás adatbázis ID-ja.")
    parser.add_argument("--recover-from-backup", help="Helyreállítás létező JSON mentésből.")
    parser.add_argument("--allow-recovery", action="store_true", help="Kifejezett engedély offline forrás mentésből helyreállítására.")
    parser.add_argument("--resume", action="store_true", help="Meglévő, tartós rotációs állapot folytatása.")
    return parser.parse_args()


async def _main(args):
    """A parancssori mód alapján ellenőrzést, ütemezést vagy cserét indít."""
    if args.check_only and (args.resume or args.recover_from_backup or args.allow_delete):
        raise RotationError("A --check-only nem kombinálható rotációs vagy helyreállítási kapcsolóval.")
    if args.schedule and (args.resume or args.recover_from_backup or args.allow_delete):
        raise RotationError("A --schedule kizárólag állapotellenőrzésre használható.")
    if args.rotate or args.resume or args.recover_from_backup:
        delete_id = args.allow_delete
        if delete_id == "__SOURCE_DB_ID__":
            delete_id = args.source_db_id or os.getenv("RENDER_DB_ID")
        if args.recover_from_backup and not args.allow_recovery:
            raise RotationError("--recover-from-backup mellé --allow-recovery szükséges.")
        if not args.recover_from_backup and not args.resume and not args.allow_delete:
            raise RotationError("Rotációhoz kifejezett --allow-delete <forrás-ID> szükséges.")
        await perform_database_rotation(
            source_db_id=args.source_db_id,
            allow_delete=delete_id,
            recover_from_backup=args.recover_from_backup,
            allow_recovery=args.allow_recovery,
            resume=args.resume,
        )
    elif args.schedule:
        await _run_schedule()
    else:
        await check_database_status()


if __name__ == "__main__":
    try:
        asyncio.run(_main(_parse_args()))
    except KeyboardInterrupt:
        logger.info("A karbantartó leállítása kérve.")
    except RotationError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("A karbantartó művelet váratlan hibával leállt (%s).", type(exc).__name__)
        sys.exit(1)
