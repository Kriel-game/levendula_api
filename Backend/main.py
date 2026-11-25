from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
import logging
from typing import NoReturn
import hmac
import os
from fastapi import Header
from pydantic import BaseModel

from Backend.database import SessionLocal, engine
from Backend import models
from Backend import schemas
from Backend.parse_log_line import parse_log_line
from Backend.security_engine import SecurityRuleEngine

# =====================================================================
# FASTAPI BACKEND SZERVER ÉS REST API VÉGPONTOK
# Szerepe: A rendszer központi vezérlőrétege. Fogadja a kliensek (Streamlit
# dashboard, Android alkalmazás, Swagger UI) HTTP kéréseit, összehangolja a
# logelemző és a biztonsági motor munkáját, valamint kezeli az adatbázist.
# =====================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Adatbázis-indítás és FastAPI-alkalmazás
# Alkalmazás indulásakor automatikusan létrehozza a 'security_events' táblát
# az adatbázisban, amennyiben az még nem létezik.
try:
    models.Base.metadata.create_all(bind=engine)
except SQLAlchemyError as exc:
    logger.exception(
        "Database initialization failed (%s)",
        type(exc).__name__,
        exc_info=(type(exc), Exception(type(exc).__name__), exc.__traceback__),
    )
    raise

app = FastAPI(title="Levendula Vendégház Biztonsági API")
maintenance_mode = os.getenv("MAINTENANCE_MODE", "").strip().lower() in {"true", "1"}

# Példányosítjuk az OOP szabálymotort, amely a kérések kiértékelését végzi
sec_engine = SecurityRuleEngine()


class MaintenanceRequest(BaseModel):
    """A karbantartási mód be- vagy kikapcsolására szolgáló kérésmodell."""

    enabled: bool


def _raise_database_error(
    db: Session, message: str, exc: SQLAlchemyError
) -> NoReturn:
    """Visszagörgeti a tranzakciót, naplóz, majd API-hibát jelez."""
    db.rollback()
    logger.exception(
        "Database operation failed (%s)",
        type(exc).__name__,
        exc_info=(type(exc), Exception(type(exc).__name__), exc.__traceback__),
    )
    raise HTTPException(status_code=500, detail=message) from None


def get_db():
    """
    Függőség-befecskendezés (Dependency Injection) generátor függvény.
    Minden egyes API kéréshez nyit egy új adatbázis-munkamenetet (Session),
    majd a válasz elküldése után (a finally ágban) garantáltan lezárja azt,
    megelőzve a memóriaszivárgást és a beragadt adatbázis-kapcsolatokat.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Hitelesítés és karbantartási adminisztráció
def _require_maintenance_token(token: Optional[str]) -> None:
    """Ellenőrzi a karbantartási végpontokhoz szükséges tokent."""
    configured_token = os.getenv("MAINTENANCE_TOKEN")
    if not configured_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A karbantartási adminisztráció nincs konfigurálva.",
        )
    if token is None or not hmac.compare_digest(
        token.encode("utf-8"), configured_token.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Érvénytelen vagy hiányzó karbantartási token.",
        )


def _require_writes_enabled() -> None:
    """Megakadályozza az írási műveleteket aktív karbantartás esetén."""
    if maintenance_mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A rendszer karbantartás alatt áll; az írási műveletek átmenetileg tiltottak.",
        )


@app.get("/api/admin/maintenance")
def get_maintenance_status(
    maintenance_token: Optional[str] = Header(default=None, alias="X-Maintenance-Token"),
):
    """Hitelesítés után visszaadja a karbantartási mód aktuális állapotát."""
    _require_maintenance_token(maintenance_token)
    return {"enabled": maintenance_mode}


@app.post("/api/admin/maintenance")
def set_maintenance_status(
    request: MaintenanceRequest,
    maintenance_token: Optional[str] = Header(default=None, alias="X-Maintenance-Token"),
):
    """Átállítja a karbantartási módot, és visszaadja az állapotát."""
    global maintenance_mode
    _require_maintenance_token(maintenance_token)
    maintenance_mode = request.enabled
    os.environ["MAINTENANCE_MODE"] = "true" if request.enabled else "false"
    return {"enabled": maintenance_mode}


@app.post("/api/admin/probe-write")
def probe_write(
    db: Session = Depends(get_db),
    maintenance_token: Optional[str] = Header(default=None, alias="X-Maintenance-Token"),
):
    """Próbabejegyzéssel ellenőrzi az adatbázis írhatóságát."""
    _require_maintenance_token(maintenance_token)
    probe = models.SecurityEvent(
        ip_address="127.0.0.1",
        timestamp="maintenance-probe",
        http_method="PROBE",
        request_url="/internal/maintenance-probe",
        status_code=200,
        severity="Normál",
        reason="Temporary database write probe",
    )
    try:
        db.add(probe)
        db.flush()
        probe_id = probe.id
        if probe_id is None:
            raise SQLAlchemyError("Database did not assign a probe ID")
        db.query(models.SecurityEvent).filter(
            models.SecurityEvent.id == probe_id
        ).one()
        db.delete(probe)
        db.commit()
    except SQLAlchemyError as exc:
        _raise_database_error(db, "Az adatbázis próbaírása nem sikerült.", exc)
    return {"writable": True, "probe_id": probe_id}


# Naplóimport és biztonsági események
# 1. Adatfelvitel és feldolgozás (POST)
@app.post("/api/logs/import", status_code=status.HTTP_201_CREATED)
def import_logs(request: schemas.LogImportRequest, db: Session = Depends(get_db)):
    """
    Új nyers szervernapló-sorok tömeges beolvasása, kiértékelése és mentése.
    Adatfolyam: Nyers szöveg -> parse_log_line() -> SecurityRuleEngine -> Adatbázis INSERT.
    """
    _require_writes_enabled()
    imported_count = 0

    try:
        for line in request.logs:
            # 1. lépés: Szöveges naplósor felbontása mezőkre (funkcionális modul)
            parsed_data = parse_log_line(line)

            if parsed_data:
                # 2. lépés: Biztonsági kockázat kiértékelése (OOP szabálymotor)
                evaluated_data = sec_engine.evaluate_request(parsed_data)

                # 3. lépés: SQLAlchemy ORM modell példányosítása a mentéshez
                db_event = models.SecurityEvent(
                    ip_address=evaluated_data["ip"],
                    timestamp=evaluated_data["timestamp"],
                    http_method=evaluated_data["method"],
                    request_url=evaluated_data["url"],
                    status_code=evaluated_data["status"],
                    severity=evaluated_data["severity"],
                    reason=evaluated_data["reason"]
                )
                db.add(db_event)
                imported_count += 1

        # Csak akkor véglegesítjük a tranzakciót, ha volt érvényes feldolgozott sor
        if imported_count > 0:
            db.commit()
    except SQLAlchemyError as exc:
        _raise_database_error(db, "Az események mentése nem sikerült.", exc)

    return {"message": f"{imported_count} darab esemény sikeresen importálva és kiértékelve."}


# 2. Riasztások listázása és szűrése (GET)
@app.get("/api/events", response_model=List[schemas.SecurityEventResponse])
def get_events(severity: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db)):
    """
    Kiértékelt biztonsági események lekérdezése időrendben visszafelé (legfrissebb elöl).
    Opcionálisan szűrhető riasztási szint (severity) alapján query paraméterrel.
    """
    try:
        query = db.query(models.SecurityEvent)

        if severity:
            query = query.filter(models.SecurityEvent.severity == severity)

        # Csökkenő sorrend ID alapján, legfeljebb 'limit' darab találat visszaadása
        events = query.order_by(models.SecurityEvent.id.desc()).limit(limit).all()
    except SQLAlchemyError as exc:
        _raise_database_error(db, "Az események lekérdezése nem sikerült.", exc)

    if not events:
        raise HTTPException(status_code=404, detail="Nem található a feltételeknek megfelelő esemény.")

    return events


# 3. Statisztikai összesítés diagramokhoz (GET)
@app.get("/api/stats/summary", response_model=List[schemas.StatSummaryResponse])
def get_stats_summary(db: Session = Depends(get_db)):
    """
    Összesíti az események darabszámát riasztási szintek szerint (SQL GROUP BY + COUNT).
    A Streamlit dashboard ebből a végpontból rajzolja ki a megoszlási oszlopdiagramot.
    """
    try:
        stats = db.query(
            models.SecurityEvent.severity,
            func.count(models.SecurityEvent.id).label('count')
        ).group_by(models.SecurityEvent.severity).all()
    except SQLAlchemyError as exc:
        _raise_database_error(db, "A statisztika lekérdezése nem sikerült.", exc)

    return [{"severity": stat.severity, "count": stat.count} for stat in stats]


# 4. Részletes lekérés IP-cím alapján (GET)
@app.get("/api/events/{ip_address}", response_model=List[schemas.SecurityEventResponse])
def get_events_by_ip(ip_address: str, db: Session = Depends(get_db)):
    """
    Egy konkrét IP-címhez tartozó összes naplózott tevékenység lekérése.
    Útvonal-paraméterként (path parameter) kapja meg a keresett IP-címet.
    """
    try:
        events = db.query(models.SecurityEvent).filter(
            models.SecurityEvent.ip_address == ip_address
        ).all()
    except SQLAlchemyError as exc:
        _raise_database_error(db, "Az IP-címhez tartozó események lekérdezése nem sikerült.", exc)

    if not events:
        raise HTTPException(status_code=404, detail=f"Nem található bejegyzés a(z) {ip_address} IP-címhez.")

    return events