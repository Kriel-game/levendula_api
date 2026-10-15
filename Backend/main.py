from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

# Importáljuk a korábban megírt moduljainkat
from database import SessionLocal, engine
import models
import schemas
from parse_log_line import parse_log_line
from security_engine import SecurityRuleEngine

# Adatbázis táblák létrehozása induláskor
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Levendula Vendégház Biztonsági API")

sec_engine = SecurityRuleEngine()


# Adatbázis-munkamenet (Session) kezelése kérésenként
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 1. Adatfelvitel és feldolgozás (POST)
# 1. Adatfelvitel és feldolgozás (POST)
@app.post("/api/logs/import", status_code=status.HTTP_201_CREATED)
def import_logs(request: schemas.LogImportRequest, db: Session = Depends(get_db)):
    """Új logsorok beolvasása, kiértékelése és adatbázisba mentése."""
    imported_count = 0

    for line in request.logs:
        parsed_data = parse_log_line(line)
        if parsed_data:
            # Objektumorientált szabálymotor futtatása
            evaluated_data = sec_engine.evaluate_request(parsed_data)

            # ORM példány létrehozása a megfelelő mezőnevek párosításával
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

    if imported_count > 0:
        db.commit()  # Tranzakció véglegesítése

    return {"message": f"{imported_count} darab esemény sikeresen importálva és kiértékelve."}


# 2. Riasztások listázása és szűrése (GET)
@app.get("/api/events", response_model=List[schemas.SecurityEventResponse])
def get_events(severity: str = None, limit: int = 100, db: Session = Depends(get_db)):
    """Események listázása, opcionálisan riasztási szint (severity) alapján szűrve."""
    query = db.query(models.SecurityEvent)

    if severity:
        query = query.filter(models.SecurityEvent.severity == severity)

    events = query.order_by(models.SecurityEvent.id.desc()).limit(limit).all()

    if not events:
        raise HTTPException(status_code=404, detail="Nem található a feltételeknek megfelelő esemény.")

    return events


# 3. Statisztikai összesítés diagramokhoz (GET)
@app.get("/api/stats/summary", response_model=List[schemas.StatSummaryResponse])
def get_stats_summary(db: Session = Depends(get_db)):
    """Összesíti az eseményeket riasztási szintek szerint a Streamlit diagramokhoz."""
    # SQLAlchemy csoportosító lekérdezés (GROUP BY)
    stats = db.query(
        models.SecurityEvent.severity,
        func.count(models.SecurityEvent.id).label('count')
    ).group_by(models.SecurityEvent.severity).all()

    # Konvertálás a Pydantic modell formátumára
    return [{"severity": stat.severity, "count": stat.count} for stat in stats]


# 4. Részletes lekérés IP-cím alapján (GET)
@app.get("/api/events/{ip_address}", response_model=List[schemas.SecurityEventResponse])
def get_events_by_ip(ip_address: str, db: Session = Depends(get_db)):
    """Egy adott IP-címhez tartozó összes naplózott kérés lekérése."""
    events = db.query(models.SecurityEvent).filter(models.SecurityEvent.ip_address == ip_address).all()

    if not events:
        raise HTTPException(status_code=404, detail=f"Nem található bejegyzés a(z) {ip_address} IP-címhez.")

    return events