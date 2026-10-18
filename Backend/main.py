from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional

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

# Alkalmazás indulásakor automatikusan létrehozza a 'security_events' táblát
# az adatbázisban, amennyiben az még nem létezik.
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Levendula Vendégház Biztonsági API")

# Példányosítjuk az OOP szabálymotort, amely a kérések kiértékelését végzi
sec_engine = SecurityRuleEngine()


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


# 1. Adatfelvitel és feldolgozás (POST)
@app.post("/api/logs/import", status_code=status.HTTP_201_CREATED)
def import_logs(request: schemas.LogImportRequest, db: Session = Depends(get_db)):
    """
    Új nyers szervernapló-sorok tömeges beolvasása, kiértékelése és mentése.
    Adatfolyam: Nyers szöveg -> parse_log_line() -> SecurityRuleEngine -> Adatbázis INSERT.
    """
    imported_count = 0

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

    return {"message": f"{imported_count} darab esemény sikeresen importálva és kiértékelve."}


# 2. Riasztások listázása és szűrése (GET)
@app.get("/api/events", response_model=List[schemas.SecurityEventResponse])
def get_events(severity: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db)):
    """
    Kiértékelt biztonsági események lekérdezése időrendben visszafelé (legfrissebb elöl).
    Opcionálisan szűrhető riasztási szint (severity) alapján query paraméterrel.
    """
    query = db.query(models.SecurityEvent)

    if severity:
        query = query.filter(models.SecurityEvent.severity == severity)

    # Csökkenő sorrend ID alapján, legfeljebb 'limit' darab találat visszaadása
    events = query.order_by(models.SecurityEvent.id.desc()).limit(limit).all()

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
    stats = db.query(
        models.SecurityEvent.severity,
        func.count(models.SecurityEvent.id).label('count')
    ).group_by(models.SecurityEvent.severity).all()

    return [{"severity": stat.severity, "count": stat.count} for stat in stats]


# 4. Részletes lekérés IP-cím alapján (GET)
@app.get("/api/events/{ip_address}", response_model=List[schemas.SecurityEventResponse])
def get_events_by_ip(ip_address: str, db: Session = Depends(get_db)):
    """
    Egy konkrét IP-címhez tartozó összes naplózott tevékenység lekérése.
    Útvonal-paraméterként (path parameter) kapja meg a keresett IP-címet.
    """
    events = db.query(models.SecurityEvent).filter(models.SecurityEvent.ip_address == ip_address).all()

    if not events:
        raise HTTPException(status_code=404, detail=f"Nem található bejegyzés a(z) {ip_address} IP-címhez.")

    return events