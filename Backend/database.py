import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# =====================================================================
# ADATBÁZIS-KAPCSOLAT ÉS MUNKAMENET (SESSION) KONFIGURÁCIÓ
# Szerepe: Ez a modul felel a fizikai adatbázis-kapcsolat felépítéséért.
# Összeköti a Python alkalmazást a felhős PostgreSQL (Render) szerverrel,
# vagy helyi fejlesztés/tesztelés esetén egy helyi SQLite fájllal.
# =====================================================================

# Betöltjük a környezeti változókat a .env fájlból (ha létezik helyileg)
load_dotenv()

# Kiolvassuk a DATABASE_URL környezeti változót.
# Ha nincs megadva (pl. helyi tesztelésnél .env nélkül), tartalékként (fallback)
# egy helyi SQLite adatbázist használ, így a program minden környezetben elindul.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vendeghaz_biztonsag.db")

# Az adatbázis-motor (Engine) létrehozása:
# Az SQLite alapértelmezetten tiltja a többszálú hozzáférést, amit a FastAPI
# aszinkron/többszálú kéréskezelése megkövetel, ezért ott engedélyezni kell a
# 'check_same_thread: False' opciót. A PostgreSQL ezt natívan kezeli.
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

# A SessionLocal egy "munkamenet-gyár" (factory): minden beérkező API kérés
# ebből példányosít magának egy saját, elszigetelt adatbázis-tranzakciót.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# A Base osztály az összes SQLAlchemy ORM adatmodell (pl. SecurityEvent) közös őse.
# Ezen keresztül tartja nyilván a rendszer a létrehozandó adatbázis-táblákat.
Base = declarative_base()