from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Helyi SQLite adatbázis URL-je (fejlesztéshez)
SQLALCHEMY_DATABASE_URL = "sqlite:///./vendeghaz_biztonsag.db"

# Engine létrehozása. Az SQLite-hoz szükséges a check_same_thread=False beállítás.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# SessionLocal osztály, ebből példányosítjuk majd az adatbázis-munkameneteket (Session)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Alaposztály a modellek számára
Base = declarative_base()