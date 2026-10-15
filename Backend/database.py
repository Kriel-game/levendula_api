import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Betöltjük a .env fájl tartalmát
load_dotenv()

# Megpróbáljuk kiolvasni a felhős linket. Ha nincs (mert pl. a tanár a saját gépén futtatja .env nélkül),
# akkor biztonsági tartalékként az SQLite-ot használja.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vendeghaz_biztonsag.db")

# Az SQLite-nak kell egy extra beállítás (check_same_thread), a PostgreSQL-nek nem.
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()