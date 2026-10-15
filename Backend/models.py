from sqlalchemy import Column, Integer, String
from Backend.database import Base


class SecurityEvent(Base):
    """
    ORM modell a kiértékelt webes kérések és biztonsági riasztások tárolására.
    """
    __tablename__ = "security_events"

    # Elsődleges kulcs (ID)
    id = Column(Integer, primary_key=True, index=True)

    # A naplósorból kinyert alapinformációk
    ip_address = Column(String, index=True)
    timestamp = Column(String)
    http_method = Column(String)
    request_url = Column(String)
    status_code = Column(Integer)

    # A SecurityRuleEngine által hozzáfűzött értékelés
    severity = Column(String, index=True)  # pl. "Normál", "Kritikus", "Magas"
    reason = Column(String)  # pl. "SQL Injekció gyanú"

# --- Az adatbázis táblák létrehozása ---
# Ezt általában a főprogram indulásakor futtatjuk le
# Base.metadata.create_all(bind=engine)