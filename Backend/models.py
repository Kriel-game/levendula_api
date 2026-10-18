from sqlalchemy import Column, Integer, String
from Backend.database import Base

# =====================================================================
# ADATBÁZIS ORM (Object-Relational Mapping) MODELL
# Szerepe: Leképezi a Python objektumokat a relációs adatbázis (PostgreSQL/SQLite)
# 'security_events' táblájára. A main.py és a karbantarto.py is ezen az
# osztályon keresztül írja és olvassa az adatokat SQL parancsok írása nélkül.
# =====================================================================


class SecurityEvent(Base):
    """
    ORM modell a kiértékelt webes kérések és biztonsági riasztások tárolására.
    """
    __tablename__ = "security_events"

    # Elsődleges kulcs (Primary Key) automatikus növeléssel és indexeléssel
    id = Column(Integer, primary_key=True, index=True)

    # A parse_log_line() által a nyers Apache naplósorból kinyert mezők.
    # Az ip_address indexelve van (index=True), hogy az IP alapú keresés
    # nagy adatmennyiségnél is gyors maradjon.
    ip_address = Column(String, index=True)
    timestamp = Column(String)
    http_method = Column(String)
    request_url = Column(String)
    status_code = Column(Integer)

    # A SecurityRuleEngine által hozzáfűzött biztonsági kiértékelés eredménye.
    # A severity szintén indexelt, mert a Streamlit felület gyakran szűr és
    # csoportosít (GROUP BY) riasztási szint szerint.
    severity = Column(String, index=True)  # Értékei: "Normál", "Magas", "Kritikus"
    reason = Column(String)                # Pl. "SQL Injekció gyanú", "Tiszta kérés"