from pydantic import BaseModel, ConfigDict
from typing import List

# =====================================================================
# PYDANTIC ADATSÉMÁK (DTO - Data Transfer Objects)
# Szerepe: Meghatározza a FastAPI végpontok által várt bemeneti JSON adatok
# és a visszaküldött válaszok pontos szerkezetét és adattípusait.
# Ha a kliens hibás formátumú adatot küld, a Pydantic automatikusan 422-es
# hibával visszautasítja, mielőtt az elérné az adatbázist.
# =====================================================================


class LogImportRequest(BaseModel):
    """
    Bemeneti séma a POST /api/logs/import végponthoz.
    Elvárja, hogy a kérés törzsében egy 'logs' kulcsú szöveges lista szerepeljen.
    """
    logs: List[str]


class SecurityEventResponse(BaseModel):
    """
    Kimeneti séma a GET /api/events végpontokhoz.
    Biztosítja, hogy a Streamlit frontend mindig garantált szerkezetű JSON-t kapjon.
    """
    id: int
    ip_address: str
    timestamp: str
    http_method: str
    request_url: str
    status_code: int
    severity: str
    reason: str

    # A from_attributes=True (korábban orm_mode) teszi lehetővé, hogy a Pydantic
    # közvetlenül átalakítsa az SQLAlchemy 'SecurityEvent' ORM objektumokat JSON-ná.
    model_config = ConfigDict(from_attributes=True)


class StatSummaryResponse(BaseModel):
    """
    Kimeneti séma a GET /api/stats/summary végponthoz.
    A riasztási szintek darabszámát adja vissza a Streamlit oszlopdiagramjához.
    """
    severity: str
    count: int