from pydantic import BaseModel
from typing import List, Optional

class LogImportRequest(BaseModel):
    """Bemeneti modell a nyers logsorok tömeges importálásához."""
    logs: List[str]

class SecurityEventResponse(BaseModel):
    """Kimeneti modell a felület (Streamlit) felé küldött adatokhoz."""
    id: int
    ip_address: str
    timestamp: str
    http_method: str
    request_url: str
    status_code: int
    severity: str
    reason: str

    class Config:
        from_attributes = True  # Lehetővé teszi az SQLAlchemy modellek közvetlen konverzióját

class StatSummaryResponse(BaseModel):
    """Kimeneti modell a statisztikai összesítéshez."""
    severity: str
    count: int