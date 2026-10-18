import pytest
from fastapi.testclient import TestClient
from Backend import models
from Backend.database import engine
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

# Importáljuk az alkalmazásunk moduljait (a fájlnevek a te projektedhez igazítandók)
from main import app, get_db
from database import Base
from security_engine import SecurityRuleEngine

# =====================================================================
# ADATBÁZIS BEÁLLÍTÁSA A TESZTEKHEZ (STATICPOOL A MEMÓRIA MEGTARTÁSÁHOZ)
# =====================================================================
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

# =====================================================================
# 1. EGYSÉGTESZTEK (UNIT TESZTEK) A BIZTONSÁGI SZABÁLYMOTORHOZ
# =====================================================================

engine_instance = SecurityRuleEngine()

def test_rule_engine_normal_case():
    """Normál eset ellenőrzése: egy ártalmatlan URL nem válthat ki riasztást."""
    test_data = {
        "ip": "81.183.12.55",
        "timestamp": "10/Sep/2026:08:15:22 +0200",
        "method": "GET",
        "url": "/szobak.php",
        "status": 200
    }
    result = engine_instance.evaluate_request(test_data)
    assert result["severity"] == "Normál"
    assert result["reason"] == "Tiszta kérés"

@pytest.mark.parametrize("malicious_url, expected_severity, expected_reason", [
    ("/foglalas.php?id=1%20OR%201=1", "Kritikus", "SQL Injekció gyanú"),
    ("/kapcsolat.php?uzenet=%3Cscript%3Ealert(1)%3C/script%3E", "Magas", "XSS támadás gyanú"),
    ("/kepek/../../../../etc/passwd", "Kritikus", "Könyvtárbejárás gyanú")
])
def test_rule_engine_attack_cases(malicious_url, expected_severity, expected_reason):
    """
    Határesetek és támadások vizsgálata paraméterezett teszttel.
    Ez a dekorátor egyetlen függvényen belül három külön esetet futtat le.
    """
    test_data = {
        "ip": "10.0.0.1",
        "timestamp": "10/Sep/2026:12:00:00 +0200",
        "method": "GET",
        "url": malicious_url,
        "status": 200
    }
    result = engine_instance.evaluate_request(test_data)
    assert result["severity"] == expected_severity
    assert result["reason"] == expected_reason

def test_rule_engine_invalid_input():
    """Hibás bemenet ellenőrzése: hiányzó 'url' kulcs a szótárban."""
    test_data = {"ip": "127.0.0.1", "method": "GET"}  # Nincs URL
    result = engine_instance.evaluate_request(test_data)
    assert result["severity"] == "Hiba"
    assert result["reason"] == "Érvénytelen vagy hiányzó bemenet"

# =====================================================================
# 2. API INTEGRÁCIÓS TESZT ELKÜLÖNÍTETT ADATBÁZISSAL
# =====================================================================

def test_api_import_and_retrieve_integration():
    """
    A tényleges API-kérés feldolgozás ellenőrzése:
    API kérés (POST) -> Tesztadatbázis írás -> API válasz (GET) -> Ellenőrzés.
    """
    # 1. Előkészítés: Létrehozzuk a táblákat az üres tesztadatbázisban
    models.Base.metadata.create_all(bind=engine)

    # 2. Végrehajtás (Adatfelvitel)
    raw_log = '192.168.1.1 - - [10/Sep/2026:16:05:12 +0200] "GET /admin.php?user=1=1 HTTP/1.1" 200 1024 "-" "-"'
    post_response = client.post("/api/logs/import", json={"logs": [raw_log]})

    # Ellenőrizzük a sikeres beküldés HTTP státuszkódját
    assert post_response.status_code == 201

    # 3. Végrehajtás (Visszaolvasás)
    get_response = client.get("/api/events")
    assert get_response.status_code == 200

    # 4. Ellenőrzés: A válasz tartalmának és a kiértékelés sikerességének vizsgálata
    events = get_response.json()
    assert len(events) == 1
    assert events[0]["ip_address"] == "192.168.1.1"
    assert events[0]["severity"] == "Kritikus"

    # 5. Takarítás: Táblák eldobása a tesztadatbázisból
    Base.metadata.drop_all(bind=test_engine)