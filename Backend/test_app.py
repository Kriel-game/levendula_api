import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from Backend.main import app, get_db
from Backend import models
from Backend.security_engine import SecurityRuleEngine

# =====================================================================
# AUTOMATIZÁLT TESZTEK (UNIT ÉS INTEGRÁCIÓS TESZTEK)
# Szerepe: A kód helyességének ellenőrzése helyileg és a GitHub Actions CI/CD
# folyamatában. Két szinten tesztel:
# 1. Unit tesztek: A SecurityRuleEngine osztályt önmagában, izoláltan vizsgálja.
# 2. Integrációs teszt: A teljes FastAPI alkalmazást (POST -> DB -> GET)
#    teszteli egy memóriában futó (in-memory) SQLite adatbázison keresztül.
# =====================================================================

# Memóriában futó SQLite adatbázis konfigurálása a tesztekhez.
# A StaticPool biztosítja, hogy a memóriában lévő adatbázis ne törlődjön
# két teszt-lekérdezés (pl. a POST és a GET hívás) között.
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    """
    Helyettesítő adatbázis-kapcsolat a teszteléshez.
    Az éles PostgreSQL helyett a memóriában lévő SQLite adatbázist adja át a végpontoknak.
    """
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Felülírjuk a FastAPI eredeti get_db függőségét a teszt adatbázissal
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
    Támadási minták vizsgálata paraméterezett teszttel.
    A @pytest.mark.parametrize dekorátor mindhárom támadási típust (SQLi, XSS,
    Path Traversal) külön-külön tesztesetként futtatja le.
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
    """Hibakezelés ellenőrzése: hiányzó 'url' kulcs a bemeneti szótárban."""
    test_data = {"ip": "127.0.0.1", "method": "GET"}
    result = engine_instance.evaluate_request(test_data)
    assert result["severity"] == "Hiba"
    assert result["reason"] == "Érvénytelen vagy hiányzó bemenet"


# =====================================================================
# 2. API INTEGRÁCIÓS TESZT ELKÜLÖNÍTETT ADATBÁZISSAL
# =====================================================================

def test_api_import_and_retrieve_integration():
    """
    Végponttól végpontig (end-to-end) tartó API munkafolyamat ellenőrzése:
    1. Táblák létrehozása a memóriában -> 2. POST (log beküldése) ->
    3. GET (kiértékelt adat visszaolvasása) -> 4. Takarítás (drop_all).
    """
    # 1. Előkészítés: Létrehozzuk a táblákat az üres memória-adatbázisban
    models.Base.metadata.create_all(bind=test_engine)

    # 2. Végrehajtás (Adatfelvitel POST kéréssel)
    raw_log = '192.168.1.1 - - [10/Sep/2026:16:05:12 +0200] "GET /admin.php?user=1=1 HTTP/1.1" 200 1024 "-" "-"'
    post_response = client.post("/api/logs/import", json={"logs": [raw_log]})
    assert post_response.status_code == 201

    # 3. Végrehajtás (Visszaolvasás GET kéréssel)
    get_response = client.get("/api/events")
    assert get_response.status_code == 200

    # 4. Ellenőrzés: Megfelelően értékelte-e ki és mentette-e el a rendszert
    events = get_response.json()
    assert len(events) == 1
    assert events[0]["ip_address"] == "192.168.1.1"
    assert events[0]["severity"] == "Kritikus"

    # 5. Takarítás: Táblák eldobása, hogy a következő teszt tiszta lappal induljon
    models.Base.metadata.drop_all(bind=test_engine)