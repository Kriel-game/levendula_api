import asyncio
import json
import os
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from Backend import main as main_module, models
from Backend.main import app, get_db
from Backend.security_engine import SecurityRuleEngine
from Karbantarto import karbantarto as maintenance


@pytest.fixture
def api_database(tmp_path, monkeypatch):
    database_path = tmp_path / "api_test.sqlite"
    test_engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    testing_session = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    models.Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(main_module, "maintenance_mode", False)
    with TestClient(app) as test_client:
        yield test_client, testing_session
    app.dependency_overrides.pop(get_db, None)
    models.Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


@pytest.mark.parametrize(
    "url, expected_severity, expected_reason",
    [
        ("/szobak.php", "Normál", "Tiszta kérés"),
        ("", "Normál", "Tiszta kérés"),
        ("/LOGIN?next=%3CsCrIpT%3E", "Magas", "XSS támadás gyanú"),
        ("/foglalas?id=1%20oR%201=1", "Kritikus", "SQL Injekció gyanú"),
    ],
)
def test_rule_engine_normal_boundary_and_encoded_inputs(
    url, expected_severity, expected_reason
):
    result = SecurityRuleEngine().evaluate_request({"url": url})
    assert result["severity"] == expected_severity
    assert result["reason"] == expected_reason


@pytest.mark.parametrize(
    "malicious_url, expected_severity, expected_reason",
    [
        ("/foglalas.php?id=1%20OR%201=1", "Kritikus", "SQL Injekció gyanú"),
        (
            "/kapcsolat.php?uzenet=%3Cscript%3Ealert(1)%3C/script%3E",
            "Magas",
            "XSS támadás gyanú",
        ),
        ("/kepek/../../../../etc/passwd", "Kritikus", "Könyvtárbejárás gyanú"),
    ],
)
def test_rule_engine_attack_cases(malicious_url, expected_severity, expected_reason):
    result = SecurityRuleEngine().evaluate_request(
        {
            "ip": "10.0.0.1",
            "timestamp": "10/Sep/2026:12:00:00 +0200",
            "method": "GET",
            "url": malicious_url,
            "status": 200,
        }
    )
    assert result["severity"] == expected_severity
    assert result["reason"] == expected_reason


def test_rule_engine_invalid_input():
    result = SecurityRuleEngine().evaluate_request({"ip": "127.0.0.1", "method": "GET"})
    assert result["severity"] == "Hiba"
    assert result["reason"] == "Érvénytelen vagy hiányzó bemenet"


def test_api_import_and_retrieve_integration(api_database):
    client, session_factory = api_database
    raw_log = (
        '192.168.1.1 - - [10/Sep/2026:16:05:12 +0200] '
        '"GET /admin.php?user=1=1 HTTP/1.1" 200 1024 "-" "-"'
    )

    post_response = client.post("/api/logs/import", json={"logs": [raw_log]})
    assert post_response.status_code == 201
    assert post_response.json() == {
        "message": "1 darab esemény sikeresen importálva és kiértékelve."
    }

    get_response = client.get("/api/events")
    assert get_response.status_code == 200
    assert len(get_response.json()) == 1
    assert get_response.json()[0]["ip_address"] == "192.168.1.1"
    assert get_response.json()[0]["severity"] == "Kritikus"

    with session_factory() as db:
        stored = db.query(models.SecurityEvent).all()
        assert len(stored) == 1
        assert stored[0].request_url == "/admin.php?user=1=1"
        assert stored[0].severity == "Kritikus"


def test_maintenance_admin_and_probe_write(api_database, monkeypatch):
    client, session_factory = api_database
    token = "pytest-maintenance-token"
    monkeypatch.setenv("MAINTENANCE_TOKEN", token)

    assert client.get("/api/admin/maintenance").status_code == 401
    assert client.get(
        "/api/admin/maintenance",
        headers={"X-Maintenance-Token": "incorrect-test-token"},
    ).status_code == 401

    headers = {"X-Maintenance-Token": token}
    enabled = client.post(
        "/api/admin/maintenance", headers=headers, json={"enabled": True}
    )
    assert enabled.status_code == 200
    assert enabled.json() == {"enabled": True}

    import_response = client.post(
        "/api/logs/import",
        json={
            "logs": [
                '192.0.2.1 - - [10/Sep/2026:16:05:12 +0000] '
                '"GET /maintenance-test HTTP/1.1" 200 1'
            ]
        },
    )
    assert import_response.status_code == 503
    assert "karbantartás" in import_response.json()["detail"]

    probe_response = client.post("/api/admin/probe-write", headers=headers)
    assert probe_response.status_code == 200
    assert probe_response.json()["writable"] is True
    assert probe_response.json()["probe_id"] > 0
    with session_factory() as db:
        assert db.query(models.SecurityEvent).count() == 0

    status_response = client.get("/api/admin/maintenance", headers=headers)
    assert status_response.json() == {"enabled": True}


def test_maintenance_admin_requires_server_token(api_database, monkeypatch):
    client, _ = api_database
    monkeypatch.delenv("MAINTENANCE_TOKEN", raising=False)
    response = client.get(
        "/api/admin/maintenance",
        headers={"X-Maintenance-Token": "test-token"},
    )
    assert response.status_code == 503


def test_render_api_retries_transient_responses(monkeypatch):
    statuses = [429, 503, 200]
    request_count = 0

    async def handler(request):
        nonlocal request_count
        request_count += 1
        return httpx.Response(statuses.pop(0), json={"ok": True})

    async def no_wait(_):
        return None

    monkeypatch.setattr(maintenance.asyncio, "sleep", no_wait)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            api = maintenance.RenderAPI("test-api-key", client)
            response = await api.request("GET", "/postgres")
            assert response.status_code == 200

    asyncio.run(run())
    assert request_count == 3


@pytest.mark.parametrize("status_code", [401, 403])
def test_render_api_stops_immediately_on_authorization_error(status_code):
    request_count = 0

    async def handler(_):
        nonlocal request_count
        request_count += 1
        return httpx.Response(status_code)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            api = maintenance.RenderAPI("test-api-key", client)
            with pytest.raises(maintenance.RotationError):
                await api.request("GET", "/postgres")

    asyncio.run(run())
    assert request_count == 1


def test_render_api_stops_after_retry_limit(monkeypatch):
    request_count = 0

    async def handler(_):
        nonlocal request_count
        request_count += 1
        return httpx.Response(503)

    async def no_wait(_):
        return None

    monkeypatch.setattr(maintenance.asyncio, "sleep", no_wait)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            api = maintenance.RenderAPI("test-api-key", client)
            with pytest.raises(maintenance.RotationError):
                await api.request("GET", "/postgres")

    asyncio.run(run())
    assert request_count == maintenance.MAX_RETRIES


@pytest.mark.parametrize("backup_state", ["missing", "corrupt"])
def test_restore_rejects_missing_or_corrupt_backup(tmp_path, backup_state):
    backup_path = tmp_path / "untrusted-backup.json"
    if backup_state == "corrupt":
        backup_path.write_text("{not-json", encoding="utf-8")
        expected_exception = json.JSONDecodeError
    else:
        expected_exception = FileNotFoundError

    with pytest.raises(expected_exception):
        maintenance.restore_backup(
            backup_path,
            f"sqlite:///{(tmp_path / 'restore.sqlite').as_posix()}",
        )
    assert not (tmp_path / "restore.sqlite").exists()


def test_resume_discovers_created_database_without_creating_another(
    tmp_path, monkeypatch
):
    state_path = tmp_path / "rotation_state.json"
    monkeypatch.setattr(maintenance, "STATE_PATH", state_path)
    state = {
        "phase": "creating_database",
        "new_db_name": "pytest-recovery-db",
        "source_db_id": "dpg-source-test",
    }
    maintenance._save_state(state)

    class MockRenderAPI:
        def __init__(self):
            self.calls = []

        async def request(self, method, path, **kwargs):
            self.calls.append((method, path))
            return httpx.Response(
                200,
                json=[
                    {
                        "postgres": {
                            "id": "dpg-created-test",
                            "name": "pytest-recovery-db",
                            "status": "available",
                        }
                    }
                ],
            )

    api = MockRenderAPI()

    async def run():
        database_id, database = await maintenance._create_or_recover_database(
            api, state, "owner-test", "free", "region-test", "16"
        )
        return database_id, database

    database_id, database = asyncio.run(run())
    assert database_id == "dpg-created-test"
    assert database["status"] == "available"
    assert api.calls == [("GET", "/postgres")]
    assert state["phase"] == "database_created"
    assert json.loads(state_path.read_text(encoding="utf-8"))["new_db_id"] == database_id

    backup_path = tmp_path / "rotation-backup.json"
    backup_path.write_text(
        json.dumps(
            {
                "metadata": {"record_count": 1},
                "events": [
                    {
                        "id": 4,
                        "ip_address": "192.0.2.5",
                        "timestamp": "2026-09-10T14:05:12Z",
                        "http_method": "GET",
                        "request_url": "/safe",
                        "status_code": 200,
                        "severity": "Normál",
                        "reason": "Tiszta kérés",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    restored_url = f"sqlite:///{(tmp_path / 'resumed.sqlite').as_posix()}"
    maintenance.restore_backup(backup_path, restored_url)
    maintenance.restore_backup(backup_path, restored_url)
    verify_engine = create_engine(restored_url)
    with sessionmaker(bind=verify_engine)() as db:
        assert db.query(models.SecurityEvent).count() == 1
    verify_engine.dispose()


@pytest.mark.parametrize("failure_point", ["restore", "postcheck"])
def test_rotation_failure_keeps_maintenance_enabled(
    tmp_path, monkeypatch, failure_point
):
    state_path = tmp_path / "rotation_state.json"
    lock_path = tmp_path / "rotation.lock"
    backup_path = tmp_path / "backup.json"
    backup_path.write_text(
        json.dumps(
            {
                "metadata": {"record_count": 0},
                "events": [],
            }
        ),
        encoding="utf-8",
    )
    state = {
        "phase": "database_created" if failure_point == "restore" else "backend_deployed",
        "source_db_id": "dpg-source-test",
        "new_db_id": "dpg-target-test",
        "backup_path": str(backup_path),
        "delete_requested": True,
        "recovery_mode": False,
    }
    monkeypatch.setattr(maintenance, "STATE_PATH", state_path)
    monkeypatch.setattr(maintenance, "LOCK_PATH", lock_path)
    monkeypatch.setattr(maintenance, "_acquire_lock", lambda: None)
    monkeypatch.setattr(maintenance, "_release_lock", lambda: None)
    monkeypatch.setattr(maintenance, "_wait_database_available", AsyncMock(
        return_value={
            "status": "available",
            "connectionInfo": {
                "internalConnectionString": "sqlite:///unused.sqlite",
                "externalConnectionString": "sqlite:///unused.sqlite",
            },
        }
    ))
    maintenance._save_state(state)
    monkeypatch.setenv("RENDER_API_KEY", "test-api-key")
    monkeypatch.setenv("RENDER_WEB_SERVICE_ID", "srv-test")
    monkeypatch.setenv("RENDER_OWNER_ID", "owner-test")
    monkeypatch.setenv("RENDER_DB_PLAN", "free")
    monkeypatch.setenv("RENDER_DB_REGION", "region-test")
    monkeypatch.setenv("RENDER_POSTGRES_VERSION", "16")
    monkeypatch.setenv("BACKEND_BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("MAINTENANCE_TOKEN", "test-token")
    monkeypatch.setenv("MAINTENANCE_MODE", "true")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))

    class MockRenderAPI:
        def __init__(self, *_):
            self.calls = []

        async def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if path == "/postgres":
                return httpx.Response(200, json=[])
            if path == "/postgres/dpg-target-test":
                return httpx.Response(
                    200,
                    json={
                        "status": "available",
                        "connectionInfo": {
                            "internalConnectionString": "sqlite:///unused.sqlite",
                            "externalConnectionString": "sqlite:///unused.sqlite",
                        },
                    },
                )
            raise AssertionError(f"Unexpected mocked API call: {method} {path}")

    monkeypatch.setattr(maintenance, "RenderAPI", MockRenderAPI)
    if failure_point == "restore":
        monkeypatch.setattr(
            maintenance,
            "restore_backup",
            lambda *_: (_ for _ in ()).throw(RuntimeError("simulated restore failure")),
        )
    else:
        monkeypatch.setattr(
            maintenance,
            "_verify_live_backend",
            AsyncMock(side_effect=RuntimeError("simulated postcheck failure")),
        )

    with pytest.raises(RuntimeError):
        asyncio.run(
            maintenance.perform_database_rotation(
                source_db_id="dpg-source-test",
                allow_delete="dpg-source-test",
                resume=True,
            )
        )

    assert os.environ["MAINTENANCE_MODE"] == "true"
    persisted_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted_state["phase"] in {"database_created", "backend_deployed"}
