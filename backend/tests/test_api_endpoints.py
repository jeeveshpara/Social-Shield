import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal, Base, engine
from app.services.security.auth import seed_default_users

client = TestClient(app)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_default_users(db)
    yield


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_metrics_endpoint():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests_served" in data
    assert "total_scans_recorded" in data


def test_auth_login_success():
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@12345",
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["username"] == "admin"
    assert data["role"] == "admin"


def test_auth_login_invalid_password():
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "WrongPassword999!",
    })
    assert response.status_code == 401


def test_auth_me_authenticated():
    # Login to acquire token
    login_resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@12345",
    })
    token = login_resp.json()["access_token"]

    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["role"] == "admin"


def test_create_and_get_scan():
    # Create scan for benign username
    response = client.post("/api/scans/", json={"target": "test_analyst_user"})
    assert response.status_code == 200
    scan_data = response.json()
    assert "id" in scan_data
    scan_id = scan_data["id"]

    # Fetch scan by id
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == scan_id

    # Fetch AI analyst report
    analyst_resp = client.get(f"/api/scans/{scan_id}/analyst")
    assert analyst_resp.status_code == 200
    assert "executive_summary" in analyst_resp.json()


def test_list_scans():
    response = client.get("/api/scans/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
