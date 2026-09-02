import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.database import Base, engine, SessionLocal

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

def test_user_registration_and_login():
    # 1. Register User
    reg_resp = client.post("/api/v1/auth/register", json={
        "username": "testuser_pytest",
        "email": "testuser@example.com",
        "password": "SecurePassword123!"
    })
    assert reg_resp.status_code in [200, 400]  # 400 if already exists in test DB

    # 2. Login User
    login_resp = client.post("/api/v1/auth/login", json={
        "username": "testuser_pytest",
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # 3. Access Protected Route
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "testuser_pytest"

def test_rbac_admin_route_forbidden():
    # 1. Login regular user
    login_resp = client.post("/api/v1/auth/login", json={
        "username": "testuser_pytest",
        "password": "SecurePassword123!"
    })
    token = login_resp.json()["access_token"]

    # 2. Attempt admin endpoint with regular USER role
    admin_resp = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert admin_resp.status_code == 403
