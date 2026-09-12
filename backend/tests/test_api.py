import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("MAILGUARD_API_KEY", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    with TestClient(app) as client:
        yield client


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_contract(client):
    response = client.post("/analyze", json={"sender": "a@example.com", "subject": "Urgent"})
    assert response.status_code == 200
    data = response.json()
    assert data["score"] == 5
    assert data["verdict"] == "Low Risk"
    assert data["confidence"] == "Low"
    assert data["signals"][0]["id"] == "urgency_language"
    assert data["recommended_action"] and data["limitations"]
    assert "sender" not in data and "subject" not in data


def test_attachment_bytes_rejected_without_echo(client):
    response = client.post("/analyze", json={"sender": "a@example.com", "attachments": [
        {"filename": "file.pdf", "content_type": "application/pdf", "data": "PRIVATE_ATTACHMENT"}]})
    assert response.status_code == 422
    assert "PRIVATE_ATTACHMENT" not in response.text


@pytest.mark.parametrize("payload", [{}, {"sender": "a", "body": "x" * 100001},
    {"sender": "a", "urls": ["https://example.com"] * 201}, {"sender": "a", "unexpected": "PRIVATE"}])
def test_input_limits(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


def test_key_required_when_configured(client, monkeypatch):
    monkeypatch.setenv("MAILGUARD_API_KEY", "test-key")
    payload = {"sender": "a@example.com"}
    assert client.post("/analyze", json=payload).status_code == 401
    assert client.post("/analyze", json=payload, headers={"X-MailGuard-Key": "wrong"}).status_code == 401
    assert client.post("/analyze", json=payload, headers={"X-MailGuard-Key": "test-key"}).status_code == 200
    assert client.get("/health").status_code == 200


def test_cloud_run_fails_closed_without_key(client, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "mailguard-api")
    assert client.post("/analyze", json={"sender": "a@example.com"}).status_code == 503


def test_vercel_fails_closed_without_key(client, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    assert client.post("/analyze", json={"sender": "a@example.com"}).status_code == 503
