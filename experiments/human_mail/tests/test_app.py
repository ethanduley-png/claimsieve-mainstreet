import os

import pytest
from fastapi.testclient import TestClient

os.environ["HUMAN_MAIL_AGENT_KEY"] = "agent-key-" + "a" * 40
os.environ["HUMAN_MAIL_OPERATOR_KEY"] = "operator-key-" + "b" * 40
os.environ["HUMAN_MAIL_AUDIT_KEY"] = "audit-key-" + "c" * 40

from human_mail.app import app

AGENT = {"X-API-Key": os.environ["HUMAN_MAIL_AGENT_KEY"]}
OPERATOR = {"X-API-Key": os.environ["HUMAN_MAIL_OPERATOR_KEY"]}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HUMAN_MAIL_DB", str(tmp_path / "test.sqlite3"))
    with TestClient(app) as c:
        yield c


def worker(client, name="Worker", region="Elkhart", skills=None):
    resp = client.post("/v1/workers", headers=OPERATOR, json={
        "name": name, "email": f"{name.lower()}@example.com", "region": region,
        "skills": skills or ["video", "measurement"], "consent_to_email": True})
    assert resp.status_code == 201, resp.text
    return resp.json()


def task(client, **overrides):
    env = dict(title="Record tool usage", description="Record a consented demonstration of a hand tool in a private workshop.",
               purpose="Train robotic grasp planning", kind="video", region="Elkhart",
               reward_cents=3500, risk="low")
    env.update(overrides)
    resp = client.post("/v1/tasks", headers=AGENT, json=env)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def approve(client, task_id, **opts):
    return client.post(f"/v1/tasks/{task_id}/approve", headers=OPERATOR,
                       json={"approved_budget_cents": 3500, "safety_review_complete": True, **opts})


def test_no_agent_can_authorize_or_send(client):
    worker(client)
    tid = task(client)
    assert client.post(f"/v1/tasks/{tid}/approve", headers=AGENT,
                       json={"approved_budget_cents": 3500,"safety_review_complete":True}).status_code == 403
    assert client.get("/v1/outbox", headers=AGENT).status_code == 403
    assert client.get("/v1/tasks").status_code == 401
    assert approve(client,tid, safety_review_complete=False).status_code == 422
    assert approve(client,tid, approved_budget_cents=3501).status_code == 409
    assert client.get("/v1/audit/verify", headers=OPERATOR).json()["valid"] is True


def test_approved_dispatch_first_worker_wins_and_review(client):
    alice = worker(client, "Alice")
    bob = worker(client, "Bob")
    tid = task(client)
    result = approve(client, tid)
    assert result.status_code == 200, result.text
    assert result.json()["offers"] == 2
    assert result.json()["email_status"] == "queued_only"
    ao = client.get("/v1/offers", headers={"X-API-Key":alice["worker_api_key_one_time"]}).json()[0]
    bo = client.get("/v1/offers", headers={"X-API-Key":bob["worker_api_key_one_time"]}).json()[0]
    assert client.post(f'/v1/offers/{ao["offer_id"]}/accept', headers={"X-API-Key":alice["worker_api_key_one_time"]}).status_code == 200
    assert client.post(f'/v1/offers/{bo["offer_id"]}/accept', headers={"X-API-Key":bob["worker_api_key_one_time"]}).status_code == 409
    assert client.post(f"/v1/tasks/{tid}/submit", headers={"X-API-Key":bob["worker_api_key_one_time"]}, json={
        "artifact_sha256":"a" * 64,"artifact_uri":"https://example.org/video.mp4","notes":"Evidence from my camera"}).status_code == 403
    assert client.post(f"/v1/tasks/{tid}/submit", headers={"X-API-Key":alice["worker_api_key_one_time"]}, json={
        "artifact_sha256":"a" * 64,"artifact_uri":"https://example.org/video.mp4","notes":"Evidence from my camera"}).status_code == 200
    assert client.post(f"/v1/tasks/{tid}/review", headers=AGENT, json={"accepted":True,"reason":"All conditions met"}).status_code == 403
    verified = client.post(f"/v1/tasks/{tid}/review", headers=OPERATOR, json={"accepted":True,"reason":"Independently checked evidence"})
    assert verified.json() == {"status":"verified", "payment_status":"manual_only"}
    assert client.get("/v1/audit/verify",headers=OPERATOR).json()["entries"] >= 7


def test_no_repeated_mail_and_cancel_other_pending(client):
    alice = worker(client, "Alice")
    worker(client,"Bob")
    tid = task(client)
    assert approve(client, tid).status_code == 200
    outbox = client.get("/v1/outbox",headers=OPERATOR).json()
    assert len(outbox) == 2
    assert client.post(f'/v1/outbox/{outbox[0]["id"]}/send',headers=OPERATOR).status_code == 503
    ao = client.get("/v1/offers", headers={"X-API-Key":alice["worker_api_key_one_time"]}).json()[0]
    assert client.post(f'/v1/offers/{ao["offer_id"]}/accept', headers={"X-API-Key":alice["worker_api_key_one_time"]}).status_code == 200
    assert client.post(f'/v1/outbox/{outbox[1]["id"]}/send',headers=OPERATOR).status_code == 409


def test_mismatched_region_no_work_dispatched(client):
    worker(client,region="Chicago")
    tid = task(client)
    assert approve(client,tid).status_code == 409
    assert client.get("/v1/outbox",headers=OPERATOR).json() == []


def test_tampered_audit_detected(client, monkeypatch):
    worker(client)
    tid = task(client)
    assert approve(client,tid).status_code == 200
    import sqlite3
    con = sqlite3.connect(os.environ["HUMAN_MAIL_DB"])
    con.execute("UPDATE audit SET action='hijacked' WHERE sequence=1")
    con.commit()
    con.close()
    assert client.get("/v1/audit/verify",headers=OPERATOR).json()["valid"] is False


def test_exact_binding_detects_tampered_task(client):
    worker(client)
    tid = task(client)
    import sqlite3
    con = sqlite3.connect(os.environ["HUMAN_MAIL_DB"])
    con.execute("UPDATE tasks SET envelope=? WHERE id=?", ('{}',tid))
    con.commit()
    con.close()
    assert approve(client,tid).status_code == 409