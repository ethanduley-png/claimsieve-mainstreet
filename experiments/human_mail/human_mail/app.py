"""Human Mail: human-in-the-loop physical task dispatch reference service.

This prototype deliberately does not charge customers, pay workers, or certify
physical completion automatically. Agents may only propose work.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

@asynccontextmanager
async def lifespan(_app):
    initialize()
    yield


APP = FastAPI(title="Human Mail", version="0.1.0",
              description="Proposal -> approval -> human offer -> proof -> independent review",
              lifespan=lifespan)
TaskKind = Literal["photo", "video", "measurement", "observation"]


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> str:
    return os.environ.get("HUMAN_MAIL_DB", "human-mail.sqlite3")


def secret(name: str) -> str:
    value = os.environ.get(name, "")
    if len(value) < 32:
        raise HTTPException(503, f"{name} must be configured with at least 32 characters")
    return value


@contextmanager
def transaction():
    path = db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=15000")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize():
    with transaction() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS workers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
            region TEXT NOT NULL, skills TEXT NOT NULL,
            api_key_hash TEXT NOT NULL UNIQUE, consent INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
            envelope TEXT NOT NULL, envelope_sha256 TEXT NOT NULL,
            status TEXT NOT NULL, selected_worker TEXT,
            proof TEXT, approved_at TEXT, submitted_at TEXT,
            reviewed_at TEXT, created_at TEXT NOT NULL,
            FOREIGN KEY(selected_worker) REFERENCES workers(id)
        );
        CREATE TABLE IF NOT EXISTS offers (
            id TEXT PRIMARY KEY, task_id TEXT NOT NULL, worker_id TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(task_id, worker_id),
            FOREIGN KEY(task_id) REFERENCES tasks(id),
            FOREIGN KEY(worker_id) REFERENCES workers(id)
        );
        CREATE TABLE IF NOT EXISTS outbox (
            id TEXT PRIMARY KEY, offer_id TEXT NOT NULL UNIQUE,
            recipient TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(offer_id) REFERENCES offers(id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
            entity TEXT NOT NULL, detail TEXT NOT NULL,
            prev_digest TEXT NOT NULL, digest TEXT NOT NULL
        );
        """)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def audit(db, actor: str, action: str, entity: str, detail: dict | None = None):
    prev = db.execute("SELECT digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
    record = dict(timestamp=stamp(), actor=actor, action=action,
                  entity=entity, detail=canonical(detail or {}),
                  prev_digest=prev["digest"] if prev else "0" * 64)
    digest = hmac.new(secret("HUMAN_MAIL_AUDIT_KEY").encode(), canonical(record).encode(), hashlib.sha256).hexdigest()
    db.execute("INSERT INTO audit(timestamp,actor,action,entity,detail,prev_digest,digest) VALUES (?,?,?,?,?,?,?)",
               (*record.values(), digest))


def verify_audit(db):
    prev = "0" * 64
    count = 0
    for r in db.execute("SELECT * FROM audit ORDER BY sequence"):
        record = {k: r[k] for k in ("timestamp", "actor", "action", "entity", "detail", "prev_digest")}
        expected = hmac.new(secret("HUMAN_MAIL_AUDIT_KEY").encode(), canonical(record).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(r["digest"], expected) or r["prev_digest"] != prev:
            return {"valid": False, "first_bad_sequence": r["sequence"], "entries": count}
        prev = r["digest"]
        count += 1
    return {"valid": True, "entries": count, "tip": prev}


def get_key(x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None) -> str:
    if not x_api_key:
        raise HTTPException(401, "X-API-Key required")
    return x_api_key


def role(expected: str):
    def require(api_key: Annotated[str, Depends(get_key)]) -> str:
        configured = secret(f"HUMAN_MAIL_{expected.upper()}_KEY")
        if not hmac.compare_digest(api_key, configured):
            raise HTTPException(403, "not authorized")
        return expected
    return require


def worker_id(api_key: Annotated[str, Depends(get_key)]) -> str:
    key_hash = sha(api_key)
    with transaction() as db:
        worker = db.execute("SELECT id FROM workers WHERE api_key_hash=? AND active=1", (key_hash,)).fetchone()
    if not worker:
        raise HTTPException(403, "unknown or disabled worker")
    return worker["id"]


def get_task(db, task_id: str):
    row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "task not found")
    return row


def check_binding(task):
    if not hmac.compare_digest(sha(task["envelope"]), task["envelope_sha256"]):
        raise HTTPException(409, "task binding mismatch: fail closed")


def check_expiry(task):
    expires_at = json.loads(task["envelope"]).get("expires_at")
    if expires_at:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if dt <= datetime.now(timezone.utc):
            raise HTTPException(409, "task expired")


class WorkerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    region: str = Field(min_length=2, max_length=100)
    skills: list[TaskKind] = Field(min_length=1, max_length=4)
    consent_to_email: bool

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("valid email required")
        return v


class TaskCreate(BaseModel):
    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10, max_length=1500)
    purpose: str = Field(min_length=5, max_length=300)
    kind: TaskKind
    region: str = Field(min_length=2, max_length=100)
    reward_cents: int = Field(ge=100, le=100_000)
    expires_at: str | None = Field(default=None, max_length=40)
    risk: Literal["low", "requires_review"] = "requires_review"
    collection_consent_required: bool = True

    @field_validator("title", "description", "purpose", "region")
    @classmethod
    def no_controls(cls, v):
        if any(ord(c) < 32 and c not in "\n\t" for c in v):
            raise ValueError("control characters are not allowed")
        return v

    @field_validator("expires_at")
    @classmethod
    def expiry_must_be_tz_aware(cls, v):
        if v is not None:
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError("time zone required")
            except ValueError as exc:
                raise ValueError("expires_at must be timezone-aware ISO 8601") from exc
        return v


class Approval(BaseModel):
    max_offers: int = Field(default=3, ge=1, le=10)
    approved_budget_cents: int = Field(ge=100, le=100_000)
    safety_review_complete: bool = False


class Proof(BaseModel):
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_uri: str = Field(min_length=8, max_length=2048)
    notes: str = Field(min_length=10, max_length=1000)

    @field_validator("artifact_uri")
    @classmethod
    def accepted_location(cls, v):
        # A pointer only: server never follows or fetches these URLs.
        if not v.startswith("https://"):
            raise ValueError("evidence URI must use HTTPS")
        return v


class Review(BaseModel):
    accepted: bool
    reason: str = Field(min_length=5, max_length=500)


@APP.get("/health")
def health():
    return {"service": "human-mail", "status": "ok", "version": "0.1.0"}


@APP.post("/v1/workers", status_code=201)
def register_worker(worker: WorkerCreate, operator=Depends(role("operator"))):
    if not worker.consent_to_email:
        raise HTTPException(422, "worker opt-in required")
    worker_id_new, token = str(uuid4()), secrets.token_urlsafe(40)
    with transaction() as db:
        db.execute("INSERT INTO workers(id,name,email,region,skills,api_key_hash,consent,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (worker_id_new, worker.name, worker.email, worker.region.strip().casefold(),
                    canonical(worker.skills), sha(token), 1, stamp()))
        audit(db, operator, "worker.registered", worker_id_new, {"skills": worker.skills, "region": worker.region})
    return {"id": worker_id_new, "worker_api_key_one_time": token}


@APP.post("/v1/tasks", status_code=201)
def propose_task(task: TaskCreate, agent=Depends(role("agent"))):
    envelope = canonical(task.model_dump(mode="json"))
    task_id = str(uuid4())
    with transaction() as db:
        db.execute("INSERT INTO tasks(id,agent_id,envelope,envelope_sha256,status,created_at) VALUES(?,?,?,?,?,?)",
                   (task_id, agent, envelope, sha(envelope), "proposed", stamp()))
        audit(db, agent, "task.proposed", task_id, {"envelope_sha256": sha(envelope)})
    return {"id": task_id, "status": "proposed", "envelope_sha256": sha(envelope)}


@APP.get("/v1/tasks")
def list_tasks(operator=Depends(role("operator"))):
    with transaction() as db:
        rows = db.execute("SELECT id,envelope,status,selected_worker,created_at FROM tasks ORDER BY created_at DESC").fetchall()
        return [{"id": r["id"], "task": json.loads(r["envelope"]), "status": r["status"],
                 "selected_worker": r["selected_worker"], "created_at": r["created_at"]} for r in rows]


@APP.get("/v1/tasks/{task_id}/status")
def agent_task_status(task_id: str, agent=Depends(role("agent"))):
    with transaction() as db:
        task = get_task(db, task_id)
        check_binding(task)
        if task["agent_id"] != agent:
            raise HTTPException(403, "not your task")
        return {"task_id": task_id, "status": task["status"],
                "approved_at": task["approved_at"], "submitted_at": task["submitted_at"],
                "reviewed_at": task["reviewed_at"],
                "payment_status": "manual_only"}


@APP.post("/v1/tasks/{task_id}/approve")
def approve_task(task_id: str, approval: Approval, operator=Depends(role("operator"))):
    if not approval.safety_review_complete:
        raise HTTPException(422, "independent safety review required")
    with transaction() as db:
        task = get_task(db, task_id)
        check_binding(task)
        check_expiry(task)
        if task["status"] != "proposed":
            raise HTTPException(409, "task is not awaiting approval")
        env = json.loads(task["envelope"])
        if approval.approved_budget_cents != env["reward_cents"]:
            raise HTTPException(409, "approval must match the exact proposed reward")
        # No automated assignment to high-risk tasks; independent reviewer must mark safe.
        candidates = db.execute("SELECT * FROM workers WHERE region=? AND active=1 ORDER BY created_at,id",
                                (env["region"].strip().casefold(),)).fetchall()
        selected = [w for w in candidates if env["kind"] in json.loads(w["skills"])][:approval.max_offers]
        if not selected:
            raise HTTPException(409, "no consenting workers for this region and skill")
        for w in selected:
            offer_id = str(uuid4())
            db.execute("INSERT INTO offers(id,task_id,worker_id,status,created_at) VALUES(?,?,?,?,?)",
                       (offer_id, task_id, w["id"], "offered", stamp()))
            # Outbox is recipient-bound and preapproved; sending is a separate controlled effect.
            db.execute("INSERT INTO outbox(id,offer_id,recipient,subject,body,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (str(uuid4()), offer_id, w["email"], f"Human Mail task offer: {env['title']}",
                        f"Task: {env['title']}\nRegion: {env['region']}\nReward: ${env['reward_cents']/100:.2f}\n"
                        f"Task ID: {task_id}\nOffer ID: {offer_id}\nSign in to your worker account to accept.\n",
                        "queued", stamp(), stamp()))
        db.execute("UPDATE tasks SET status='offered',approved_at=? WHERE id=?", (stamp(), task_id))
        audit(db, operator, "task.approved_offered", task_id,
              {"envelope_sha256": task["envelope_sha256"], "offers": len(selected), "approved_budget_cents": approval.approved_budget_cents})
        return {"task_id": task_id, "status": "offered", "offers": len(selected), "email_status": "queued_only"}


@APP.get("/v1/offers")
def my_offers(worker: str = Depends(worker_id)):
    with transaction() as db:
        rows = db.execute("SELECT offers.id,offers.task_id,offers.status,tasks.envelope FROM offers JOIN tasks ON tasks.id=offers.task_id WHERE offers.worker_id=? ORDER BY offers.created_at DESC", (worker,)).fetchall()
        return [{"offer_id": r["id"], "task_id": r["task_id"], "status": r["status"],
                 "task": json.loads(r["envelope"])} for r in rows]


@APP.post("/v1/offers/{offer_id}/accept")
def accept_offer(offer_id: str, worker: str = Depends(worker_id)):
    with transaction() as db:
        offer = db.execute("SELECT * FROM offers WHERE id=? AND worker_id=?", (offer_id, worker)).fetchone()
        if not offer:
            raise HTTPException(404, "offer not found")
        task = get_task(db, offer["task_id"])
        check_binding(task)
        check_expiry(task)
        if offer["status"] != "offered" or task["status"] != "offered":
            raise HTTPException(409, "offer no longer available")
        db.execute("UPDATE tasks SET status='assigned',selected_worker=? WHERE id=?", (worker, task["id"]))
        db.execute("UPDATE offers SET status='withdrawn' WHERE task_id=? AND status='offered'", (task["id"],))
        db.execute("UPDATE offers SET status='accepted' WHERE id=?", (offer_id,))
        # Cancel queued emails to other workers. Already sent mail cannot be recalled.
        db.execute("UPDATE outbox SET status='cancelled',updated_at=? WHERE offer_id IN (SELECT id FROM offers WHERE task_id=? AND status='withdrawn') AND status='queued'", (stamp(), task["id"]))
        audit(db, f"worker:{worker}", "offer.accepted", task["id"], {"offer_id": offer_id})
    return {"status": "assigned", "task_id": offer["task_id"]}


@APP.post("/v1/tasks/{task_id}/submit")
def submit_proof(task_id: str, proof: Proof, worker: str = Depends(worker_id)):
    with transaction() as db:
        task = get_task(db, task_id)
        check_binding(task)
        if task["status"] != "assigned" or task["selected_worker"] != worker:
            raise HTTPException(403, "not assigned to this worker")
        db.execute("UPDATE tasks SET status='submitted',proof=?,submitted_at=? WHERE id=?",
                   (canonical(proof.model_dump()), stamp(), task_id))
        audit(db, f"worker:{worker}", "proof.submitted", task_id,
              {"artifact_sha256": proof.artifact_sha256})
    return {"status": "submitted", "payment_status": "not_initiated"}


@APP.post("/v1/tasks/{task_id}/review")
def review_proof(task_id: str, review: Review, operator=Depends(role("operator"))):
    with transaction() as db:
        task = get_task(db, task_id)
        check_binding(task)
        if task["status"] != "submitted":
            raise HTTPException(409, "task has no submitted proof")
        outcome = "verified" if review.accepted else "rejected"
        db.execute("UPDATE tasks SET status=?,reviewed_at=? WHERE id=?", (outcome, stamp(), task_id))
        audit(db, operator, "proof.reviewed", task_id, {"outcome": outcome, "reason": review.reason})
    return {"status": outcome, "payment_status": "manual_only"}


@APP.get("/v1/audit/verify")
def audit_status(operator=Depends(role("operator"))):
    with transaction() as db:
        return verify_audit(db)


@APP.get("/v1/outbox")
def queued_emails(operator=Depends(role("operator"))):
    with transaction() as db:
        rows = db.execute("SELECT id,offer_id,recipient,subject,status FROM outbox ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


@APP.post("/v1/outbox/{message_id}/send")
def send_approved_email(message_id: str, operator=Depends(role("operator"))):
    # No arbitrary recipient, content, or destination accepted at the send boundary.
    # 'sending' is durable before network I/O: failed/unknown sends never retry automatically.
    with transaction() as db:
        item = db.execute("SELECT * FROM outbox WHERE id=?", (message_id,)).fetchone()
        if not item:
            raise HTTPException(404, "outbox message not found")
        offer = db.execute("SELECT * FROM offers WHERE id=?", (item["offer_id"],)).fetchone()
        task = get_task(db, offer["task_id"])
        check_binding(task)
        check_expiry(task)
        if item["status"] != "queued" or task["status"] != "offered" or offer["status"] != "offered":
            raise HTTPException(409, "message may no longer be sent")
        host = os.environ.get("HUMAN_MAIL_SMTP_HOST")
        sender = os.environ.get("HUMAN_MAIL_FROM")
        if not host or not sender:
            raise HTTPException(503, "SMTP not configured: mail remains queued")
        db.execute("UPDATE outbox SET status='sending',updated_at=? WHERE id=?", (stamp(), message_id))
        audit(db, operator, "mail.delivery_attempted", message_id, {"recipient_hash": sha(item["recipient"]), "offer_id": offer["id"]})
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, item["recipient"], item["subject"]
    msg.set_content(item["body"])
    try:
        port = int(os.environ.get("HUMAN_MAIL_SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=12) as client:
            client.starttls()
            username, password = os.environ.get("HUMAN_MAIL_SMTP_USERNAME"), os.environ.get("HUMAN_MAIL_SMTP_PASSWORD")
            if username and password:
                client.login(username, password)
            client.send_message(msg)
        outcome = "sent"
    except Exception:
        outcome = "unknown"
    with transaction() as db:
        db.execute("UPDATE outbox SET status=?,updated_at=? WHERE id=? AND status='sending'", (outcome, stamp(), message_id))
        audit(db, "mailer", "mail.delivery_observed", message_id, {"outcome": outcome})
    return {"message_id": message_id, "status": outcome, "note": "sent means SMTP accepted, not human read or delivered"}

app = APP