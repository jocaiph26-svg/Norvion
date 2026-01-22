from __future__ import annotations
# ----------------------------
# Internal: Deterministic rule inventory (versioned)
# ----------------------------
RULE_INVENTORY = [
    {
        "rule": "Cash runway tight",
        "id": "runway_tight",
        "threshold": "< low_cash_buffer_days setting",
        "data_gates": ["daily burn data", "current cash"],
        "suppression_reasons": ["manual ignore", "noted seasonal"],
        "metric": "runway_days",
        "version": "v1.0",
    },
    {
        "rule": "Expense spike",
        "id": "expense_spike",
        "threshold": "> expense_spike_pct vs prior window",
        "data_gates": ["expense data", "window size >= 2"],
        "suppression_reasons": ["missing data", "manual ignore"],
        "metric": "expense_change",
        "version": "v1.0",
    },
    {
        "rule": "Revenue drop",
        "id": "revenue_drop",
        "threshold": "< -revenue_drop_pct vs prior window",
        "data_gates": ["revenue data", "window size >= 2"],
        "suppression_reasons": ["missing data", "manual ignore"],
        "metric": "income_change",
        "version": "v1.0",
    },
    {
        "rule": "Expense concentration",
        "id": "expense_concentration",
        "threshold": "> concentration_threshold for single vendor/category",
        "data_gates": ["vendor/category data"],
        "suppression_reasons": ["manual ignore"],
        "metric": "max_vendor_or_category_share",
        "version": "v1.0",
    },
    {
        "rule": "Large expense transaction",
        "id": "large_expense",
        "threshold": "> mean + (large_txn_sigma * std)",
        "data_gates": ["expense distribution stats"],
        "suppression_reasons": ["manual ignore", "known seasonal"],
        "metric": "largest_expense_amount",
        "version": "v1.0",
    },
    {
        "rule": "Overdue receivables",
        "id": "overdue_receivables",
        "threshold": ">= overdue_days setting",
        "data_gates": ["invoice_id", "due_date", "status columns"],
        "suppression_reasons": ["missing invoice data"],
        "metric": "overdue_ar_total",
        "version": "v1.0",
    },
    {
        "rule": "Overdue payables",
        "id": "overdue_payables",
        "threshold": ">= overdue_days setting",
        "data_gates": ["invoice_id", "due_date", "status columns"],
        "suppression_reasons": ["missing invoice data"],
        "metric": "overdue_ap_total",
        "version": "v1.0",
    },
]
RULE_INDEX = {str(r.get("id")): r for r in RULE_INVENTORY}

import io
import csv
import json
import sqlite3
import hashlib
import logging
import os
import math
import re
import sys
import time
import secrets
import hmac
from functools import wraps
from dataclasses import dataclass, field
# TIMESTAMP POLICY: All timestamps use UTC (datetime.utcnow()).
# Stored timestamps are ISO 8601 strings without timezone suffix.
# Consumers should treat all timestamps as UTC.
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple, Optional, Union, Callable
from pathlib import Path
from contextlib import contextmanager

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, UploadFile, Form, Query, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jinja2 import TemplateNotFound
from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware

# ----------------------------
# Password Hashing (werkzeug-compatible PBKDF2)
# ----------------------------
# Using built-in hashlib for PBKDF2 to avoid new dependencies.
# This matches werkzeug.security semantics but uses stdlib only.
PBKDF2_ITERATIONS = 260000  # OWASP 2023 recommendation
PBKDF2_HASH_FUNC = "sha256"
SALT_LENGTH = 16

def generate_password_hash(password: str) -> str:
    """Generate a PBKDF2-SHA256 password hash."""
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_hex(SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_FUNC,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt}${dk.hex()}"

def check_password_hash(pwhash: str, password: str) -> bool:
    """Verify a password against a PBKDF2-SHA256 hash."""
    if not pwhash or not password:
        return False
    try:
        if not pwhash.startswith("pbkdf2:sha256:"):
            return False
        parts = pwhash.split("$")
        if len(parts) != 3:
            return False
        header, salt, stored_hash = parts
        iterations = int(header.split(":")[-1])
        dk = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_FUNC,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False

# Password policy constants
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

def _rule_inventory_hash() -> str:
    """Deterministic hash of current rule inventory for auditability."""
    canonical = json.dumps(RULE_INVENTORY, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

BASE_DIR = Path(__file__).resolve().parent
DEMO_DATA_DIR = BASE_DIR / "demo_data"

# ----------------------------
# Canonical comparison semantics (C1.1 / C1.2)
# ----------------------------
COMPARISON_KIND_ADJACENT_WINDOWS = "adjacent_windows_same_length"
ALERT_ID_VERSION = "v1.0"
QUALITY_SUPPRESSION_THRESHOLD = 70
TENANT_HEADER = "X-Tenant-ID"
TENANT_DEFAULT = "public"
CONFIG_VERSION = "v1"
CONFIG_MIGRATION_POLICY = "manual"
ACCESS_ROLE_HEADER = "X-Access-Role"
ACCESS_ACTOR_HEADER = "X-Actor-ID"
# Updated RBAC roles: viewer < auditor < operator < manager < admin
# viewer: basic read-only access
# auditor: read-only with access to audit trails, reports, and exports (no modifications)
# operator: can upload, update alert status/note
# manager: can view settings/config (not change)
# admin: full access including settings changes and user management
AUTH_ROLES = ["viewer", "auditor", "operator", "manager", "admin"]
ACCESS_ROLES = AUTH_ROLES  # Backward compatibility alias
RULE_CHANGE_STATUSES = {"draft", "approved", "active"}

# D4: Role capability matrix (authoritative)
ROLE_CAPABILITIES = {
    "viewer": {
        "view",  # View pages, alerts, insights
    },
    "auditor": {
        "view",
        "export",  # Export reports, run JSON
        "audit",  # View access events
    },
    "operator": {
        "view",
        "create",  # Upload CSV, create runs
        "update",  # Update alert status/notes
    },
    "manager": {
        "view",
        "create",
        "update",
        "configure",  # View/edit settings, rules
    },
    "admin": {
        "view",
        "create",
        "update",
        "configure",
        "manage_users",  # Create/update users
        "manage_integrations",  # Manage integrations
    },
}

# ----------------------------
# Authentication constants
# ----------------------------
AUTH_SESSION_KEY = "auth_user_id"
AUTH_TENANT_KEY = "auth_tenant_id"
AUTH_ROLE_KEY = "auth_user_role"
AUTH_EMAIL_KEY = "auth_user_email"
AUTH_SESSION_VERSION_KEY = "auth_session_version"  # HIGH(7): Track session version for invalidation
STEPUP_SESSION_KEY = "stepup_verified_at"
STEPUP_VALIDITY_SECONDS = 600  # 10 minutes
RESET_TOKEN_EXPIRY_HOURS = 1
DEV_MAIL_OUTBOX_FILE = "dev_mail_outbox.json"
MAX_DEV_OUTBOX_ENTRIES = 50

# Routes that don't require authentication
# D3: Explicit public vs protected route contract
PUBLIC_ROUTES = {
    "/",
    "/home",
    "/login",
    "/logout",  # Has auth but no TOS required
    "/forgot-password",
    "/reset-password",
    "/api/health",
    "/healthz",
}
PUBLIC_ROUTE_PREFIXES = (
    "/static/",
)

# FastAPI framework-generated documentation routes (developer tooling, not application endpoints)
# These are auto-mounted by FastAPI and exempted from guard validation
FRAMEWORK_ROUTES_EXEMPT = {
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    # Webhook endpoint: Uses secret-based authentication (bearer-style) instead of session auth
    # Auth mechanism: Validates body.secret via constant-time hmac.compare_digest() before processing
    # See P2(8) remediation - secret validation occurs at line ~8159 BEFORE any business logic
    # This is industry-standard webhook auth pattern (GitHub, Stripe, Shopify, etc.)
    "/api/webhook/transactions",
}

_CODE_HASH_CACHE: Optional[str] = None

def window_comparison_label(days: int) -> str:
    d = int(days)
    return f"most recent {d} days vs immediately preceding {d} days"

# ----------------------------
# App constants
# ----------------------------
APP_TITLE = "SME Early Warning"
# Allow tests (and power-users) to run against an isolated database without
# changing application code. In normal use, this remains the bundled app.db.
_DB_PATH_ENV = os.getenv("SME_EW_DB_PATH", "app.db")
DB_PATH = _DB_PATH_ENV if os.path.isabs(_DB_PATH_ENV) else str(BASE_DIR / _DB_PATH_ENV)
MAX_UPLOAD_BYTES = 6 * 1024 * 1024  # 6MB
MAX_UPLOAD_ROWS = 100_000 # demo safety : prevent pathological CSVs from exhausting memory/CPU
SQLITE_TIMEOUT_S = 30
MAX_WEBHOOK_BYTES = 1 * 1024 * 1024  # 1MB demo cap (webhook payloads should be small)
CSV_CONTENT_TYPES = {"text/csv", "application/csv", "application/vnd.ms-excel"}
RATE_LIMIT_WINDOW_S = 60
RATE_LIMIT_UPLOADS = 30

# ----------------------------
# Ledger + provenance constants
# ----------------------------
LEDGER_SCHEMA_VERSION = "ledger_v1"
ADAPTER_VERSION = "adapter_v1"
# Allowed normalized columns (strict contract)
LEDGER_V1_COLUMNS = [
    "date",
    "amount",
    "type",
    "category",
    "counterparty",
    "description",
    "invoice_id",
    "due_date",
    "status",
    "direction",
]

# Rule safety caps (demo-safe; prevents pathological regex payloads)
MAX_RULE_TEXT_LEN = 200
MAX_RULES_RETURN = 2000

# TOS (Terms of Service) version - increment when TOS changes to require re-acceptance
TOS_VERSION = "1.0"
TOS_ROUTES_EXEMPT = ("/tos", "/logout", "/static/", "/login", "/api/health")

# ----------------------------
# Logging (demo-safe)
# ----------------------------
logger = logging.getLogger("sme_early_warning")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

def _safe_log_message(x: Any, max_len: int = 160) -> str:
    s = str(x or "")
    s = s.replace("\x00", "")
    if len(s) > max_len:
        s = s[:max_len]
    return s

_RATE_LIMIT_BUCKETS: Dict[str, List[float]] = {}

def _rate_limit_allow(key: str, limit: int, window_s: int) -> bool:
    """
    In-memory sliding-window rate limiter for authentication and upload endpoints.

    TODO_ENTERPRISE: This implementation is single-instance only.
    For horizontal scaling (multiple app instances / load balancing):
    - Replace with Redis-backed rate limiting (redis.incr with TTL)
    - Use library like slowapi with Redis backend
    - Ensure distributed coordination across instances
    See DEPLOYMENT_CHECKLIST.md for details.

    LIMITATIONS (HIGH Issue #6):
    - In-memory only: resets on restart, not shared across processes
    - No persistence: limits do not survive application restarts
    - Single-process only: will NOT work correctly with multiple app instances (horizontal scaling)
    - No distributed coordination: each process maintains its own independent bucket state

    For production multi-instance deployments, replace with Redis-backed rate limiting
    (e.g., using redis.incr with TTL, or a library like slowapi with Redis backend).

    Current usage:
    - Login attempts: 10/minute per IP
    - Password reset: 5/5min per email (dev mode only)
    - CSV upload: 30/minute per tenant
    - Webhook ingestion: 30/minute per tenant

    Returns True if request is allowed, False if rate limit exceeded.
    """
    now = float(time.time())
    window_start = now - float(window_s)
    bucket = _RATE_LIMIT_BUCKETS.get(key, [])
    bucket = [ts for ts in bucket if ts >= window_start]
    if len(bucket) >= int(limit):
        _RATE_LIMIT_BUCKETS[key] = bucket
        return False
    bucket.append(now)
    _RATE_LIMIT_BUCKETS[key] = bucket
    return True

# ----------------------------
# FastAPI + templates
# ----------------------------
# P0-01: Disable framework documentation routes in production
_SME_EW_ENV = os.getenv('SME_EW_ENV', 'development').strip().lower()
if _SME_EW_ENV == "production":
    app = FastAPI(
        title=APP_TITLE,
        docs_url=None,      # Disables /docs
        redoc_url=None,     # Disables /redoc
        openapi_url=None,   # Disables /openapi.json
    )
else:
    app = FastAPI(title=APP_TITLE)
# Session middleware is used only to persist selected run context across pages.
# This uses Starlette's built-in session support (no new dependencies).
_SESSION_SECRET_RAW = os.getenv('SME_EW_SESSION_SECRET', '')
_SESSION_SECRET_DEMO_DEFAULT = "CHANGE_ME_DEMO_SESSION_SECRET"

# Production-safe session secret enforcement
_session_secret_missing = not _SESSION_SECRET_RAW or not _SESSION_SECRET_RAW.strip()
_session_secret_is_demo = _SESSION_SECRET_RAW == _SESSION_SECRET_DEMO_DEFAULT

if _SME_EW_ENV == "production":
    if _session_secret_missing:
        logger.critical(
            "FATAL: SME_EW_SESSION_SECRET is missing or empty in production mode. "
            "Set a cryptographically secure session secret. Refusing to start."
        )
        sys.exit(1)
    if _session_secret_is_demo:
        logger.critical(
            "FATAL: SME_EW_SESSION_SECRET must not be the demo default in production mode. "
            "Set a cryptographically secure session secret. Refusing to start."
        )
        sys.exit(1)
    _SESSION_SECRET = _SESSION_SECRET_RAW
else:
    # Non-production: use demo default if not set, but warn
    if _session_secret_missing:
        _SESSION_SECRET = _SESSION_SECRET_DEMO_DEFAULT
        logger.warning(
            "SME_EW_SESSION_SECRET is not set. Using demo default. "
            "Set an env var for safer sessions in non-demo deployments."
        )
    elif _session_secret_is_demo:
        _SESSION_SECRET = _SESSION_SECRET_RAW
        logger.warning(
            "SME_EW_SESSION_SECRET is using the demo default. "
            "Set a unique env var for safer sessions."
        )
    else:
        _SESSION_SECRET = _SESSION_SECRET_RAW

# ----------------------------
# Webhook secret startup validation
# ----------------------------
_WEBHOOK_SECRET_DEMO_DEFAULT = "CHANGE_ME_DEMO_SECRET"
_WEBHOOK_SECRET_ENV = os.getenv("SME_EW_WEBHOOK_SECRET", "")

if _SME_EW_ENV == "production":
    if _WEBHOOK_SECRET_ENV == _WEBHOOK_SECRET_DEMO_DEFAULT:
        logger.critical(
            "FATAL: SME_EW_WEBHOOK_SECRET must not be the demo default in production mode. "
            "Set a cryptographically secure webhook secret. Refusing to start."
        )
        sys.exit(1)
    if not _WEBHOOK_SECRET_ENV:
        # Warn but don't fail - webhook secret can also be set in DB settings
        # Runtime check in webhook handler will reject demo defaults
        logger.warning(
            "SME_EW_WEBHOOK_SECRET environment variable not set in production. "
            "Webhook ingestion will fail unless a secure secret is configured in tenant settings."
        )
else:
    if not _WEBHOOK_SECRET_ENV:
        logger.info(
            "SME_EW_WEBHOOK_SECRET not set. Using database settings or demo default for webhooks."
        )

def _parse_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default

def _clamp_float(x: Any, lo: float, hi: float, default: float) -> float:
    try:
        v = float(x)
    except Exception:
        return float(default)
    if not math.isfinite(v):
        return float(default)
    return float(min(max(v, lo), hi))

def _clamp_int(x: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(x)
    except Exception:
        return int(default)
    return int(min(max(v, lo), hi))

_demo_mode_env = _parse_bool(os.getenv("SME_EW_DEMO_MODE", "true"), default=True)
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    same_site="lax",
    https_only=(_SME_EW_ENV == "production"),
    max_age=3600,  # 1 hour session (temporarily changed from None to debug session issues)
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists() and STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    # Demo-hardening: don't crash if static/ is missing in a minimal environment.
    logger.warning("Static directory %s not found; continuing without /static mount", STATIC_DIR)
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler.

    - Tries to render `error.html` if present (nice for demos).
    - Falls back to plain text to avoid "exception in exception handler".
    """
    safe_msg = _safe_log_message(exc)
    if safe_msg:
        logger.error("Unhandled exception: %s: %s", exc.__class__.__name__, safe_msg)
    else:
        logger.error("Unhandled exception: %s", exc.__class__.__name__)
    try:
        _log_access(
            _tenant_id(request),
            _actor_id(request),
            _access_role(request),
            "error",
            f"exception:{request.url.path}",
            True,
        )
    except Exception:
        pass
    try:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "title": "Something went wrong",
                "error_title": "Something went wrong",
                "error_message": "The app is still running. This was caused by an unexpected input or missing data. Try again, or upload a new CSV.",
                "schema_help": None,
                "actions": [
                    {"label": "Back to Upload", "href": "/upload"},
                    {"label": "Home", "href": "/dashboard"},
                    {"label": "History", "href": "/history"},
                ],
                # Demo safety: don't leak stack traces / raw exceptions in the UI.
                "show_details": False,
                "error_details": None,
                "access_role": _access_role(request),
                "access_actor": _actor_id(request),
                "access_tenant": _tenant_id(request),
            },
            status_code=500,
        )
    except TemplateNotFound:
        return PlainTextResponse("Internal Server Error", status_code=500)
    except Exception:
        return PlainTextResponse("Internal Server Error", status_code=500)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    accept = str(request.headers.get("accept") or "").lower()
    if exc.status_code == 403 and "text/html" in accept:
        try:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "title": "Access denied",
                    "error_title": "Access denied",
                    "error_message": "You do not have permission to view this page.",
                    "schema_help": None,
                    "actions": [
                        {"label": "Home", "href": "/dashboard"},
                        {"label": "Back to Upload", "href": "/upload"},
                    ],
                    "show_details": False,
                    "error_details": None,
                    "access_role": _access_role(request),
                    "access_actor": _actor_id(request),
                    "access_tenant": _tenant_id(request),
                },
                status_code=403,
            )
        except TemplateNotFound:
            return HTMLResponse("Access denied", status_code=403)
        except Exception:
            return HTMLResponse("Access denied", status_code=403)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ----------------------------
# DB helpers (WAL + busy timeout to reduce locks)
# ----------------------------
def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_S, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Pragmas that matter for demo stability
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    return conn

import typing

@contextmanager
def db_conn() -> typing.Iterator[sqlite3.Connection]:
    conn = _connect_db()
    try:
        yield conn
    finally:
        conn.close()


def safe_json_loads(s: Any, default: Any):
    try:
        if s is None:
            return default
        if isinstance(s, (dict, list)):
            return s
        return json.loads(s)
    except Exception:
        return default


def _table_has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(str(r["name"]) == col for r in rows)

def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [str(r["name"]) for r in rows]
    except Exception:
        return []


def _insert_run_row(
    conn: sqlite3.Connection,
    created_at: str,
    filename: str,
    params_json: str,
    summary_json: str,
    alerts_json: str,
    quality_json: str,
    file_sha256: Optional[str] = None,
    settings_hash: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> int:
    """
    Backward-compatible INSERT into runs.
    - Some deployments may not have newer columns (file_sha256/settings_hash).
    - Build the INSERT dynamically using existing schema columns.
    Returns inserted run_id.
    """
    cols = set(_table_columns(conn, "runs"))
    base = {
        "created_at": created_at,
        "filename": filename,
        "params_json": params_json,
        "summary_json": summary_json,
        "alerts_json": alerts_json,
        "quality_json": quality_json,
    }
    if "file_sha256" in cols and file_sha256 is not None:
        base["file_sha256"] = file_sha256
    if "settings_hash" in cols and settings_hash is not None:
        base["settings_hash"] = settings_hash
    if "tenant_id" in cols and tenant_id is not None:
        base["tenant_id"] = tenant_id

    insert_cols = [
        k
        for k in [
            "created_at",
            "filename",
            "params_json",
            "summary_json",
            "alerts_json",
            "quality_json",
            "file_sha256",
            "settings_hash",
            "tenant_id",
        ]
        if k in base
    ]
    placeholders = ", ".join(["?"] * len(insert_cols))
    sql = f"INSERT INTO runs ({', '.join(insert_cols)}) VALUES ({placeholders})"
    conn.execute(sql, tuple(base[c] for c in insert_cols))
    row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
    return int(row["id"]) if row and row["id"] is not None else 0


def db_init() -> None:
    with db_conn() as conn:
        cur = conn.cursor()

        # ----------------------------
        # Authentication tables (Phase 1-5)
        # ----------------------------
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            UNIQUE(tenant_id, email)
        )
        """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        # Migration: Add tos_accepted_at column for TOS acceptance tracking
        if not _table_has_column(conn, "users", "tos_accepted_at"):
            try:
                cur.execute("ALTER TABLE users ADD COLUMN tos_accepted_at TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "users", "tos_version"):
            try:
                cur.execute("ALTER TABLE users ADD COLUMN tos_version TEXT")
            except Exception:
                pass

        # HIGH(7): Session invalidation - Add session_version for role change invalidation
        if not _table_has_column(conn, "users", "session_version"):
            try:
                cur.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
            except Exception:
                pass

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON password_reset_tokens(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_hash ON password_reset_tokens(token_hash)")

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            actor_id TEXT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            target_user_id INTEGER,
            details_json TEXT,
            ip_address TEXT
        )
        """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_created ON auth_audit_log(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_tenant ON auth_audit_log(tenant_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_user ON auth_audit_log(user_id)")

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            params_json TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            alerts_json TEXT NOT NULL,
            quality_json TEXT NOT NULL
        )
        """
        )

        # Lightweight migration(s)
        if not _table_has_column(conn, "runs", "file_sha256"):
            try:
                cur.execute("ALTER TABLE runs ADD COLUMN file_sha256 TEXT")
            except Exception:
                # If migration fails, continue; demo still works.
                pass

        if not _table_has_column(conn, "runs", "settings_hash"):
            try:
                cur.execute("ALTER TABLE runs ADD COLUMN settings_hash TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "runs", "tenant_id"):
            try:
                cur.execute("ALTER TABLE runs ADD COLUMN tenant_id TEXT")
            except Exception:
                pass

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            updated_at TEXT NOT NULL,
            settings_json TEXT NOT NULL
        )
        """
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS tenant_settings (
            tenant_id TEXT PRIMARY KEY,
            settings_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            settings_hash TEXT NOT NULL
        )
        """
        )
        try:
            rows = cur.execute(
                "SELECT tenant_id, settings_json, settings_hash FROM tenant_settings"
            ).fetchall()
            for r in rows:
                if not r["settings_hash"]:
                    s = safe_json_loads(r["settings_json"], {}) or {}
                    if isinstance(s, dict):
                        cur.execute(
                            "UPDATE tenant_settings SET settings_hash = ? WHERE tenant_id = ?",
                            (_canonical_json_hash(s), str(r["tenant_id"])),
                        )
        except Exception:
            pass

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS alert_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            alert_id TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(run_id, alert_id),
            FOREIGN KEY(run_id) REFERENCES runs(id)
        )
        """
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS alert_state (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'review',
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            last_seen_run_id INTEGER,
            last_score REAL NOT NULL DEFAULT 0.0
        )
        """
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            run_id INTEGER,
            alert_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT,
            note TEXT
        )
        """
        )

        # Integrations scaffolding (no keys required; safe placeholders)
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 0,
            config_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        )
        """
        )
        # Entity-scoped integrations scaffold (disabled; stored only)
        if not _table_has_column(conn, "integrations", "tenant_id"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "status"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN status TEXT NOT NULL DEFAULT 'disabled'")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "metadata_json"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN metadata_json TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "secret_ref"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN secret_ref TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "created_at"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations(tenant_id)"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_integrations_tenant_provider ON integrations(tenant_id, provider)"
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS ingest_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            run_id INTEGER,
            provider TEXT NOT NULL,
            source_mode TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(tenant_id, idempotency_key)
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_ingest_requests_created_at ON ingest_requests(created_at)"
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            allowed INTEGER NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_events_created_at ON access_events(created_at)"
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS explanation_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            run_id INTEGER,
            snapshot_id TEXT,
            report_id TEXT,
            enabled_flag INTEGER NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_explanation_requests_tenant_created ON explanation_requests(tenant_id, created_at)"
        )
        
        # ---- Integrations migration: sync state fields (demo-safe scaffold) ----
        if not _table_has_column(conn, "integrations", "last_sync_at"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN last_sync_at TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "last_sync_status"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN last_sync_status TEXT")
            except Exception:
                pass
        if not _table_has_column(conn, "integrations", "last_sync_note"):
            try:
                cur.execute("ALTER TABLE integrations ADD COLUMN last_sync_note TEXT")
            except Exception:
                pass

        # ---- Deterministic categorisation rules ----
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS vendor_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            match_type TEXT NOT NULL DEFAULT 'equals', -- equals|contains|startswith
            category TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_vendor_rules_vendor ON vendor_rules(vendor)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_vendor_rules_priority ON vendor_rules(priority)"
        )
        # Migration: Add tenant_id to vendor_rules for multi-tenant isolation
        if not _table_has_column(conn, "vendor_rules", "tenant_id"):
            try:
                cur.execute("ALTER TABLE vendor_rules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_vendor_rules_tenant ON vendor_rules(tenant_id)")
            except Exception:
                pass

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS description_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            match_type TEXT NOT NULL DEFAULT 'contains', -- contains|startswith|equals|regex (regex optional by setting)
            category TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_description_rules_priority ON description_rules(priority)"
        )
        # Migration: Add tenant_id to description_rules for multi-tenant isolation
        if not _table_has_column(conn, "description_rules", "tenant_id"):
            try:
                cur.execute("ALTER TABLE description_rules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_description_rules_tenant ON description_rules(tenant_id)")
            except Exception:
                pass

        # ---- Manual categorisation overrides (forward-only) ----
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS categorisation_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_field TEXT NOT NULL, -- counterparty|description
            pattern TEXT NOT NULL,
            match_type TEXT NOT NULL DEFAULT 'equals', -- equals|contains|startswith|regex
            category TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'high', -- high|medium
            is_enabled INTEGER NOT NULL DEFAULT 1,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_categorisation_overrides_target ON categorisation_overrides(target_field)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_categorisation_overrides_created ON categorisation_overrides(created_at)"
        )

        # ---- Rule change governance (forward-only metadata capture) ----
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS rule_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            version_tag TEXT NOT NULL,
            status TEXT NOT NULL,
            effective_at TEXT NOT NULL,
            approver_id TEXT NOT NULL,
            rationale TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_changes_tenant_created_at ON rule_changes(tenant_id, created_at)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_changes_rule_version ON rule_changes(rule_id, version_tag)"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_changes_tenant_rule_version ON rule_changes(tenant_id, rule_id, version_tag)"
        )

        # Indexes that make the demo snappy
        cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_events_alert_id ON alert_events(alert_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_events_created_at ON alert_events(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_state_updated_at ON alert_state(updated_at)")

        # Seed settings
        row = cur.execute("SELECT COUNT(*) AS c FROM settings").fetchone()
        if int(row["c"]) == 0:
            defaults = {
                "config_version": CONFIG_VERSION,
                "currency": "AUD",
                "starting_cash": 25000.0,
                "window_days": 90,
                "burn_days": 30,
                "low_cash_buffer_days": 21,
                "expense_spike_pct": 0.35,
                "revenue_drop_pct": 0.25,
                "concentration_threshold": 0.45,
                "large_txn_sigma": 3.0,
                "recurring_min_hits": 3,
                "overdue_days": 7,
                "recent_compare_days": 30,

                # Demo-grade product toggles (no external services required)
                "demo_mode": True,
                "enable_integrations_scaffold": True,
                "webhook_secret": "CHANGE_ME_DEMO_SECRET",

                # Categorisation controls
                "enable_categorisation_rules": True,
                # Regex rules are disabled by default to avoid ReDoS-style patterns in demo mode.
                "enable_regex_rules": False,
            }
            cur.execute(
                "INSERT INTO settings (id, updated_at, settings_json) VALUES (1, ?, ?)",
                (datetime.utcnow().isoformat(), json.dumps(defaults)),
            )

        # Seed integrations rows if missing
        existing = {str(r["provider"]) for r in cur.execute("SELECT provider FROM integrations").fetchall()}
        for provider in ["xero", "quickbooks", "myob", "stripe", "shopify", "square", "bank_csv"]:
            if provider not in existing:
                cur.execute(
                    "INSERT INTO integrations (provider, is_enabled, config_json, updated_at) VALUES (?, 0, '{}', ?)",
                    (provider, datetime.utcnow().isoformat()),
                )

        # Seed demo admin user if no users exist
        # Password: Demo123!Admin (printed to console on first run in dev mode)
        user_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        if int(user_count["c"]) == 0:
            demo_password = os.getenv("SME_EW_DEMO_ADMIN_PASSWORD", "Demo123!Admin")
            demo_email = os.getenv("SME_EW_DEMO_ADMIN_EMAIL", "admin@demo.local")
            demo_tenant = TENANT_DEFAULT
            try:
                cur.execute(
                    """
                    INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at)
                    VALUES (?, ?, ?, 'admin', 1, ?)
                    """,
                    (demo_tenant, demo_email, generate_password_hash(demo_password), datetime.utcnow().isoformat()),
                )
                if _SME_EW_ENV != "production":
                    logger.info("=" * 60)
                    logger.info("DEMO ADMIN USER CREATED")
                    logger.info("  Email: %s", demo_email)
                    logger.info("  Password: %s", demo_password)
                    logger.info("  Tenant: %s", demo_tenant)
                    logger.info("  Role: admin")
                    logger.info("=" * 60)
            except Exception as e:
                logger.warning("Could not seed demo admin user: %s", e)

        conn.commit()


def _validate_route_enforcement():
    """
    D3: Validate that all routes are either public or protected.
    Fail fast in dev if unclassified routes exist.
    """
    import inspect

    # Collect all registered routes
    unprotected_routes = []
    for route in app.routes:
        if not hasattr(route, "path"):
            continue

        path = route.path

        # Skip public routes
        if path in PUBLIC_ROUTES:
            continue
        if any(path.startswith(prefix) for prefix in PUBLIC_ROUTE_PREFIXES):
            continue

        # Skip FastAPI framework-generated documentation routes
        if path in FRAMEWORK_ROUTES_EXEMPT:
            continue

        # Skip routes with path parameters (harder to validate statically)
        if "{" in path:
            continue

        # Check if route handler has guards
        # Routes should call require_user, _require_auth, _require_role, _require_dev_mode, or _is_authenticated
        endpoint = route.endpoint if hasattr(route, "endpoint") else None
        if endpoint:
            try:
                source = inspect.getsource(endpoint) if callable(endpoint) else ""
            except (OSError, TypeError):
                # Can't get source (e.g., built-in, C function, or dynamically created)
                # Conservatively flag as unprotected
                source = ""
            has_guard = any(guard in source for guard in [
                "require_user(",
                "_require_auth(",
                "_require_role(",
                "_require_dev_mode(",
                "_is_authenticated("  # Used by /stepup and other auth-only routes
            ])
            if not has_guard:
                unprotected_routes.append(path)

    if unprotected_routes:
        msg = (
            f"[D3 ENFORCEMENT VIOLATION] Found {len(unprotected_routes)} routes without guards:\n"
            + "\n".join(f"  - {r}" for r in unprotected_routes)
            + "\n\nAll routes must be either:\n"
            + "  1) Listed in PUBLIC_ROUTES, PUBLIC_ROUTE_PREFIXES, or FRAMEWORK_ROUTES_EXEMPT\n"
            + "  2) Call require_user(), _require_auth(), _require_role(), _require_dev_mode(), or _is_authenticated()\n"
        )
        logger.error(msg)
        # Fail fast in dev
        raise RuntimeError(msg)

    logger.info("[D3] Route enforcement validation passed (%d routes checked)", len(app.routes))


@app.on_event("startup")
def _startup():
    db_init()
    logger.info("Startup complete. DB initialised at %s", DB_PATH)

    # D3: Validate route enforcement contract (dev mode only)
    if _SME_EW_ENV != "production":
        _validate_route_enforcement()


def _settings_from_row(row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    s = safe_json_loads(row["settings_json"] if row else "{}", {})
    if isinstance(s, dict) and not s.get("config_version"):
        s["config_version"] = CONFIG_VERSION
    return s if isinstance(s, dict) else {}


def _normalize_tenant_id(value: Optional[str]) -> str:
    if value is None:
        return ""
    safe = re.sub(r"[^A-Za-z0-9_-]", "", str(value).strip())
    return safe


def _safe_rule_change_status(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if s in RULE_CHANGE_STATUSES else "draft"


def _safe_version_tag(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    safe = re.sub(r"[^a-z0-9._-]", "", raw)
    return safe[:60]


def _parse_effective_at(value: Any) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def _effective_in_future(value: Any, now_utc: datetime) -> Optional[bool]:
    dt = _parse_effective_at(value)
    if dt is None:
        return None
    return bool(dt > now_utc)


def _effective_bucket(value: Any, now_utc: datetime) -> str:
    dt = _parse_effective_at(value)
    if dt is None:
        return "unknown"
    return "future" if dt > now_utc else "current_or_past"


def read_settings(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    with db_conn() as conn:
        tenant_key = _normalize_tenant_id(tenant_id) if tenant_id is not None else ""
        if tenant_key:
            trow = conn.execute(
                "SELECT settings_json FROM tenant_settings WHERE tenant_id = ?",
                (tenant_key,),
            ).fetchone()
            if trow:
                return _settings_from_row(trow)
        row = conn.execute("SELECT settings_json FROM settings WHERE id = 1").fetchone()
        return _settings_from_row(row)


def write_settings(s: Dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            "UPDATE settings SET updated_at = ?, settings_json = ? WHERE id = 1",
            (datetime.utcnow().isoformat(), json.dumps(s)),
        )
        conn.commit()


def _canonical_json_hash(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def write_tenant_settings(tenant_id: str, s: Dict[str, Any]) -> None:
    tenant_key = _normalize_tenant_id(tenant_id) or TENANT_DEFAULT
    settings_hash = _canonical_json_hash(s)
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_settings (tenant_id, settings_json, updated_at, settings_hash)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                settings_json=excluded.settings_json,
                updated_at=excluded.updated_at,
                settings_hash=excluded.settings_hash
            """,
            (tenant_key, json.dumps(s), datetime.utcnow().isoformat(), settings_hash),
        )
        conn.commit()

def _effective_webhook_secret(settings: Dict[str, Any]) -> str:
    env = os.getenv("SME_EW_WEBHOOK_SECRET")
    if env:
        return str(env)
    return str(settings.get("webhook_secret") or "")


def _require_dev_mode(request: Request) -> None:
    """
    Hard-gate for dev/test routes. In production mode, returns 404 to avoid
    acknowledging that dev routes exist. This is a security measure.
    """
    if _SME_EW_ENV == "production":
        raise HTTPException(status_code=404, detail="Not found")
    # Additionally check tenant-level demo_mode setting
    tenant_id = _tenant_id(request)
    s = read_settings(tenant_id)
    if not _parse_bool(s.get("demo_mode", True), default=True):
        raise HTTPException(status_code=404, detail="Not found")


# ----------------------------
# DISABLED: AI explanation scaffolding
# ----------------------------
# WARNING: AI features are DISABLED and MUST NOT be enabled without enterprise
# policy approval. The system is deterministic and non-advisory by design.
# These schemas exist for future reference ONLY. No AI inference occurs.
# Kill switch defaults to OFF. Do not change without governance review.
# ----------------------------
AI_EXPLANATION_SCHEMA_VERSION = "v1"
AI_EXPLANATION_KILL_SWITCH_KEY = "ai_explanations_enabled"  # Default: OFF
AI_PROMPT_TEMPLATE_ID = "explain_v1"

# DISABLED: Schema reserved for future AI features (not currently used)
AI_EXPLANATION_SCHEMA = {
    "request": {
        "schema_version": AI_EXPLANATION_SCHEMA_VERSION,
        "tenant_id": "tenant_id",
        "run_id": "run_id",
        "alert_id": "alert_id",
        "snapshot_id": "snapshot_id",
        "report_id": "report_id",
        "evidence_refs": [
            {"path": "summary.<field>"},
            {"path": "alerts[].<field>"},
            {"path": "quality.<field>"},
            {"path": "params.<field>"},
            {"path": "run.<field>"},
        ],
        "prompt_template_id": AI_PROMPT_TEMPLATE_ID,
    },
    "response": {
        "schema_version": AI_EXPLANATION_SCHEMA_VERSION,
        "tenant_id": "tenant_id",
        "run_id": "run_id",
        "alert_id": "alert_id",
        "explanation_text": "",
        "citations": [{"path": "summary.<field>"}],
        "prompt_template_id": AI_PROMPT_TEMPLATE_ID,
    },
}

# DISABLED: Governance constraints for future AI (not currently enforced)
AI_PROMPT_GOVERNANCE = {
    "constraints": [
        "no advice",
        "no recommendations",
        "no predictions",
        "no inference beyond stored evidence",
        "neutral, observational language only",
    ],
    "citations_required": True,
    "allowed_evidence_roots": ["summary", "alerts", "quality", "params", "run"],
}

# DISABLED: Audit log schema for future AI (not currently used)
AI_AUDIT_LOG_SCHEMA = {
    "schema_version": AI_EXPLANATION_SCHEMA_VERSION,
    "fields": [
        "id",
        "created_at",
        "tenant_id",
        "actor_id",
        "run_id",
        "alert_id",
        "prompt_template_id",
        "evidence_refs",
        "explanation_hash",
        "status",
    ],
}


def _ai_explanations_enabled(settings: Dict[str, Any]) -> bool:
    return bool(_parse_bool(settings.get(AI_EXPLANATION_KILL_SWITCH_KEY), default=False))


def _run_row_for_tenant(run_id: int, tenant_id: str) -> Optional[sqlite3.Row]:
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT id, alerts_json, params_json, tenant_id FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (int(run_id), TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, alerts_json, params_json FROM runs WHERE id = ?",
                (int(run_id),),
            ).fetchone()
    return row


# ----------------------------
# Authentication helpers (Phase 1-5)
# ----------------------------
def _get_client_ip(request: Request) -> str:
    """Get client IP for audit logging."""
    try:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return str(request.client.host)
    except Exception:
        pass
    return ""

def _is_authenticated(request: Request) -> bool:
    """Check if user is logged in via session."""
    try:
        return bool(request.session.get(AUTH_SESSION_KEY))
    except Exception:
        return False

def _current_user_id(request: Request) -> Optional[int]:
    """Get current user ID from session."""
    try:
        uid = request.session.get(AUTH_SESSION_KEY)
        return int(uid) if uid else None
    except Exception:
        return None

def _get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetch user by ID."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, tenant_id, email, role, is_active, created_at, last_login_at, tos_version, tos_accepted_at FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if row:
            return {
                "id": int(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "email": str(row["email"]),
                "role": str(row["role"]),
                "is_active": bool(row["is_active"]),
                "created_at": str(row["created_at"]),
                "last_login_at": str(row["last_login_at"]) if row["last_login_at"] else None,
                "tos_version": str(row["tos_version"]) if row["tos_version"] else None,
                "tos_accepted_at": str(row["tos_accepted_at"]) if row["tos_accepted_at"] else None,
            }
    return None

def _get_user_by_email(email: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch user by email (optionally scoped to tenant)."""
    with db_conn() as conn:
        if tenant_id:
            row = conn.execute(
                "SELECT id, tenant_id, email, password_hash, role, is_active, created_at FROM users WHERE email = ? AND tenant_id = ?",
                (email.lower().strip(), tenant_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, tenant_id, email, password_hash, role, is_active, created_at FROM users WHERE email = ?",
                (email.lower().strip(),),
            ).fetchone()
        if row:
            return {
                "id": int(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "email": str(row["email"]),
                "password_hash": str(row["password_hash"]),
                "role": str(row["role"]),
                "is_active": bool(row["is_active"]),
                "created_at": str(row["created_at"]),
            }
    return None

def _log_auth_event(
    tenant_id: str,
    event_type: str,
    user_id: Optional[int] = None,
    actor_id: Optional[str] = None,
    target_user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Log authentication/authorization events for audit."""
    try:
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO auth_audit_log
                (created_at, tenant_id, actor_id, user_id, event_type, target_user_id, details_json, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    str(tenant_id),
                    str(actor_id or ""),
                    user_id,
                    str(event_type),
                    target_user_id,
                    json.dumps(details) if details else None,
                    str(ip_address or ""),
                ),
            )
            conn.commit()
    except Exception:
        pass

def _validate_password(password: str) -> Tuple[bool, str]:
    """Validate password meets policy. Returns (valid, error_message)."""
    if not password:
        return False, "Password is required"
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f"Password cannot exceed {PASSWORD_MAX_LENGTH} characters"
    return True, ""


def _validate_role_capability(role: str, action: str) -> bool:
    """
    D4: Validate that a role has the capability for an action.
    This is informational only - does not change existing role hierarchy behavior.
    """
    if role not in ROLE_CAPABILITIES:
        logger.warning("[D4] Unknown role: %s", role)
        return False

    # Extract base action from composite actions like "deny:insufficient_role:manager"
    base_action = action.split(":")[0] if ":" in action else action

    # Check if role has capability for base action
    capabilities = ROLE_CAPABILITIES[role]
    has_capability = base_action in capabilities

    if not has_capability and not action.startswith("deny:"):
        logger.debug("[D4] Role %s lacks capability %s (allowed: %s)", role, base_action, capabilities)

    return has_capability


# ----------------------------
# Run context helpers (selected run persistence)
# ----------------------------
def _tenant_id(request: Optional[Request]) -> str:
    """Get tenant ID from authenticated session (Phase 2: session-only, no headers)."""
    if request is None:
        return TENANT_DEFAULT
    # Primary: get from authenticated session
    try:
        session_tenant = request.session.get(AUTH_TENANT_KEY)
        if session_tenant:
            safe = re.sub(r"[^A-Za-z0-9_-]", "", str(session_tenant).strip())
            return safe or TENANT_DEFAULT
    except Exception:
        pass
    # Fallback for dev mode ONLY: allow header if SME_EW_DEV_BYPASS=true AND localhost
    dev_bypass_enabled = _parse_bool(os.getenv("SME_EW_DEV_BYPASS", "false"), default=False)
    if dev_bypass_enabled:
        try:
            client_host = str(request.client.host if request.client else "")
            if client_host in ("127.0.0.1", "::1", "localhost"):
                raw = request.headers.get(TENANT_HEADER)
                if raw:
                    safe = re.sub(r"[^A-Za-z0-9_-]", "", str(raw).strip())
                    return safe or TENANT_DEFAULT
        except Exception:
            pass
    return TENANT_DEFAULT


def _access_role(request: Optional[Request]) -> str:
    """Get user role from authenticated session (Phase 2/3: session-only)."""
    if request is None:
        return "viewer"
    # Primary: get from authenticated session
    try:
        session_role = request.session.get(AUTH_ROLE_KEY)
        if session_role and session_role in AUTH_ROLES:
            return str(session_role)
    except Exception:
        pass
    # Fallback for dev mode ONLY
    dev_bypass_enabled = _parse_bool(os.getenv("SME_EW_DEV_BYPASS", "false"), default=False)
    if dev_bypass_enabled:
        try:
            client_host = str(request.client.host if request.client else "")
            if client_host in ("127.0.0.1", "::1", "localhost"):
                # Check header for dev testing
                raw = str(request.headers.get(ACCESS_ROLE_HEADER) or "").strip().lower()
                if raw in AUTH_ROLES:
                    return raw
                return "admin"  # Dev bypass defaults to admin
        except Exception:
            pass
    return "viewer"


def _actor_id(request: Optional[Request]) -> str:
    """Get actor ID (email) from authenticated session."""
    if request is None:
        return ""
    try:
        email = request.session.get(AUTH_EMAIL_KEY)
        if email:
            return _safe_text(str(email), 120)
    except Exception:
        pass
    # Dev fallback
    dev_bypass_enabled = _parse_bool(os.getenv("SME_EW_DEV_BYPASS", "false"), default=False)
    if dev_bypass_enabled:
        try:
            raw = str(request.headers.get(ACCESS_ACTOR_HEADER) or "").strip()
            return _safe_text(raw, 120)
        except Exception:
            pass
    return ""


def _role_rank(role: str) -> int:
    """Get numeric rank for role comparison."""
    try:
        return AUTH_ROLES.index(role)
    except Exception:
        return 0


def _log_access(
    tenant_id: str,
    actor_id: str,
    role: str,
    action: str,
    resource: str,
    allowed: bool = True,
) -> None:
    # D4: Validate role capability (informational, logs warning if mismatch)
    if role:
        _validate_role_capability(role, action)

    try:
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO access_events
                (created_at, tenant_id, actor_id, role, action, resource, allowed)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    str(tenant_id),
                    str(actor_id or ""),
                    str(role or "viewer"),
                    _safe_text(action, 120),
                    _safe_text(resource, 200),
                    1 if allowed else 0,
                ),
            )
            conn.commit()
    except Exception:
        pass


def _require_role(request: Request, min_role: str, action: str, resource: str) -> str:
    """Require minimum role for action. Raises HTTPException if denied."""
    # First check TOS acceptance for non-exempt routes
    _require_tos(request)
    role = _access_role(request)
    allowed = _role_rank(role) >= _role_rank(min_role)
    # D1: Log with explicit deny reason if insufficient role
    action_log = f"deny:insufficient_role:{min_role}" if not allowed else action
    _log_access(_tenant_id(request), _actor_id(request), role, action_log, resource, allowed)
    if not allowed:
        raise HTTPException(status_code=403, detail="forbidden")
    return role


def _require_stepup(request: Request) -> bool:
    """Check if step-up authentication is valid (Phase 5)."""
    try:
        stepup_at = request.session.get(STEPUP_SESSION_KEY)
        if not stepup_at:
            return False
        stepup_time = datetime.fromisoformat(str(stepup_at))
        now = datetime.utcnow()
        return (now - stepup_time).total_seconds() < STEPUP_VALIDITY_SECONDS
    except Exception:
        return False


def _set_stepup(request: Request) -> None:
    """Set step-up verification timestamp in session."""
    try:
        request.session[STEPUP_SESSION_KEY] = datetime.utcnow().isoformat()
    except Exception:
        pass


def _clear_stepup(request: Request) -> None:
    """Clear step-up verification from session."""
    try:
        request.session.pop(STEPUP_SESSION_KEY, None)
    except Exception:
        pass


# ----------------------------
# CSRF Protection (P0-08)
# ----------------------------
CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Routes exempt from CSRF (API endpoints using Bearer auth, webhooks, login)
CSRF_EXEMPT_ROUTES = frozenset((
    "/login",
    "/api/webhook/ingest",
    "/api/health",
))
CSRF_EXEMPT_PREFIXES = (
    "/api/ui/",  # Read-only API endpoints
    "/static/",
)


class SessionError(Exception):
    """Raised when session operations fail critically."""
    pass


def _get_csrf_token(request: Request) -> str:
    """Get or create CSRF token for the session.

    CRITICAL INVARIANT: This function MUST return a token that is stored in session.
    If session read/write fails, this raises SessionError (results in 500).
    Never return a token that isn't stored - that causes silent CSRF failures.
    """
    path = request.url.path
    ip = _get_client_ip(request)

    try:
        token = request.session.get(CSRF_SESSION_KEY)
        if not token:
            token = secrets.token_urlsafe(32)
            request.session[CSRF_SESSION_KEY] = token
        return str(token)
    except Exception as e:
        # Session access failed - this is a critical server error
        # Log with context but NEVER log token values
        actor = None
        tenant = None
        try:
            actor = request.session.get(AUTH_SESSION_KEY)
            tenant = request.session.get(AUTH_TENANT_KEY)
        except Exception:
            pass
        logger.error(
            "Session failure during CSRF token operation: path=%s ip=%s actor=%s tenant=%s error=%s",
            path, ip, actor, tenant, str(e)
        )
        # Raise to trigger 500 error - do NOT return unstored token
        raise SessionError(f"Session unavailable: {e}") from e


def _validate_csrf(request: Request, form_token: Optional[str] = None) -> bool:
    """
    Validate CSRF token from form or header against session.
    Returns True if valid, False otherwise.

    LOGGING POLICY: Never log token values or prefixes. Only log:
    - path, ip, actor_id, tenant_id
    - token status: "present" or "missing"
    """
    try:
        session_token = request.session.get(CSRF_SESSION_KEY)
        if not session_token:
            return False

        # Check form field first
        if form_token:
            return hmac.compare_digest(str(form_token), str(session_token))

        # Check header
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if header_token:
            return hmac.compare_digest(str(header_token), str(session_token))

        return False
    except Exception:
        return False


def _require_csrf(request: Request, form_token: Optional[str] = None) -> None:
    """
    Require valid CSRF token. Raises HTTPException if invalid.
    Skips validation for exempt routes and non-HTML requests.
    """
    path = request.url.path

    # Check exempt routes
    if path in CSRF_EXEMPT_ROUTES:
        return
    for prefix in CSRF_EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return

    # Skip for API requests (they use Bearer tokens, not session auth)
    content_type = str(request.headers.get("content-type") or "").lower()
    accept = str(request.headers.get("accept") or "").lower()
    if "application/json" in content_type and "text/html" not in accept:
        # JSON API request - typically uses different auth mechanism
        return

    # Validate CSRF token
    if not _validate_csrf(request, form_token):
        logger.warning("CSRF validation failed for %s from %s - form_token: %s", path, _get_client_ip(request), "present" if form_token else "missing")
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _session_key_for_tenant(tenant_id: str) -> str:
    return f"active_run_id::{tenant_id}"


def _tenant_alert_id(tenant_id: str, alert_id: str) -> str:
    t = str(tenant_id or TENANT_DEFAULT)
    a = str(alert_id or "")
    if not a:
        return ""
    prefix = f"{t}:"
    if a.startswith(prefix):
        return a
    return f"{prefix}{a}"


def _strip_tenant_alert_id(tenant_id: str, alert_id: str) -> str:
    if not alert_id:
        return ""
    prefix = f"{tenant_id}:"
    if alert_id.startswith(prefix):
        return alert_id[len(prefix) :]
    return alert_id


def _alert_id_filter_clause(tenant_id: str) -> Tuple[str, Tuple[str, ...]]:
    if tenant_id == TENANT_DEFAULT:
        return "(alert_id LIKE ? OR alert_id NOT LIKE '%:%')", (f"{tenant_id}:%",)
    return "alert_id LIKE ?", (f"{tenant_id}:%",)


def _tenant_alert_ids(tenant_id: str, alert_ids: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for aid in alert_ids:
        ta = _tenant_alert_id(tenant_id, aid)
        if ta and ta not in seen:
            out.append(ta)
            seen.add(ta)
        if tenant_id == TENANT_DEFAULT and aid and aid not in seen:
            out.append(aid)
            seen.add(aid)
    return out


def _get_latest_run_id(tenant_id: str) -> Optional[int]:
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT id FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 1",
                (TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return int(row["id"]) if row else None


def _get_active_run_id(request: Request, run_id_param: Optional[int] = None) -> Optional[int]:
    """Return the active run id for this request.

    Priority:
      1) explicit ?run_id= (also persists to session)
      2) session-stored active_run_id
      3) None (caller may fall back to latest)
    """
    tenant_id = _tenant_id(request)
    key = _session_key_for_tenant(tenant_id)
    if run_id_param is not None:
        try:
            rid = int(run_id_param)
            request.session[key] = rid
            return rid
        except Exception:
            pass

    try:
        rid = request.session.get(key)
        return int(rid) if rid is not None else None
    except Exception:
        return None


def _clear_active_run(request: Request) -> None:
    try:
        tenant_id = _tenant_id(request)
        key = _session_key_for_tenant(tenant_id)
        request.session.pop(key, None)
    except Exception:
        pass


def _run_snapshot(run_id: int, tenant_id: str) -> Optional[Dict[str, Any]]:
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT id, created_at, filename, summary_json, alerts_json, quality_json FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (int(run_id), TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, created_at, filename, summary_json, alerts_json, quality_json FROM runs WHERE id = ?",
                (int(run_id),),
            ).fetchone()
    if not row:
        return None
    return {
        "id": int(row["id"]),
        "created_at": str(row["created_at"]),
        "filename": str(row["filename"]),
        "tenant_id": str(row["tenant_id"]) if ("tenant_id" in row.keys() and row["tenant_id"] is not None) else TENANT_DEFAULT,
        "summary": safe_json_loads(row["summary_json"], {}) or {},
        "alerts": safe_json_loads(row["alerts_json"], []) or [],
        "quality": safe_json_loads(row["quality_json"], {}) or {},
    }


def _active_and_latest(request: Request, run_id_param: Optional[int] = None) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Return (active_run_snapshot, latest_run_snapshot)."""
    tenant_id = _tenant_id(request)
    latest_id = _get_latest_run_id(tenant_id)
    latest = _run_snapshot(latest_id, tenant_id) if latest_id is not None else None

    active_id = _get_active_run_id(request, run_id_param)
    if active_id is None:
        return latest, latest

    active = _run_snapshot(active_id, tenant_id)
    if active is None:
        # Stale session or bad param; fall back safely.
        _clear_active_run(request)
        return latest, latest

    return active, latest


def _run_qs(active: Optional[Dict[str, Any]], latest: Optional[Dict[str, Any]]) -> str:
    """Querystring used to preserve run context in links."""
    try:
        if active and latest and int(active["id"]) != int(latest["id"]):
            return f"?run_id={int(active['id'])}"
    except Exception:
        pass
    return ""


def _run_scope_context(
    active_run: Optional[Dict[str, Any]],
    latest_run: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    current = active_run or latest_run
    if not current:
        return None
    is_latest = False
    if latest_run:
        try:
            is_latest = int(current.get("id")) == int(latest_run.get("id"))
        except Exception:
            is_latest = False
    return {
        "run_id": int(current.get("id")) if current.get("id") is not None else None,
        "created_at": str(current.get("created_at") or ""),
        "filename": str(current.get("filename") or ""),
        "tenant_id": str(current.get("tenant_id") or ""),
        "is_latest": bool(is_latest),
    }

# ----------------------------
# Formatting helpers
# ----------------------------
def money(x: float, ccy: str) -> str:
    """Human money formatting.

    Demo defaults to 0 decimal places to avoid raw float noise. Internally we
    keep full precision for deterministic checks; formatting is for display only.
    """
    try:
        x = float(x)
    except Exception:
        return f"{ccy} —"
    if not math.isfinite(x):
        return f"{ccy} —"
    return f"{ccy} {x:,.0f}"


def pct(x: float) -> str:
    """Format a fraction as a percentage for UI display."""
    if x is None:
        return "—"
    try:
        p = float(x) * 100.0
    except Exception:
        return "—"
    if not math.isfinite(p):
        return "—"
    if p == 0:
        return "0%"
    if abs(p) < 1.0:
        return f"{p:.1f}%"
    return f"{p:.0f}%"
    

def num(x: float, decimals: int = 2) -> str:
    """Generic numeric formatter to prevent trust-killing float spam."""
    try:
        x = float(x)
    except Exception:
        return "—"
    if not math.isfinite(x):
        return "—"
    if abs(x) >= 1000:
        return f"{x:,.{max(0, int(decimals))}f}".rstrip("0").rstrip(".")
    return f"{x:.{max(0, int(decimals))}f}".rstrip("0").rstrip(".")


templates.env.filters["money"] = lambda v, ccy="AUD": money(v, ccy)
templates.env.filters["pct"] = lambda v: pct(v)
templates.env.filters["num"] = lambda v, d=2: num(v, int(d))


def days(x: Union[float, int]) -> str:
    try:
        return f"{float(x):.0f} days"
    except Exception:
        return "—"


templates.env.filters["days"] = lambda v: days(v)


def human_dt(s: str) -> str:
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(s)


templates.env.filters["humandt"] = lambda v: human_dt(str(v or ""))


# P1-05: Vendor name redaction for privacy (display-only, no data modification)
# HIGH(5): Expanded to cover common payroll/HR vendor names and patterns
SENSITIVE_VENDOR_PATTERNS = [
    r"(?i)employee",
    r"(?i)salary",
    r"(?i)payroll",
    r"(?i)bonus",
    r"(?i)commission",
    r"(?i)contractor.*payment",
    # Common payroll providers
    r"(?i)\bADP\b",
    r"(?i)\bGusto\b",
    r"(?i)Paychex",
    r"(?i)Rippling",
    r"(?i)Bamboo\s*HR",
    r"(?i)Zenefits",
    r"(?i)Justworks",
    r"(?i)TriNet",
    # UK/Commonwealth patterns
    r"(?i)\bPAYE\b",
    r"(?i)\bHMRC\b",
    # Generic HR/compensation patterns
    r"(?i)compensation",
    r"(?i)\bHR\b",
    r"(?i)Human\s*Resources",
    r"(?i)benefits?\s*admin",
    r"(?i)reimbursement",
]

def redact_vendor(vendor_name: str, user_role: str) -> str:
    """
    Redact sensitive vendor names for non-admin users (display-only).
    Admin users see full names. This does NOT modify stored data.
    """
    if not vendor_name or user_role == "admin":
        return vendor_name

    import re
    for pattern in SENSITIVE_VENDOR_PATTERNS:
        if re.search(pattern, vendor_name):
            return "[Redacted - Sensitive]"

    return vendor_name


templates.env.filters["redact_vendor"] = lambda v, role="viewer": redact_vendor(str(v or ""), str(role or "viewer"))


def _render_or_fallback(
    request: Request,
    template_name: str,
    context: Dict[str, Any],
    fallback_title: str,
    fallback_html: str,
) -> HTMLResponse:
    """Render a template if it exists; otherwise return inline HTML.

    This prevents a 'TemplateNotFound' from nuking a demo.
    """
    # Set access context - each wrapped individually to prevent one failure from blocking others
    try:
        context.setdefault("access_role", _access_role(request))
    except Exception as e:
        logger.warning("Failed to get access_role: %s", e)
        context.setdefault("access_role", "viewer")

    try:
        context.setdefault("access_actor", _actor_id(request))
    except Exception as e:
        logger.warning("Failed to get access_actor: %s", e)
        context.setdefault("access_actor", None)

    try:
        context.setdefault("access_tenant", _tenant_id(request))
    except Exception as e:
        logger.warning("Failed to get access_tenant: %s", e)
        context.setdefault("access_tenant", TENANT_DEFAULT)

    # CSRF token is CRITICAL - must always be set for form security
    try:
        csrf = _get_csrf_token(request)
        context.setdefault("csrf_token", csrf)
        logger.debug("CSRF token set in context: %s...", csrf[:10] if csrf else "None")
    except Exception as e:
        logger.error("CRITICAL: Failed to generate CSRF token: %s", e)
        # Generate emergency token and try to store it
        emergency_token = secrets.token_urlsafe(32)
        try:
            request.session[CSRF_SESSION_KEY] = emergency_token
        except Exception:
            pass
        context.setdefault("csrf_token", emergency_token)
    try:
        return templates.TemplateResponse(template_name, context)
    except TemplateNotFound:
        access_note = ""
        role = context.get("access_role")
        actor = context.get("access_actor")
        tenant = context.get("access_tenant")
        if role is not None:
            parts = [f"role: <span style=\"font-family: ui-monospace, SFMono-Regular, Menlo, monospace;\">{role}</span>"]
            if actor:
                parts.append(
                    f"actor: <span style=\"font-family: ui-monospace, SFMono-Regular, Menlo, monospace;\">{actor}</span>"
                )
            if tenant:
                parts.append(
                    f"tenant: <span style=\"font-family: ui-monospace, SFMono-Regular, Menlo, monospace;\">{tenant}</span>"
                )
            access_note = f"<p style=\"color:#555;\">Access context: {' | '.join(parts)}</p>"
        html = f"""
        <!doctype html>
        <html><head><meta charset="utf-8"><title>{fallback_title}</title></head>
        <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px; max-width: 980px; margin: 0 auto;">
          <h1 style="margin:0 0 12px 0;">{fallback_title}</h1>
          {fallback_html}
          {access_note}
          <hr style="margin:24px 0;">
          <p style="color:#666;">(Fallback page rendered because <code>{template_name}</code> is missing.)</p>
        </body></html>
        """
        return HTMLResponse(html, status_code=200)


def _read_only_response(request: Request, title: str, message: str, detail: str):
    accept = str(request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        try:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "title": title,
                    "error_title": title,
                    "error_message": message,
                    "schema_help": None,
                    "actions": [
                        {"label": "Back", "href": "/dashboard"},
                        {"label": "History", "href": "/history"},
                    ],
                    "show_details": False,
                    "error_details": None,
                    "access_role": _access_role(request),
                    "access_actor": _actor_id(request),
                    "access_tenant": _tenant_id(request),
                },
                status_code=403,
            )
        except TemplateNotFound:
            return HTMLResponse(message, status_code=403)
        except Exception:
            return HTMLResponse(message, status_code=403)
    return JSONResponse({"detail": detail}, status_code=403)


# ----------------------------
# CSV Normalisation
# ----------------------------
def normalise_csv(
    df: pd.DataFrame, return_report: bool = False
) -> Union[pd.DataFrame, Tuple[pd.DataFrame, Dict[str, Any]]]:
    df = df.copy()
    input_cols = [c.strip().lower() for c in df.columns]
    df.columns = input_cols

    rename_map = {
        "transaction_date": "date",
        "txn_date": "date",
        "posted_date": "date",
        "value": "amount",
        "total": "amount",
        "merchant": "counterparty",
        "vendor": "counterparty",
        "supplier": "counterparty",
        "payee": "counterparty",
        "customer": "counterparty",
        "details": "description",
        "memo": "description",
        "note": "description",
        "invoice": "invoice_id",
        "invoice_number": "invoice_id",
    }
    applied_renames: List[Dict[str, str]] = []
    for k, v in rename_map.items():
        if k in df.columns and v not in df.columns:
            df.rename(columns={k: v}, inplace=True)
            applied_renames.append({"from": k, "to": v})

    if "date" not in df.columns:
        raise ValueError("CSV missing required column: date")
    if "amount" not in df.columns:
        raise ValueError("CSV missing required column: amount")

    rows_input = int(len(df))
    date_series = pd.to_datetime(df["date"], errors="coerce", utc=True).dt.tz_convert(None).dt.normalize()
    date_invalid = int(date_series.isna().sum())
    df["date"] = date_series
    df = df.dropna(subset=["date"])

    # Robust amount parsing for common exports: handle thousands separators like "1,234.56".
    # (Locale-specific decimal commas are not supported; keep behavior deterministic.)
    amount_invalid = 0
    try:
        amt = df["amount"].astype(str).str.strip()
        neg_paren = amt.str.match(r"^\(.*\)$")
        amt = amt.str.replace(r"[()]", "", regex=True)
        amt = amt.str.replace(",", "", regex=False)
        amt = amt.str.replace(r"[^0-9\.\-]", "", regex=True)
        amt_num = pd.to_numeric(amt, errors="coerce")
        amount_invalid = int(amt_num.isna().sum())
        amt_num = amt_num.fillna(0.0).astype(float)
        amt_num = np.where(neg_paren, -np.abs(amt_num), amt_num)
        df["amount"] = amt_num
    except Exception:
        amt_raw = df["amount"].astype(str).str.strip()
        neg_paren = amt_raw.str.match(r"^\(.*\)$")
        amt_raw = amt_raw.str.replace(r"[()]", "", regex=True)
        amt_raw = amt_raw.str.replace(",", "", regex=False)
        amt_raw = amt_raw.str.replace(r"[^0-9\.\-]", "", regex=True)
        amt_num = pd.to_numeric(amt_raw, errors="coerce")
        amount_invalid = int(amt_num.isna().sum())
        amt_num = amt_num.fillna(0.0).astype(float)
        amt_num = np.where(neg_paren, -np.abs(amt_num), amt_num)
        df["amount"] = amt_num

    type_inferred = "type" not in df.columns
    if "type" not in df.columns:
        df["type"] = np.where(df["amount"] < 0, "expense", "income")
    df["type"] = df["type"].astype(str).str.lower().str.strip()
    invalid_type_mask = ~df["type"].isin(["income", "expense"])
    df.loc[invalid_type_mask, "type"] = np.where(
        df["amount"] < 0, "expense", "income"
    )
    type_invalid_corrected = int(invalid_type_mask.sum())

    category_defaulted = False
    if "category" not in df.columns:
        df["category"] = "Uncategorised"
        category_defaulted = True
    df["category"] = df["category"].astype(str).str.strip()
    df.loc[df["category"].eq("") | df["category"].isna(), "category"] = "Uncategorised"

    counterparty_defaulted = False
    if "counterparty" not in df.columns:
        df["counterparty"] = "Unknown"
        counterparty_defaulted = True
    df["counterparty"] = df["counterparty"].astype(str).str.strip()
    df.loc[df["counterparty"].eq("") | df["counterparty"].isna(), "counterparty"] = "Unknown"

    description_defaulted = False
    if "description" not in df.columns:
        df["description"] = ""
        description_defaulted = True
    df["description"] = df["description"].astype(str)

    if "invoice_id" in df.columns:
        df["invoice_id"] = df["invoice_id"].astype(str).str.strip()
    if "due_date" in df.columns:
        df["due_date"] = pd.to_datetime(df["due_date"], errors="coerce").dt.normalize()
    if "status" in df.columns:
        df["status"] = df["status"].astype(str).str.lower().str.strip()
    if "direction" in df.columns:
        df["direction"] = df["direction"].astype(str).str.upper().str.strip()

    dedup_cols = [c for c in LEDGER_V1_COLUMNS if c in df.columns]
    rows_before_dedup = int(len(df))
    if dedup_cols:
        df = df.drop_duplicates(subset=dedup_cols, keep="first")
    rows_after_dedup = int(len(df))
    duplicates_dropped = int(rows_before_dedup - rows_after_dedup)

    df["abs_amount"] = df["amount"].abs()
    rename_lookup = {r["to"]: r["from"] for r in applied_renames}
    required_mapping = {}
    for col in ["date", "amount", "type", "category", "counterparty", "description"]:
        if col in input_cols:
            required_mapping[col] = col
        elif col in rename_lookup:
            required_mapping[col] = rename_lookup[col]
        else:
            required_mapping[col] = None
    report = {
        "rows_input": int(rows_input),
        "rows_output": int(len(df)),
        "rows_dropped_missing_date": int(date_invalid),
        "duplicates_dropped": int(duplicates_dropped),
        "duplicate_basis": dedup_cols,
        "amount_parse_invalid": int(amount_invalid),
        "applied_renames": applied_renames,
        "required_column_mapping": required_mapping,
        "defaults_applied": {
            "type_inferred": bool(type_inferred),
            "type_invalid_corrected": int(type_invalid_corrected),
            "category_defaulted": bool(category_defaulted),
            "counterparty_defaulted": bool(counterparty_defaulted),
            "description_defaulted": bool(description_defaulted),
        },
        "columns_input": input_cols,
        "columns_output": [str(c) for c in df.columns],
        "added_columns": ["abs_amount"],
    }
    if return_report:
        return df, report
    return df


# ----------------------------
# Ledger contract + provenance helpers
# ----------------------------
def _ledger_contract_report(df: pd.DataFrame) -> Dict[str, Any]:
    """Strict, deterministic report: what columns we have, what we dropped/kept.

    This does NOT mutate the dataframe. Used for provenance/audit only.
    """
    cols = [str(c) for c in df.columns]
    allowed = set(LEDGER_V1_COLUMNS + ["abs_amount"])
    extra = sorted([c for c in cols if c not in allowed])
    required_fields = ["date", "amount", "type", "category", "counterparty", "description"]
    optional_fields = ["invoice_id", "due_date", "status", "direction"]
    missing_core = sorted([c for c in required_fields if c not in cols])
    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "adapter_version": ADAPTER_VERSION,
        "required_fields": required_fields,
        "optional_fields": optional_fields,
        "columns_present": cols,
        "missing_core": missing_core,
        "extra_columns": extra,
        "row_count": int(len(df)),
    }


def _safe_text(x: Any, max_len: int = 200) -> str:
    s = str(x or "")
    s = s.replace("\x00", "")
    if len(s) > max_len:
        s = s[:max_len]
    return s


# CSV formula injection protection characters
_CSV_FORMULA_CHARS = frozenset(("=", "+", "-", "@", "\t", "\r", "\n"))


def _safe_csv_cell(x: Any) -> str:
    """
    Sanitize a value for CSV export to prevent formula injection.
    Spreadsheet applications (Excel, Google Sheets, LibreOffice Calc) interpret
    cells starting with =, +, -, @ as formulas. This can be exploited to execute
    arbitrary commands when users open the CSV.

    Defense: Prefix dangerous cells with a single quote (') which is the standard
    Excel escape for formula prevention and is generally invisible to users.
    """
    s = str(x) if x is not None else ""
    # Replace newlines and carriage returns with spaces
    s = s.replace("\n", " ").replace("\r", " ")
    # Check if first character is a formula trigger
    if s and s[0] in _CSV_FORMULA_CHARS:
        # Prefix with single quote - Excel's formula escape
        return "'" + s
    return s


def _safe_match_type(v: Any, allowed: set, default: str) -> str:
    s = str(v or "").strip().lower()
    return s if s in allowed else default


def _authorized_entities_for_actor(request: Request) -> List[str]:
    tenant_id = _tenant_id(request)
    actor_id = _actor_id(request)
    entities: List[str] = []
    if actor_id:
        try:
            with db_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT DISTINCT tenant_id
                    FROM access_events
                    WHERE actor_id = ?
                    ORDER BY tenant_id ASC
                    LIMIT 100
                    """,
                    (actor_id,),
                ).fetchall()
            for r in rows:
                val = str(r["tenant_id"] or "").strip()
                if val:
                    entities.append(val)
        except Exception:
            entities = []
    if tenant_id and tenant_id not in entities:
        entities.append(tenant_id)
    return entities


def _confidence_for_rule(source: str, match_type: str) -> str:
    if source == "vendor_rule":
        return "high"
    if source == "override":
        return "high" if match_type in {"equals", "startswith"} else "medium"
    if source == "description_rule":
        return "high" if match_type in {"equals", "startswith"} else "medium"
    return "low"


# ----------------------------
# Deterministic categorisation rules engine
# ----------------------------
def _load_vendor_rules(conn: sqlite3.Connection, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    tenant_key = _normalize_tenant_id(tenant_id) if tenant_id else TENANT_DEFAULT
    # Load tenant-specific rules, falling back to default tenant rules if none exist
    if _table_has_column(conn, "vendor_rules", "tenant_id"):
        rows = conn.execute(
            """
            SELECT id, vendor, match_type, category, is_enabled, priority, note, updated_at
            FROM vendor_rules
            WHERE is_enabled = 1 AND (tenant_id = ? OR tenant_id = 'default')
            ORDER BY CASE WHEN tenant_id = ? THEN 0 ELSE 1 END, priority ASC, id ASC
            LIMIT ?
            """,
            (tenant_key, tenant_key, MAX_RULES_RETURN),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, vendor, match_type, category, is_enabled, priority, note, updated_at
            FROM vendor_rules
            WHERE is_enabled = 1
            ORDER BY priority ASC, id ASC
            LIMIT ?
            """,
            (MAX_RULES_RETURN,),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "vendor": str(r["vendor"] or ""),
                "match_type": str(r["match_type"] or "equals").lower(),
                "category": str(r["category"] or "Uncategorised"),
                "priority": int(r["priority"] or 100),
                "note": str(r["note"] or ""),
                "updated_at": str(r["updated_at"] or ""),
            }
        )
    return out


def _load_description_rules(conn: sqlite3.Connection, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    tenant_key = _normalize_tenant_id(tenant_id) if tenant_id else TENANT_DEFAULT
    # Load tenant-specific rules, falling back to default tenant rules if none exist
    if _table_has_column(conn, "description_rules", "tenant_id"):
        rows = conn.execute(
            """
            SELECT id, pattern, match_type, category, is_enabled, priority, note, updated_at
            FROM description_rules
            WHERE is_enabled = 1 AND (tenant_id = ? OR tenant_id = 'default')
            ORDER BY CASE WHEN tenant_id = ? THEN 0 ELSE 1 END, priority ASC, id ASC
            LIMIT ?
            """,
            (tenant_key, tenant_key, MAX_RULES_RETURN),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, pattern, match_type, category, is_enabled, priority, note, updated_at
            FROM description_rules
            WHERE is_enabled = 1
            ORDER BY priority ASC, id ASC
            LIMIT ?
            """,
            (MAX_RULES_RETURN,),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "pattern": str(r["pattern"] or ""),
                "match_type": str(r["match_type"] or "contains").lower(),
                "category": str(r["category"] or "Uncategorised"),
                "priority": int(r["priority"] or 100),
                "note": str(r["note"] or ""),
                "updated_at": str(r["updated_at"] or ""),
            }
        )
    return out


def _load_override_rules(
    conn: sqlite3.Connection, run_created_at: Optional[str]
) -> List[Dict[str, Any]]:
    if not run_created_at:
        return []
    rows = conn.execute(
        """
        SELECT id, target_field, pattern, match_type, category, confidence, is_enabled, note, created_at
        FROM categorisation_overrides
        WHERE is_enabled = 1 AND datetime(created_at) <= datetime(?)
        ORDER BY created_at ASC, id ASC
        LIMIT ?
        """,
        (str(run_created_at), MAX_RULES_RETURN),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "target_field": str(r["target_field"] or "counterparty").lower(),
                "pattern": str(r["pattern"] or ""),
                "match_type": str(r["match_type"] or "equals").lower(),
                "category": str(r["category"] or "Uncategorised"),
                "confidence": str(r["confidence"] or "high").lower(),
                "note": str(r["note"] or ""),
                "created_at": str(r["created_at"] or ""),
            }
        )
    return out


def _apply_rule_match_series(series: pd.Series, needle: str, match_type: str, enable_regex: bool) -> pd.Series:
    """Return boolean mask. Deterministic and guarded."""
    hay = series.fillna("").astype(str)
    n = _safe_text(needle, MAX_RULE_TEXT_LEN)
    if not n:
        return pd.Series([False] * len(hay), index=hay.index)

    mt = match_type
    if mt == "equals":
        return hay.str.strip().str.lower().eq(n.strip().lower())
    if mt == "startswith":
        return hay.str.strip().str.lower().str.startswith(n.strip().lower())
    if mt == "contains":
        # plain substring match (regex=False => safe)
        return hay.str.lower().str.contains(n.lower(), regex=False)
    if mt == "regex":
        if not enable_regex:
            return pd.Series([False] * len(hay), index=hay.index)
        # Guard: cap pattern length and compile safely
        pat = n
        try:
            re.compile(pat)
        except Exception:
            return pd.Series([False] * len(hay), index=hay.index)
        return hay.str.contains(pat, regex=True, na=False)
    return pd.Series([False] * len(hay), index=hay.index)


def apply_deterministic_categorisation(
    df: pd.DataFrame,
    settings: Dict[str, Any],
    conn: sqlite3.Connection,
    run_created_at: Optional[str] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Apply deterministic rules to fill category for Uncategorised rows.

    Priority order:
      1) manual overrides
      2) vendor_rules
      3) description_rules
      4) keep existing category
      5) fallback 'Uncategorised'

    Returns (df, report) where report is safe to store in params_json.
    """
    enabled = bool(_parse_bool(settings.get("enable_categorisation_rules", True), default=True))
    if not enabled:
        return df, {"enabled": False, "applied": 0, "by_source": {}, "notes": ["categorisation disabled"]}

    enable_regex = bool(_parse_bool(settings.get("enable_regex_rules", False), default=False))
    out = df.copy()
    if "category" not in out.columns:
        out["category"] = "Uncategorised"
    if "counterparty" not in out.columns:
        out["counterparty"] = "Unknown"
    if "description" not in out.columns:
        out["description"] = ""

    # Only attempt to categorise rows that are currently Uncategorised (or blank)
    cat = out["category"].fillna("").astype(str).str.strip()
    unc_mask = cat.eq("") | cat.str.lower().eq("uncategorised") | cat.str.lower().eq("uncategorized")
    if not bool(unc_mask.any()):
        return out, {"enabled": True, "applied": 0, "by_source": {}, "notes": ["nothing uncategorised"]}

    vendor_rules = _load_vendor_rules(conn)
    desc_rules = _load_description_rules(conn)
    override_rules = _load_override_rules(conn, run_created_at)

    applied = 0
    by_source = {"override": 0, "vendor_rule": 0, "description_rule": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    audit_samples: List[Dict[str, Any]] = []

    # overrides (forward-only: created_at <= run_created_at)
    if override_rules:
        for rule in override_rules:
            target = rule["target_field"]
            mt = rule["match_type"]
            mt_allowed = {"equals", "startswith", "contains", "regex"}
            mt = mt if mt in mt_allowed else "equals"
            if mt == "regex" and not enable_regex:
                continue

            series = out.loc[unc_mask, "counterparty"] if target == "counterparty" else out.loc[unc_mask, "description"]
            series = series.fillna("").astype(str)
            mask = _apply_rule_match_series(series, rule["pattern"], mt, enable_regex=enable_regex)
            if not bool(mask.any()):
                continue
            idx = mask[mask].index
            out.loc[idx, "category"] = rule["category"]
            applied_now = int(len(idx))
            applied += applied_now
            by_source["override"] += applied_now
            conf = _confidence_for_rule("override", mt)
            confidence_counts[conf] = int(confidence_counts.get(conf, 0)) + applied_now
            if len(audit_samples) < 30:
                audit_samples.append(
                    {
                        "source": "override",
                        "rule_id": int(rule["id"]),
                        "match_type": mt,
                        "category": rule["category"],
                        "confidence": conf,
                        "example_counterparty": str(out.loc[idx[0], "counterparty"]) if (target == "counterparty" and len(idx)) else "",
                        "example_description": _safe_text(str(out.loc[idx[0], "description"]), 120) if (target == "description" and len(idx)) else "",
                    }
                )
            cat2 = out["category"].fillna("").astype(str).str.strip()
            unc_mask = cat2.eq("") | cat2.str.lower().eq("uncategorised") | cat2.str.lower().eq("uncategorized")
            if not bool(unc_mask.any()):
                break

    # vendor rules
    if vendor_rules:
        cp = out.loc[unc_mask, "counterparty"].fillna("").astype(str)
        for rule in vendor_rules:
            mask = _apply_rule_match_series(cp, rule["vendor"], rule["match_type"], enable_regex=False)
            if not bool(mask.any()):
                continue
            idx = mask[mask].index
            out.loc[idx, "category"] = rule["category"]
            applied_now = int(len(idx))
            applied += applied_now
            by_source["vendor_rule"] += applied_now
            conf = _confidence_for_rule("vendor_rule", rule["match_type"])
            confidence_counts[conf] = int(confidence_counts.get(conf, 0)) + applied_now
            if len(audit_samples) < 30:
                audit_samples.append(
                    {
                        "source": "vendor_rule",
                        "rule_id": int(rule["id"]),
                        "match_type": rule["match_type"],
                        "category": rule["category"],
                        "confidence": conf,
                        "example_counterparty": str(out.loc[idx[0], "counterparty"]) if len(idx) else "",
                    }
                )
            # refresh unc_mask after applying
            cat2 = out["category"].fillna("").astype(str).str.strip()
            unc_mask = cat2.eq("") | cat2.str.lower().eq("uncategorised") | cat2.str.lower().eq("uncategorized")
            if not bool(unc_mask.any()):
                break

    # description rules
    if bool(unc_mask.any()) and desc_rules:
        desc = out.loc[unc_mask, "description"].fillna("").astype(str)
        for rule in desc_rules:
            mt = rule["match_type"]
            mt_allowed = {"equals", "startswith", "contains", "regex"}
            mt = mt if mt in mt_allowed else "contains"
            mask = _apply_rule_match_series(desc, rule["pattern"], mt, enable_regex=enable_regex)
            if not bool(mask.any()):
                continue
            idx = mask[mask].index
            out.loc[idx, "category"] = rule["category"]
            applied_now = int(len(idx))
            applied += applied_now
            by_source["description_rule"] += applied_now
            conf = _confidence_for_rule("description_rule", mt)
            confidence_counts[conf] = int(confidence_counts.get(conf, 0)) + applied_now
            if len(audit_samples) < 30:
                audit_samples.append(
                    {
                        "source": "description_rule",
                        "rule_id": int(rule["id"]),
                        "match_type": mt,
                        "category": rule["category"],
                        "confidence": conf,
                        "example_description": _safe_text(str(out.loc[idx[0], "description"]), 120) if len(idx) else "",
                    }
                )
            cat2 = out["category"].fillna("").astype(str).str.strip()
            unc_mask = cat2.eq("") | cat2.str.lower().eq("uncategorised") | cat2.str.lower().eq("uncategorized")
            if not bool(unc_mask.any()):
                break

    report = {
        "enabled": True,
        "applied": int(applied),
        "by_source": by_source,
        "confidence_counts": confidence_counts,
        "override_rules_count": int(len(override_rules)),
        "vendor_rules_count": int(len(vendor_rules)),
        "description_rules_count": int(len(desc_rules)),
        "enable_regex_rules": bool(enable_regex),
        "samples": audit_samples,
    }
    return out, report


# ----------------------------
# Alert model
# ----------------------------
@dataclass
class Alert:
    id: str
    severity: str
    title: str
    why: str

    # INTERNAL-ONLY: Deprecated field retained for backward compatibility.
    # NOT advisory. NOT recommendations. Empty in all new alerts.
    suggested_actions: List[str]

    # INTERNAL-ONLY: Observational context for human review.
    # NOT recommendations. NOT advice. Descriptive only.
    # API consumers MUST NOT interpret these as guidance or suggestions.
    review_considerations: List[str]

    # INTERNAL-ONLY: Reserved schema field for future structured context.
    # NOT advisory. NOT recommendations. Currently unused metadata.
    api_considerations: Dict[str, Any]

    signal_strength: str
    evidence: Dict[str, Any]
    suppressed: bool = False
    suppression_reason: str = ""
    quality_context: Dict[str, Any] = field(default_factory=dict)
    severity_band: str = ""
    rule_id: str = ""
    rule_name: str = ""
    rule_version: str = ""
    rule_threshold: Any = ""
    data_requirements: List[str] = field(default_factory=list)
    suppression_reasons: List[str] = field(default_factory=list)



def signal_strength_from_gap(gap: float) -> str:
    if gap >= 0.6:
        return "High"
    if gap >= 0.3:
        return "Medium"
    return "Low"

def severity_from_gap(gap: float) -> str:
    """
    Deterministic severity mapping.
    Severity reflects magnitude of deviation beyond threshold,
    not alert type.
    """
    if gap >= 0.6:
        return "critical"
    if gap >= 0.3:
        return "warning"
    return "info"


def rel_change(new: float, old: float) -> float:
    if old <= 1e-9:
        return 0.0 if new <= 1e-9 else 1.0
    return (new - old) / old


def _standard_severity_band(sev: str) -> str:
    s = str(sev or "").strip().lower()
    if s in {"critical", "warning", "info"}:
        return s
    return "info"


def _enrich_alerts_with_rule_metadata(
    alerts: List[Alert],
    window_days: int,
    burn_days: int,
    recent_days: int,
    comparison_label: str,
    comparison_kind: str,
) -> None:
    for a in alerts:
        rid = str(a.id or "")
        rule = RULE_INDEX.get(rid, {})
        a.severity_band = _standard_severity_band(a.severity)
        a.rule_id = rid
        a.rule_name = str(rule.get("rule") or a.title or rid)
        a.rule_version = str(rule.get("version") or "")
        a.rule_threshold = rule.get("threshold") if isinstance(rule, dict) else ""
        a.data_requirements = list(rule.get("data_gates") or []) if isinstance(rule, dict) else []
        a.suppression_reasons = list(rule.get("suppression_reasons") or []) if isinstance(rule, dict) else []

        ev = a.evidence if isinstance(a.evidence, dict) else {}
        ev.setdefault(
            "inputs",
            {
                "window_days": int(window_days),
                "burn_days": int(burn_days),
                "recent_days": int(recent_days),
                "comparison_label": str(comparison_label),
                "comparison_kind": str(comparison_kind),
            },
        )
        a.evidence = ev


# ----------------------------
# C1.3 — Narrative builders (deterministic)
# ----------------------------
def _comparison_narrative(
    comparison_label: str,
    recent_value: float,
    previous_value: float,
    currency: str,
    delta: float,
) -> str:
    """
    Narrative text must be derivable entirely from evidence fields.
    """
    return (
        f"For {comparison_label}, values were {money(recent_value, currency)} vs "
        f"{money(previous_value, currency)} ({pct(delta)} change)."
    )


# ----------------------------
# C2.2 — Standardised explainability structure
# ----------------------------
def build_explainability(
    *,
    check_name: str,
    comparison_label: Optional[str],
    evidence: Dict[str, Any],
    fired: bool,
    threshold: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Canonical explainability payload.
    This structure is identical for all alerts.
    """
    return {
        "check": check_name,
        "fired": bool(fired),
        "comparison": comparison_label,
        "threshold": threshold,
        "evidence_keys": sorted(list(evidence.keys())),
    }


# ----------------------------
# C2.1 — Non-trigger explainability
# ----------------------------
def non_trigger_reason(
    *,
    check_name: str,
    rule_name: str,
    missing_gates: List[str],
    threshold_crossed: bool,
    suppressed: bool = False,
    suppression_reason: str = "",
) -> Dict[str, Any]:
    """
    Deterministic explanation for why a check did not fire.
    """
    if suppressed:
        return {
            "check": check_name,
            "rule_name": rule_name,
            "fired": False,
            "reason": "suppressed",
            "suppression_reason": suppression_reason,
            "missing_gates": list(missing_gates),
        }
    if missing_gates:
        return {
            "check": check_name,
            "rule_name": rule_name,
            "fired": False,
            "reason": "missing_data",
            "missing_gates": list(missing_gates),
        }
    if not threshold_crossed:
        return {
            "check": check_name,
            "rule_name": rule_name,
            "fired": False,
            "reason": "threshold_not_crossed",
        }
    return {
        "check": check_name,
        "rule_name": rule_name,
        "fired": False,
        "reason": "unknown",
    }

# Add this near the data_quality() function, around line 1100:
def quality_band(score: float) -> str:
    """Map quality score to letter grade."""
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    return "D"

# ----------------------------
# Data completeness
# ----------------------------
def data_quality(df: pd.DataFrame, window_df: pd.DataFrame) -> Dict[str, Any]:
    total = len(df)
    wtotal = len(window_df)

    uncategorised_share = float((window_df["category"] == "Uncategorised").mean()) if wtotal else 1.0
    unknown_vendor_share = float((window_df["counterparty"] == "Unknown").mean()) if wtotal else 1.0

    if wtotal:
        days_span = (window_df["date"].max() - window_df["date"].min()).days + 1
    else:
        days_span = 0

    dup_cols = [c for c in ["date", "amount", "type", "category", "counterparty"] if c in window_df.columns]
    dup_rate = float(window_df.duplicated(subset=dup_cols).mean()) if wtotal else 0.0

    required_fields = ["date", "amount", "type", "category", "counterparty", "description"]
    optional_invoice_fields = ["invoice_id", "due_date", "status"]
    has_invoices = int(all(f in df.columns for f in optional_invoice_fields))
    has_direction = int("direction" in df.columns)
    missing_required = sorted([f for f in required_fields if f not in df.columns])

    score = 100.0
    score -= 25.0 * min(max(uncategorised_share, 0), 1)
    score -= 20.0 * min(max(unknown_vendor_share, 0), 1)
    score -= 15.0 * min(max(dup_rate, 0), 1)

    if days_span < 30:
        score -= 15.0
    elif days_span < 60:
        score -= 8.0

    score += 5.0 * has_invoices
    score += 2.0 * has_direction
    score = min(max(score, 0.0), 100.0)

    flags: List[str] = []
    if uncategorised_share > 0.35:
        flags.append("Many transactions are uncategorised — category labels are missing for a large share of rows.")
    if unknown_vendor_share > 0.25:
        flags.append("Many transactions have unknown counterparties — counterparty labels are missing for a large share of rows.")
    if dup_rate > 0.10:
        flags.append("High duplicate-like rows detected — duplicate-like rate exceeds 10% in the window.")
    if days_span < 30:
        flags.append("Short date coverage — fewer distinct dates observed within the window.")
    if not has_invoices:
        flags.append("Invoice fields not detected — overdue checks will be skipped.")
    if not has_direction:
        flags.append("Direction field not detected — direction-specific checks will be skipped.")

    validation_gates = [
        {"gate": "required_fields_present", "passed": len(missing_required) == 0, "missing": missing_required},
        {"gate": "invoice_fields_present", "passed": bool(has_invoices), "missing": optional_invoice_fields if not has_invoices else []},
        {"gate": "direction_present", "passed": bool(has_direction), "missing": ["direction"] if not has_direction else []},
    ]

    return {
        "score": float(score),
        "band": quality_band(score),
        "total_rows": int(total),
        "window_rows": int(wtotal),
        "window_days_covered": int(days_span),
        "uncategorised_share": float(uncategorised_share),
        "unknown_vendor_share": float(unknown_vendor_share),
        "dup_rate": float(dup_rate),
        "flags": flags,
        "validation_gates": validation_gates,
    }



# ----------------------------
# Alert scoring (used for memory logic)
# ----------------------------
def alert_score(alert_dict: Dict[str, Any]) -> float:
    ev = alert_dict.get("evidence") or {}
    if isinstance(ev, dict) and "gap" in ev:
        try:
            gap_val = float(ev.get("gap", 0.0))
            if gap_val > 0:
                return gap_val
        except (ValueError, TypeError):
            pass

    alert_id = str(alert_dict.get("id", ""))

    if "runway" in alert_id and "runway_days" in ev and "threshold_days" in ev:
        try:
            runway = float(ev.get("runway_days", 0))
            threshold = float(ev.get("threshold_days", 1))
            if threshold > 0:
                return max(0.0, (threshold - runway) / threshold)
        except (ValueError, TypeError):
            pass

    if "expense_spike" in alert_id and "expense_change" in ev:
        try:
            return abs(float(ev.get("expense_change", 0)))
        except (ValueError, TypeError):
            pass

    if "revenue_drop" in alert_id and "income_change" in ev:
        try:
            return abs(float(ev.get("income_change", 0)))
        except (ValueError, TypeError):
            pass

    if "concentration" in alert_id and "share" in ev:
        try:
            return float(ev.get("share", 0))
        except (ValueError, TypeError):
            pass

    ss = str(alert_dict.get("signal_strength", "")).strip().lower()
    if ss == "high":
        return 0.6
    if ss == "medium":
        return 0.3
    if ss == "low":
        return 0.15
    return 0.15


# ----------------------------
# Core analysis
# ----------------------------
def build_summary_and_alerts(
    df: pd.DataFrame, s: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[Alert], Dict[str, Any]]:
    currency = str(s.get("currency", "AUD")).upper().strip() or "AUD"
    starting_cash = float(s.get("starting_cash", 25000.0))
    window_days = int(s.get("window_days", 90))
    burn_days = int(s.get("burn_days", 30))

    low_cash_buffer_days = float(s.get("low_cash_buffer_days", 21))
    expense_spike_pct = float(s.get("expense_spike_pct", 0.35))
    revenue_drop_pct = float(s.get("revenue_drop_pct", 0.25))
    concentration_threshold = float(s.get("concentration_threshold", 0.45))

    large_sigma = float(s.get("large_txn_sigma", 3.0))
    recurring_min_hits = int(s.get("recurring_min_hits", 3))
    overdue_days = int(s.get("overdue_days", 7))
    recent_compare_days = int(s.get("recent_compare_days", 30))

    end_date = df["date"].max()
    start_date = end_date - pd.Timedelta(days=window_days - 1)
    w = df[(df["date"] >= start_date) & (df["date"] <= end_date)].copy()
    if w.empty:
        raise ValueError("No rows in selected window. Increase window_days or check date formatting.")
    window_income = float(w.loc[w["type"] == "income", "abs_amount"].sum())
    window_expense = float(w.loc[w["type"] == "expense", "abs_amount"].sum())
    window_net_change = float(window_income - window_expense)
    window_transaction_count = int(len(w))
    window_dates = w["date"].dt.normalize()
    window_days_observed = int(window_dates.nunique())
    window_days_span_inclusive = int((end_date - start_date).days + 1)
    window_days_with_income = int(w.loc[w["type"] == "income", "date"].dt.normalize().nunique())
    window_days_with_expense = int(w.loc[w["type"] == "expense", "date"].dt.normalize().nunique())
    window_missing_dates = max(int(window_days_span_inclusive - window_days_observed), 0)

    daily = (
        w.groupby(["date", "type"])["abs_amount"]
        .sum()
        .unstack(fill_value=0.0)
        .rename(columns={"income": "income", "expense": "expense"})
        .sort_index()
    )
    if "income" not in daily.columns:
        daily["income"] = 0.0
    if "expense" not in daily.columns:
        daily["expense"] = 0.0
    daily["net"] = daily["income"] - daily["expense"]
    daily["cash"] = starting_cash + daily["net"].cumsum()
    daily_income_min = float(daily["income"].min()) if len(daily) else 0.0
    daily_income_max = float(daily["income"].max()) if len(daily) else 0.0
    daily_income_std = float(daily["income"].std(ddof=0)) if len(daily) else 0.0
    daily_expense_min = float(daily["expense"].min()) if len(daily) else 0.0
    daily_expense_max = float(daily["expense"].max()) if len(daily) else 0.0
    daily_expense_std = float(daily["expense"].std(ddof=0)) if len(daily) else 0.0
    daily_net_min = float(daily["net"].min()) if len(daily) else 0.0
    daily_net_max = float(daily["net"].max()) if len(daily) else 0.0
    daily_net_std = float(daily["net"].std(ddof=0)) if len(daily) else 0.0

    burn_start = end_date - pd.Timedelta(days=burn_days - 1)
    burn_slice = daily.loc[(daily.index >= burn_start) & (daily.index <= end_date)]
    avg_daily_burn = float(burn_slice["expense"].mean()) if len(burn_slice) else float(daily["expense"].mean())
    avg_daily_burn = max(avg_daily_burn, 1e-6)

    current_cash = float(daily["cash"].iloc[-1])
    runway_days = float(current_cash / avg_daily_burn)

    # Compare most-recent vs immediately preceding windows
    recent_days = recent_compare_days if window_days >= 2 * recent_compare_days else max(7, window_days // 2)

    recent_start = end_date - pd.Timedelta(days=recent_days - 1)
    prev_end = recent_start - pd.Timedelta(days=1)
    prev_start = prev_end - pd.Timedelta(days=recent_days - 1)

    recent = w[(w["date"] >= recent_start) & (w["date"] <= end_date)]
    prev = w[(w["date"] >= prev_start) & (w["date"] <= prev_end)]

    recent_income = float(recent.loc[recent["type"] == "income", "abs_amount"].sum())
    recent_expense = float(recent.loc[recent["type"] == "expense", "abs_amount"].sum())
    prev_income = float(prev.loc[prev["type"] == "income", "abs_amount"].sum()) if len(prev) else recent_income
    prev_expense = float(prev.loc[prev["type"] == "expense", "abs_amount"].sum()) if len(prev) else recent_expense
    
    comparison_label = window_comparison_label(recent_days)
    comparison_kind = COMPARISON_KIND_ADJACENT_WINDOWS

    income_change = rel_change(recent_income, prev_income)
    expense_change = rel_change(recent_expense, prev_expense)

    recent_expenses = recent[recent["type"] == "expense"].copy()
    total_recent_expenses = max(float(recent_expense), 1e-6)

    by_vendor = recent_expenses.groupby("counterparty")["abs_amount"].sum().sort_values(ascending=False)
    by_category = recent_expenses.groupby("category")["abs_amount"].sum().sort_values(ascending=False)

    top_vendor = str(by_vendor.index[0]) if len(by_vendor) else "None"
    top_vendor_share = float(by_vendor.iloc[0] / total_recent_expenses) if len(by_vendor) else 0.0
    top_category = str(by_category.index[0]) if len(by_category) else "None"
    top_category_share = float(by_category.iloc[0] / total_recent_expenses) if len(by_category) else 0.0

    exp = w[w["type"] == "expense"]["abs_amount"]
    exp_mean = float(exp.mean()) if len(exp) else 0.0
    exp_std = float(exp.std(ddof=0)) if len(exp) else 0.0
    exp_large_thr = exp_mean + large_sigma * exp_std if exp_std > 0 else (exp_mean * 3 if exp_mean > 0 else 0)

    largest_expense = w[w["type"] == "expense"].sort_values("abs_amount", ascending=False).head(1)

    recurring_candidates = w[w["type"] == "expense"].groupby(["counterparty", "category"]).size().sort_values(ascending=False)
    recurring = recurring_candidates[recurring_candidates >= recurring_min_hits].head(5)
    recurring_list = [{"counterparty": k[0], "category": k[1], "hits": int(v)} for k, v in recurring.items()]

    overdue_ar: List[Dict[str, Any]] = []
    overdue_ap: List[Dict[str, Any]] = []
    has_invoice_fields = ("invoice_id" in w.columns) and ("due_date" in w.columns) and ("status" in w.columns)
    if has_invoice_fields:
        tmp = w.dropna(subset=["due_date"]).copy()
        tmp["days_past_due"] = (end_date - tmp["due_date"]).dt.days
        unpaid_status = {"open", "unpaid", "overdue", "outstanding", "draft"}
        unpaid = tmp[tmp["status"].isin(unpaid_status)].copy()

        if "direction" not in unpaid.columns:
            unpaid["direction"] = np.where(unpaid["type"] == "income", "AR", "AP")

        overdue = unpaid[unpaid["days_past_due"] >= overdue_days]

        def top_overdue(d: pd.DataFrame) -> List[Dict[str, Any]]:
            if d.empty:
                return []
            g = d.groupby("counterparty")["abs_amount"].sum().sort_values(ascending=False).head(5)
            return [{"counterparty": str(vendor), "amount": float(amt)} for vendor, amt in g.items()]

        overdue_ar = top_overdue(overdue[overdue["direction"].str.upper().eq("AR")])
        overdue_ap = top_overdue(overdue[overdue["direction"].str.upper().eq("AP")])

        # Compute aging buckets for stored evidence
        def compute_aging(d: pd.DataFrame) -> Dict[str, Any]:
            if d.empty:
                return {}
            days = d["days_past_due"]
            return {
                "7_30_days": int(((days >= 7) & (days < 30)).sum()),
                "30_60_days": int(((days >= 30) & (days < 60)).sum()),
                "60_90_days": int(((days >= 60) & (days < 90)).sum()),
                "90_plus_days": int((days >= 90).sum()),
                "oldest_days": int(days.max()) if len(days) > 0 else 0,
            }

        overdue_ar_aging = compute_aging(overdue[overdue["direction"].str.upper().eq("AR")])
        overdue_ap_aging = compute_aging(overdue[overdue["direction"].str.upper().eq("AP")])

    cash_series = [{"date": str(idx.date()), "cash": float(v)} for idx, v in daily["cash"].items()]
    exp_breakdown = [{"label": str(cat), "value": float(amt)} for cat, amt in by_category.head(8).items()] if len(by_category) else []
    window_expenses = w[w["type"] == "expense"].copy()
    window_expense_total = float(window_expense)
    concentration_top_n = 5
    if len(window_expenses):
        vendor_totals = (
            window_expenses.groupby("counterparty")["abs_amount"]
            .sum()
            .reset_index()
        )
        vendor_totals["share"] = vendor_totals["abs_amount"] / max(window_expense_total, 1e-6)
        vendor_totals = vendor_totals.sort_values(
            by=["share", "counterparty"],
            ascending=[False, True],
            kind="mergesort",
        )
        top_vendors_expense = [
            {
                "counterparty": str(row["counterparty"]),
                "amount": float(row["abs_amount"]),
                "share": float(row["share"]),
            }
            for _, row in vendor_totals.head(concentration_top_n).iterrows()
        ]
        category_totals = (
            window_expenses.groupby("category")["abs_amount"]
            .sum()
            .reset_index()
        )
        category_totals["share"] = category_totals["abs_amount"] / max(window_expense_total, 1e-6)
        category_totals = category_totals.sort_values(
            by=["share", "category"],
            ascending=[False, True],
            kind="mergesort",
        )
        top_categories_expense = [
            {
                "category": str(row["category"]),
                "amount": float(row["abs_amount"]),
                "share": float(row["share"]),
            }
            for _, row in category_totals.head(concentration_top_n).iterrows()
        ]
    else:
        top_vendors_expense = []
        top_categories_expense = []

    alerts: List[Alert] = []
    fired_checks: set[str] = set()

    if runway_days < low_cash_buffer_days:
        fired_checks.add("runway_tight")
        gap = (low_cash_buffer_days - runway_days) / max(low_cash_buffer_days, 1e-6)
        alerts.append(
            Alert(
    id="runway_tight",
    severity="critical",
    title="Cash runway is getting tight",
    why=(
        f"Average daily outflow over last {burn_days} days is ~{money(avg_daily_burn, currency)}. "
        f"With current cash around {money(current_cash, currency)}, buffer is ~{runway_days:.0f} days "
        f"(threshold {low_cash_buffer_days:.0f})."
    ),
    suggested_actions=[],
    review_considerations=[
        "Next 14 days of scheduled payments and commitments",
        "Overdue invoice status (AR aging report shows collection opportunities)",
        "Upcoming tax, payroll, and supplier obligations",
        "Non-essential discretionary spend that could be deferred",
    ],
    api_considerations={
        "suggested_tools": ["cash_flow_projection", "ar_aging_report", "payment_calendar"],
        "external_context_types": ["industry_payment_terms", "seasonal_cash_patterns"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={
        "avg_daily_burn": avg_daily_burn,
        "current_cash": current_cash,
        "runway_days": runway_days,
        "threshold_days": low_cash_buffer_days,
        "gap": gap,
    },
)
        )

    if expense_change > expense_spike_pct:
        gap = (expense_change - expense_spike_pct) / max(expense_spike_pct, 1e-6)
        fired_checks.add("expense_spike")
        alerts.append(
            Alert(
    id="expense_spike",
    severity=severity_from_gap(gap),
    title="Spending has increased vs the prior period",
    why=_comparison_narrative(
        comparison_label,
        recent_expense,
        prev_expense,
        currency,
        expense_change,
    ),
    suggested_actions=[],
    review_considerations=[
        f"Top expense category: {top_category} ({pct(top_category_share)} of recent spend)",
        f"Top vendor: {top_vendor} ({pct(top_vendor_share)} of recent spend)",
        "Planned vs unplanned spend classification (annual bills, inventory builds, etc.)",
        "Whether this represents a new baseline or one-time event",
    ],
    api_considerations={
        "suggested_tools": ["vendor_analysis", "category_trend", "budget_comparison"],
        "external_context_types": ["vendor_pricing_changes", "industry_cost_inflation"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={
        "comparison_label": comparison_label,
        "comparison_kind": comparison_kind,
        "recent_expense": recent_expense,
        "prev_expense": prev_expense,
        "expense_change": expense_change,
        "narrative_inputs": {
            "recent": recent_expense,
            "previous": prev_expense,
            "delta": expense_change,
        },
        "top_category": top_category,
        "top_vendor": top_vendor,
        "gap": gap,
    },
)
        )
    if income_change < -revenue_drop_pct:
        gap = ((-income_change) - revenue_drop_pct) / max(revenue_drop_pct, 1e-6)
        fired_checks.add("revenue_drop")
        alerts.append(
            Alert(
    id="revenue_drop",
    severity=severity_from_gap(gap),
    title="Income has dropped vs the prior period",
    why=_comparison_narrative(
        comparison_label,
        recent_income,
        prev_income,
        currency,
        income_change,
    ),
    suggested_actions=[],
    review_considerations=[
        "Invoice timing (late invoices) vs genuine demand slowdown (fewer sales)",
        "AR aging: overdue accounts that could accelerate cash if collected",
        "Pipeline and channel performance over last 2-4 weeks",
        "Seasonal patterns or known client payment schedules",
    ],
    api_considerations={
        "suggested_tools": ["sales_pipeline", "ar_aging_report", "revenue_forecast"],
        "external_context_types": ["market_conditions", "seasonal_trends", "client_payment_patterns"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={
        "recent_income": recent_income,
        "prev_income": prev_income,
        "income_change": income_change,
        "comparison_label": comparison_label,
        "comparison_kind": comparison_kind,
        "alert_id_version": ALERT_ID_VERSION,
        "narrative_inputs": {
            "recent": recent_income,
            "previous": prev_income,
            "delta": income_change,
        },
        "gap": gap,
    },
)
        )

    if (top_vendor_share > concentration_threshold) or (top_category_share > concentration_threshold):
        fired_checks.add("expense_concentration")
        share = max(top_vendor_share, top_category_share)
        gap = (share - concentration_threshold) / max(concentration_threshold, 1e-6)
        # Keep severity semantics consistent with signal magnitude. Near-threshold
        # concentration is informational; materially above threshold is actionable.
        sev = "warning" if gap >= 0.3 else "info"
        label = "vendor" if top_vendor_share >= top_category_share else "category"
        who = top_vendor if label == "vendor" else top_category
        alerts.append(
            Alert(
    id="expense_concentration",
    severity=sev,
    title="Expense concentration is high (dependency risk)",
    why=(
        f"Top {label} '{who}' represents about {pct(share)} of expenses in last {recent_days} days "
        f"(threshold {pct(concentration_threshold)}). High concentration can indicate dependency risk "
        f"(e.g., a single supplier or cost bucket driving spend)."
    ),
    suggested_actions=[],
    review_considerations=[
        f"Payment terms and upcoming price changes with {who}",
        "Availability of alternative suppliers for critical items",
        "Current concentration trend (increasing, stable, or decreasing)",
        "Supply chain disruption risk assessment",
    ],
    api_considerations={
        "suggested_tools": ["vendor_concentration_report", "supplier_risk_assessment"],
        "external_context_types": ["market_supplier_availability", "industry_concentration_norms"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={"label": label, "who": who, "share": share, "threshold": concentration_threshold, "gap": gap},
)
        )

    if not largest_expense.empty and exp_large_thr > 0:
        row = largest_expense.iloc[0]
        if float(row["abs_amount"]) >= exp_large_thr:
            fired_checks.add("large_expense")
            gap = (float(row["abs_amount"]) - exp_large_thr) / max(exp_large_thr, 1e-6)
            alerts.append(
                Alert(
    id="large_expense",
    severity="info",
    title="A large expense transaction stands out",
    why=(
        f"Largest expense is {money(float(row['abs_amount']), currency)} to '{row['counterparty']}' "
        f"({row['category']}) on {str(pd.to_datetime(row['date']).date())}. "
        f"Above threshold {money(exp_large_thr, currency)}."
    ),
    suggested_actions=[],
    review_considerations=[
        "Whether this is one-off or recurring expense",
        "Data completeness: potential duplicate or export error",
        "Known seasonal/annual obligations (insurance, licenses, equipment)",
    ],
    api_considerations={
        "suggested_tools": ["transaction_detail_view", "duplicate_detection"],
        "external_context_types": ["vendor_billing_patterns"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={"threshold": exp_large_thr, "mean": exp_mean, "std": exp_std, "sigma": large_sigma, "gap": gap},
)
            )

    if has_invoice_fields and overdue_ar:
        fired_checks.add("overdue_receivables")
        total_overdue = sum(x["amount"] for x in overdue_ar)
        gap = min(total_overdue / max(recent_income, 1e-6), 1.0) if recent_income > 0 else 0.5

        # Build aging summary for why text
        aging_parts = []
        if overdue_ar_aging.get("90_plus_days", 0) > 0:
            aging_parts.append(f"{overdue_ar_aging['90_plus_days']} invoice(s) 90+ days")
        if overdue_ar_aging.get("60_90_days", 0) > 0:
            aging_parts.append(f"{overdue_ar_aging['60_90_days']} invoice(s) 60-90 days")
        if overdue_ar_aging.get("30_60_days", 0) > 0:
            aging_parts.append(f"{overdue_ar_aging['30_60_days']} invoice(s) 30-60 days")
        aging_summary = ", ".join(aging_parts) if aging_parts else f"Oldest: {overdue_ar_aging.get('oldest_days', 0)} days"

        alerts.append(
            Alert(
    id="overdue_receivables",
    severity="warning",
    title="Overdue receivables detected (cash timing risk)",
    why=(f"Receivables appear overdue (>= {overdue_days} days). Top overdue customers sum to ~{money(total_overdue, currency)}. Aging: {aging_summary}."),
    suggested_actions=[],
    review_considerations=[
        "Top 3 overdue customers (highest impact first)",
        "Reminder cadence: pre-due, due date, +7 days, +14 days",
        "Deposit/part-payment terms for new work if chronic overdue persists",
        "Disputed invoices vs simply late payments",
    ],
    api_considerations={
        "suggested_tools": ["ar_aging_report", "customer_payment_history"],
        "external_context_types": ["industry_payment_terms", "customer_credit_profiles"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={"overdue_days": overdue_days, "top_overdue_customers": overdue_ar, "aging": overdue_ar_aging, "gap": gap},
)
        )

    if has_invoice_fields and overdue_ap:
        fired_checks.add("overdue_payables")
        total_overdue = sum(x["amount"] for x in overdue_ap)
        gap = min(total_overdue / max(recent_expense, 1e-6), 1.0) if recent_expense > 0 else 0.3

        # Build aging summary for why text
        aging_parts = []
        if overdue_ap_aging.get("90_plus_days", 0) > 0:
            aging_parts.append(f"{overdue_ap_aging['90_plus_days']} invoice(s) 90+ days")
        if overdue_ap_aging.get("60_90_days", 0) > 0:
            aging_parts.append(f"{overdue_ap_aging['60_90_days']} invoice(s) 60-90 days")
        if overdue_ap_aging.get("30_60_days", 0) > 0:
            aging_parts.append(f"{overdue_ap_aging['30_60_days']} invoice(s) 30-60 days")
        aging_summary = ", ".join(aging_parts) if aging_parts else f"Oldest: {overdue_ap_aging.get('oldest_days', 0)} days"

        alerts.append(
            Alert(
    id="overdue_payables",
    severity="info",
    title="Overdue payables detected (supplier relationship risk)",
    why=(f"Payables appear overdue (>= {overdue_days} days). Top overdue suppliers sum to ~{money(total_overdue, currency)}. Aging: {aging_summary}."),
    suggested_actions=[],
    review_considerations=[
        "Disputed items vs genuinely late payments",
        "Proactive supplier communication if cash-constrained",
        "Invoice status updates (mark settled items)",
    ],
    api_considerations={
        "suggested_tools": ["ap_aging_report", "supplier_relationship_status"],
        "external_context_types": ["supplier_payment_terms", "vendor_credit_limits"],
    },
    signal_strength=signal_strength_from_gap(gap),
    evidence={"overdue_days": overdue_days, "top_overdue_suppliers": overdue_ap, "aging": overdue_ap_aging, "gap": gap},
)
        )

    # ----------------------------
    # C2.1 — record non-trigger reasons (all rules, deterministic)
    # ----------------------------
    non_triggers: List[Dict[str, Any]] = []

    summary = {
        "currency": currency,
        "starting_cash": starting_cash,
        "window_days": window_days,
        "window_start_date": str(start_date.date()),
        "burn_days": burn_days,
        "end_date": str(end_date.date()),
        "window_income": window_income,
        "window_expense": window_expense,
        "window_net_change": window_net_change,
        "window_transaction_count": window_transaction_count,
        "window_days_observed": window_days_observed,
        "window_days_span_inclusive": window_days_span_inclusive,
        "window_days_with_income": window_days_with_income,
        "window_days_with_expense": window_days_with_expense,
        "window_missing_dates": window_missing_dates,
        "concentration_top_n": concentration_top_n,
        "concentration_expense_denominator": window_expense_total,
        "concentration_top_vendors_expense": top_vendors_expense,
        "concentration_top_categories_expense": top_categories_expense,
        "daily_income_min": daily_income_min,
        "daily_income_max": daily_income_max,
        "daily_income_std": daily_income_std,
        "daily_expense_min": daily_expense_min,
        "daily_expense_max": daily_expense_max,
        "daily_expense_std": daily_expense_std,
        "daily_net_min": daily_net_min,
        "daily_net_max": daily_net_max,
        "daily_net_std": daily_net_std,
        "recent_days": recent_days,
        "current_cash": current_cash,
        "avg_daily_burn": avg_daily_burn,
        "runway_days": runway_days,
        "recent_income": recent_income,
        "recent_expense": recent_expense,
        "prev_income": prev_income,
        "prev_expense": prev_expense,
        "comparison_kind": comparison_kind,
        "comparison_label": comparison_label,
        "income_change": income_change,
        "expense_change": expense_change,
        "top_vendor": top_vendor,
        "top_vendor_share": top_vendor_share,
        "top_category": top_category,
        "top_category_share": top_category_share,
        "recurring_expenses": recurring_list,
        "charts": {"cash_series": cash_series, "expense_breakdown": exp_breakdown},
    }

    _enrich_alerts_with_rule_metadata(
        alerts,
        window_days=window_days,
        burn_days=burn_days,
        recent_days=recent_days,
        comparison_label=comparison_label,
        comparison_kind=comparison_kind,
    )
    quality = data_quality(df, w)
    quality_score = float(quality.get("score", 0.0))
    quality_band = str(quality.get("band") or "")
    gate = {
        "threshold": float(QUALITY_SUPPRESSION_THRESHOLD),
        "score": float(quality_score),
        "band": quality_band,
        "suppressed": bool(quality_score < QUALITY_SUPPRESSION_THRESHOLD),
    }
    for a in alerts:
        a.quality_context = {
            "score": float(quality_score),
            "band": quality_band,
            "threshold": float(QUALITY_SUPPRESSION_THRESHOLD),
        }
        if quality_score < QUALITY_SUPPRESSION_THRESHOLD:
            a.suppressed = True
            a.suppression_reason = "Data completeness below threshold"
        else:
            a.suppressed = False
            a.suppression_reason = ""
    missing_gates_map = {
        "runway_tight": [
            g for g in ["daily burn data", "current cash"] if (len(daily) == 0 or not math.isfinite(current_cash) or not math.isfinite(avg_daily_burn))
        ],
        "expense_spike": [] if len(prev) else ["window size >= 2"],
        "revenue_drop": [] if len(prev) else ["window size >= 2"],
        "expense_concentration": [] if ("counterparty" in w.columns and "category" in w.columns) else ["vendor/category data"],
        "large_expense": [] if len(exp) else ["expense distribution stats"],
        "overdue_receivables": [] if has_invoice_fields else ["invoice_id", "due_date", "status columns"],
        "overdue_payables": [] if has_invoice_fields else ["invoice_id", "due_date", "status columns"],
    }
    threshold_crossed_map = {
        "runway_tight": runway_days < low_cash_buffer_days,
        "expense_spike": expense_change > expense_spike_pct,
        "revenue_drop": income_change < -revenue_drop_pct,
        "expense_concentration": (top_vendor_share > concentration_threshold) or (top_category_share > concentration_threshold),
        "large_expense": bool(not largest_expense.empty and exp_large_thr > 0 and float(largest_expense.iloc[0]["abs_amount"]) >= exp_large_thr),
        "overdue_receivables": bool(has_invoice_fields and overdue_ar),
        "overdue_payables": bool(has_invoice_fields and overdue_ap),
    }
    for r in RULE_INVENTORY:
        rid = str(r.get("id") or "")
        if rid in fired_checks:
            continue
        non_triggers.append(
            non_trigger_reason(
                check_name=rid,
                rule_name=str(r.get("rule") or rid),
                missing_gates=missing_gates_map.get(rid, []),
                threshold_crossed=bool(threshold_crossed_map.get(rid, False)),
                suppressed=bool(gate.get("suppressed")),
                suppression_reason="Data completeness below threshold" if gate.get("suppressed") else "",
            )
        )
    summary["alert_quality_gate"] = gate
    summary["non_trigger_explainability"] = non_triggers
    return summary, alerts, quality


# ----------------------------
# Alert memory + events (FIX: no nested DB writes)
# ----------------------------
def get_alert_state_map(tenant_id: str) -> dict:
    with db_conn() as conn:
        try:
            clause, params = _alert_id_filter_clause(tenant_id)
            rows = conn.execute(
                f"SELECT alert_id, status, note, updated_at, last_score FROM alert_state WHERE {clause}",
                params,
            ).fetchall()
        except Exception:
            return {}
    out: Dict[str, Dict[str, Any]] = {}
    prefer: Dict[str, bool] = {}
    for r in rows:
        raw_id = str(r["alert_id"])
        base_id = _strip_tenant_alert_id(tenant_id, raw_id)
        is_namespaced = raw_id.startswith(f"{tenant_id}:")
        if base_id in out and prefer.get(base_id, False) and not is_namespaced:
            continue
        out[base_id] = {
            "status": str(r["status"] or "review"),
            "note": str(r["note"] or ""),
            "updated_at": str(r["updated_at"] or ""),
            "last_score": float(r["last_score"] or 0.0),
        }
        prefer[base_id] = is_namespaced
    return out


def get_feedback_map(run_id: int, tenant_id: str) -> Dict[str, Dict[str, Any]]:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT alert_id, status, note, updated_at FROM alert_feedback WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    out: Dict[str, Dict[str, Any]] = {}
    prefer: Dict[str, bool] = {}
    for r in rows:
        raw_id = str(r["alert_id"])
        base_id = _strip_tenant_alert_id(tenant_id, raw_id)
        is_namespaced = raw_id.startswith(f"{tenant_id}:")
        if base_id in out and prefer.get(base_id, False) and not is_namespaced:
            continue
        out[base_id] = {
            "status": str(r["status"]),
            "note": str(r["note"]),
            "updated_at": str(r["updated_at"]),
        }
        prefer[base_id] = is_namespaced
    return out


def upsert_alert_state(
    alert_id: str,
    status: str,
    note: str,
    run_id: Optional[int],
    score: float,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    now = datetime.utcnow().isoformat()
    own = conn is None
    if own:
        conn = _connect_db()
    try:
        cur = conn.cursor()
        row = cur.execute("SELECT status, last_score FROM alert_state WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO alert_state (alert_id, status, note, updated_at, last_seen_run_id, last_score) VALUES (?, ?, ?, ?, ?, ?)",
                (alert_id, status, note or "", now, run_id, float(score)),
            )
        else:
            prev_score = float(row["last_score"] or 0.0)
            # Track max score ever seen (used for "worsened" checks)
            new_score = max(float(score), prev_score)
            cur.execute(
                "UPDATE alert_state SET status=?, note=?, updated_at=?, last_seen_run_id=?, last_score=? WHERE alert_id=?",
                (status, note or "", now, run_id, new_score, alert_id),
            )
        if own:
            conn.commit()
    finally:
        if own and conn is not None:
            conn.close()


def insert_alert_event(
    run_id: Optional[int],
    alert_id: str,
    event_type: str,
    status: Optional[str] = None,
    note: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    own = conn is None
    if own:
        conn = _connect_db()
    try:
        conn.execute(
            "INSERT INTO alert_events (created_at, run_id, alert_id, event_type, status, note) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), run_id, alert_id, event_type, status, note),
        )
        if own:
            conn.commit()
    finally:
        if own and conn is not None:
            conn.close()


def update_alert_memory_for_run(
    run_id: int, alerts: List[Dict[str, Any]], tenant_id: str, improve_margin: float = 0.15
) -> None:
    """
    Updates alert_state based on current run:
    - Inserts new alerts
    - Reopens resolved alerts if they reappear
    - Auto-resolves alerts that disappear
    - If suppressed alerts worsen, force back to review
    """
    now = datetime.utcnow().isoformat()

    with db_conn() as conn:
        cur = conn.cursor()
        base_ids = [str(a.get("id")) for a in alerts if a.get("id") is not None]
        current_ids = set(_tenant_alert_ids(tenant_id, base_ids))

        # Update/insert all current alerts
        for a in alerts:
            aid = _tenant_alert_id(tenant_id, str(a.get("id")))
            if not aid:
                continue
            score = alert_score(a)

            row = cur.execute("SELECT status, last_score FROM alert_state WHERE alert_id = ?", (aid,)).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO alert_state (alert_id, status, note, updated_at, last_seen_run_id, last_score) VALUES (?, 'review', '', ?, ?, ?)",
                    (aid, now, run_id, float(score)),
                )
                insert_alert_event(run_id, aid, "auto_new", "review", None, conn=conn)
            else:
                prev_status = str(row["status"])
                prev_score = float(row["last_score"] or 0.0)

                worsened = float(score) > (prev_score * 1.15)
                improved = float(score) < (prev_score * (1.0 - improve_margin))

                if prev_status == "resolved":
                    cur.execute(
                        "UPDATE alert_state SET status='review', updated_at=?, last_seen_run_id=?, last_score=? WHERE alert_id=?",
                        (now, run_id, float(score), aid),
                    )
                    insert_alert_event(run_id, aid, "auto_reopened", "review", None, conn=conn)
                else:
                    if prev_status in {"noted", "actioned", "ignore", "snoozed"} and worsened:
                        cur.execute(
                            "UPDATE alert_state SET status='review', updated_at=?, last_seen_run_id=?, last_score=? WHERE alert_id=?",
                            (now, run_id, float(score), aid),
                        )
                        insert_alert_event(
                            run_id,
                            aid,
                            "auto_worsened",
                            "review",
                            f"Alert worsened from {prev_score:.2f} to {score:.2f}",
                            conn=conn,
                        )
                    elif improved:
                        cur.execute(
                            "UPDATE alert_state SET updated_at=?, last_seen_run_id=?, last_score=? WHERE alert_id=?",
                            (now, run_id, float(score), aid),
                        )
                        insert_alert_event(
                            run_id,
                            aid,
                            "auto_improved",
                            prev_status,
                            f"Alert improved from {prev_score:.2f} to {score:.2f}",
                            conn=conn,
                        )
                    else:
                        cur.execute(
                            "UPDATE alert_state SET updated_at=?, last_seen_run_id=?, last_score=? WHERE alert_id=?",
                            (now, run_id, max(float(score), prev_score), aid),
                        )

        # Auto-resolve alerts not present this run
        clause, params = _alert_id_filter_clause(tenant_id)
        rows = cur.execute(
            f"SELECT alert_id, status FROM alert_state WHERE status != 'resolved' AND {clause}",
            params,
        ).fetchall()
        for r in rows:
            aid = str(r["alert_id"])
            if aid not in current_ids:
                cur.execute(
                    "UPDATE alert_state SET status='resolved', updated_at=? WHERE alert_id=?",
                    (now, aid),
                )
                insert_alert_event(run_id, aid, "auto_resolved", "resolved", "Alert no longer triggered", conn=conn)

        conn.commit()


def _apply_effective_feedback(
    alerts: List[Dict[str, Any]],
    per_run_feedback: Dict[str, Dict[str, Any]],
    state: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for a in alerts:
        aid = str(a.get("id") or "")
        fb = per_run_feedback.get(aid) if aid else None
        st = state.get(aid) if aid else None

        if fb:
            status = str(fb.get("status") or "review")
            note = str(fb.get("note") or "")
            updated_at = str(fb.get("updated_at") or "")
        elif st:
            status = str(st.get("status") or "review")
            note = str(st.get("note") or "")
            updated_at = str(st.get("updated_at") or "")
        else:
            status, note, updated_at = "review", "", ""

        ax = dict(a)
        ax["_status"] = status
        ax["_note"] = note
        ax["_updated_at"] = updated_at
        out.append(ax)

    order = {"review": 0, "noted": 1, "actioned": 2, "ignore": 3, "snoozed": 4, "resolved": 5}
    out.sort(key=lambda x: (order.get(str(x.get("_status") or "review"), 9), str(x.get("severity") or "")))
    return out


# ----------------------------
# Run retrieval helpers
# ----------------------------
def _latest_run_snapshot(tenant_id: str) -> Optional[Dict[str, Any]]:
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT id, created_at, filename, summary_json, alerts_json, quality_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 1",
                (TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, created_at, filename, summary_json, alerts_json, quality_json FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
    if not row:
        return None
    return {
        "id": int(row["id"]),
        "created_at": str(row["created_at"]),
        "filename": str(row["filename"]),
        "tenant_id": str(row["tenant_id"]) if ("tenant_id" in row.keys() and row["tenant_id"] is not None) else TENANT_DEFAULT,
        "summary": safe_json_loads(row["summary_json"], {}) or {},
        "alerts": safe_json_loads(row["alerts_json"], []) or [],
        "quality": safe_json_loads(row["quality_json"], {}) or {},
    }


def _latest_run_summary_meta(tenant_id: str) -> Optional[Dict[str, Any]]:
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT id, created_at, summary_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 1",
                (TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, created_at, summary_json FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
    if not row:
        return None
    return {
        "id": int(row["id"]),
        "created_at": str(row["created_at"]),
        "summary": safe_json_loads(row["summary_json"], {}) or {},
    }


def _is_number(x: Any) -> bool:
    try:
        v = float(x)
    except Exception:
        return False
    return math.isfinite(v)


def _run_to_run_fields() -> List[str]:
    return [
        "window_income",
        "window_expense",
        "window_net_change",
        "window_transaction_count",
        "window_days_observed",
        "window_days_span_inclusive",
        "window_days_with_income",
        "window_days_with_expense",
        "window_missing_dates",
        "current_cash",
        "runway_days",
        "recent_income",
        "recent_expense",
        "income_change",
        "expense_change",
        "concentration_expense_denominator",
    ]


def _attach_run_to_run_summary(
    summary: Dict[str, Any], prior_meta: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    if not prior_meta:
        return summary
    prior_summary = prior_meta.get("summary") if isinstance(prior_meta, dict) else None
    if not isinstance(prior_summary, dict):
        return summary
    fields = _run_to_run_fields()
    items: List[Dict[str, Any]] = []
    for key in fields:
        cur_val = summary.get(key)
        prior_val = prior_summary.get(key)
        delta = None
        if _is_number(cur_val) and _is_number(prior_val):
            delta = float(cur_val) - float(prior_val)
        items.append(
            {
                "field": str(key),
                "current": cur_val,
                "prior": prior_val,
                "delta": delta,
            }
        )
    out = dict(summary)
    out["run_to_run"] = {
        "prior_run_id": int(prior_meta.get("id")),
        "prior_created_at": str(prior_meta.get("created_at") or ""),
        "fields": items,
    }
    return out

def _latest_alert_map(latest_run: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not latest_run:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for a in latest_run.get("alerts") or []:
        if isinstance(a, dict) and a.get("id") is not None:
            out[str(a.get("id"))] = a
    return out


def _hash_settings(s: Dict[str, Any]) -> str:
    # Stable hash for idempotency checks (ignores ordering)
    # Do not include secrets in the hash; changing webhook secret should not affect analysis idempotency.
    ss = dict(s or {})
    ss.pop("webhook_secret", None)
    blob = json.dumps(ss, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _safe_source_block(provider: str, mode: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {"provider": str(provider or "unknown"), "mode": str(mode or "unknown")}
    if isinstance(extra, dict):
        # keep it small/safe
        for k, v in extra.items():
            if k in {"path", "note", "ingest_id", "filename"}:
                d[k] = _safe_text(v, 200)
    return d


def _idempotency_key_from_request(request: Request, body: Dict[str, Any]) -> str:
    key = str(request.headers.get("Idempotency-Key") or "").strip()
    if not key:
        key = str(body.get("ingest_id") or "").strip()
    if not key:
        key = str(body.get("idempotency_key") or "").strip()
    return _safe_text(key, 120)


def _ingest_request_hash(provider: str, mode: str, transactions: Any) -> str:
    payload = {"provider": str(provider or ""), "mode": str(mode or ""), "transactions": transactions or []}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _code_version_hash() -> str:
    global _CODE_HASH_CACHE
    if _CODE_HASH_CACHE:
        return _CODE_HASH_CACHE
    try:
        data = Path(__file__).read_bytes()
        _CODE_HASH_CACHE = hashlib.sha256(data).hexdigest()
        return _CODE_HASH_CACHE
    except Exception:
        _CODE_HASH_CACHE = "unavailable"
        return _CODE_HASH_CACHE


def _derive_artifact_ids(
    file_sha256: str, settings_hash: str, code_hash: str, rule_hash: str
) -> Dict[str, str]:
    seed = f"{file_sha256}|{settings_hash}|{code_hash}|{rule_hash}"
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return {
        "snapshot_id": f"snapshot_{h[:16]}",
        "report_id": f"report_{h[:16]}",
    }


def _report_ids_from_run(row: sqlite3.Row, params: Dict[str, Any]) -> Dict[str, str]:
    artifact_ids = params.get("artifact_ids") if isinstance(params, dict) else None
    if isinstance(artifact_ids, dict) and artifact_ids.get("report_id") and artifact_ids.get("snapshot_id"):
        return {"report_id": str(artifact_ids["report_id"]), "snapshot_id": str(artifact_ids["snapshot_id"])}
    file_sha = str(row["file_sha256"]) if ("file_sha256" in row.keys()) and row["file_sha256"] is not None else ""
    settings_hash = str(row["settings_hash"]) if ("settings_hash" in row.keys()) and row["settings_hash"] is not None else ""
    code_hash = str(params.get("code_hash") or "")
    rule_hash = str(params.get("rule_inventory_hash") or "")
    if file_sha and settings_hash and code_hash and rule_hash:
        return _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)
    return {"report_id": f"report_run_{int(row['id'])}", "snapshot_id": f"snapshot_run_{int(row['id'])}"}


def _sanitize_alert_for_export(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove advisory/recommendation fields from alert before export.
    Keeps only deterministic, observational, and compliance-safe fields.
    """
    sanitized = alert.copy()
    # Remove advisory fields that read as recommendations
    sanitized.pop("review_considerations", None)
    sanitized.pop("suggested_actions", None)
    # Remove nested advisory fields
    if "api_considerations" in sanitized:
        api_cons = sanitized.get("api_considerations") or {}
        if isinstance(api_cons, dict):
            api_cons = api_cons.copy()
            api_cons.pop("suggested_tools", None)
            api_cons.pop("external_context_types", None)
            # If empty after stripping, remove entirely
            if not api_cons:
                sanitized.pop("api_considerations", None)
            else:
                sanitized["api_considerations"] = api_cons
    return sanitized

def _build_report_from_run(row: sqlite3.Row) -> Dict[str, Any]:
    params = safe_json_loads(row["params_json"], {}) or {}
    summary = safe_json_loads(row["summary_json"], {}) or {}
    alerts_raw = safe_json_loads(row["alerts_json"], []) or []
    # Sanitize alerts to remove advisory content
    alerts = [_sanitize_alert_for_export(a) if isinstance(a, dict) else a for a in alerts_raw]
    quality = safe_json_loads(row["quality_json"], {}) or {}
    ids = _report_ids_from_run(row, params)
    tenant_id = str(row["tenant_id"]) if ("tenant_id" in row.keys()) and row["tenant_id"] is not None else TENANT_DEFAULT
    source = params.get("source") if isinstance(params, dict) else {}
    ingest_id = ""
    if isinstance(source, dict):
        ingest_id = str(source.get("ingest_id") or "")
    return {
        "report_id": ids["report_id"],
        "snapshot_id": ids["snapshot_id"],
        "run": {
            "run_id": int(row["id"]),
            "created_at": str(row["created_at"]),
            "filename": str(row["filename"]),
            "provider": str((params.get("source") or {}).get("provider") or ""),
            "config_hash": str(params.get("config_hash") or ""),
            "code_hash": str(params.get("code_hash") or ""),
            "rule_inventory_hash": str(params.get("rule_inventory_hash") or ""),
            "rule_inventory_version": str(params.get("rule_inventory_version") or ""),
            "tenant_id": tenant_id,
        },
        "audit": {
            "config_version": str(params.get("config_version") or ""),
            "config_hash": str(params.get("config_hash") or ""),
            "code_hash": str(params.get("code_hash") or ""),
            "rule_inventory_hash": str(params.get("rule_inventory_hash") or ""),
            "tenant_id": tenant_id,
            "ingest_id": ingest_id,
        },
        "summary": summary,
        "alerts": alerts,
        "quality": quality,
    }


def _insight_narratives(
    summary: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    quality: Optional[Dict[str, Any]],
    runway_na: bool,
    runway_note: str,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    currency = str(summary.get("currency", "AUD"))
    comparison_label = str(summary.get("comparison_label") or "")

    current_cash = float(summary.get("current_cash") or 0.0)
    avg_daily_burn = float(summary.get("avg_daily_burn") or 0.0)
    runway_days = summary.get("runway_days")
    burn_days = int(summary.get("burn_days") or 0)

    recent_income = float(summary.get("recent_income") or 0.0)
    prev_income = float(summary.get("prev_income") or 0.0)
    income_change = float(summary.get("income_change") or 0.0)
    recent_expense = float(summary.get("recent_expense") or 0.0)
    prev_expense = float(summary.get("prev_expense") or 0.0)
    expense_change = float(summary.get("expense_change") or 0.0)

    out.append(
        {
            "title": "Cash position",
            "text": f"Current cash is {money(current_cash, currency)}.",
            "evidence": {"current_cash": current_cash, "currency": currency},
        }
    )
    if runway_na:
        out.append(
            {
                "title": "Runway",
                "text": f"Runway is not calculated for this run. {runway_note}".strip(),
                "evidence": {"runway_na": True, "runway_note": runway_note},
            }
        )
    else:
        out.append(
            {
                "title": "Runway",
                "text": f"Calculated runway (static burn) is {float(runway_days):.0f} days based on average daily burn of {money(avg_daily_burn, currency)} over {burn_days} days.",
                "evidence": {
                    "runway_days": float(runway_days or 0.0),
                    "avg_daily_burn": avg_daily_burn,
                    "burn_days": burn_days,
                },
            }
        )

    if comparison_label:
        out.append(
            {
                "title": "Income change",
                "text": (
                    f"Income changed by {pct(income_change)} over {comparison_label} "
                    f"({money(recent_income, currency)} vs {money(prev_income, currency)})."
                ),
                "evidence": {
                    "comparison_label": comparison_label,
                    "recent_income": recent_income,
                    "prev_income": prev_income,
                    "income_change": income_change,
                },
            }
        )
        out.append(
            {
                "title": "Expense change",
                "text": (
                    f"Expenses changed by {pct(expense_change)} over {comparison_label} "
                    f"({money(recent_expense, currency)} vs {money(prev_expense, currency)})."
                ),
                "evidence": {
                    "comparison_label": comparison_label,
                    "recent_expense": recent_expense,
                    "prev_expense": prev_expense,
                    "expense_change": expense_change,
                },
            }
        )

    suppressed_count = 0
    for a in alerts:
        if isinstance(a, dict) and bool(a.get("suppressed")):
            suppressed_count += 1
    out.append(
        {
            "title": "Alert summary",
            "text": f"{len(alerts)} alert(s) in this run; {suppressed_count} suppressed due to data completeness.",
            "evidence": {"alerts_count": int(len(alerts)), "suppressed_count": int(suppressed_count)},
        }
    )

    if isinstance(quality, dict):
        out.append(
            {
                "title": "Data completeness",
                "text": f"Data completeness score is {float(quality.get('score') or 0.0):.0f}/100 ({quality.get('band') or '—'}).",
                "evidence": {
                    "score": float(quality.get("score") or 0.0),
                    "band": str(quality.get("band") or ""),
                },
            }
        )

    return out


def _build_run_params(
    settings,
    source,
    contract,
    cat_report,
    normalization: Optional[Dict[str, Any]] = None,
    config_hash: Optional[str] = None,
    code_hash: Optional[str] = None,
    rule_hash: Optional[str] = None,
    artifact_ids: Optional[Dict[str, str]] = None,
):
    s_for_params = dict(settings or {})
    s_for_params.pop("webhook_secret", None)
    return {
        "settings": s_for_params,
        "source": source,
        "ledger_contract": contract,
        "categorisation": cat_report,
        "normalization": normalization or {},
        "config_version": str(s_for_params.get("config_version") or CONFIG_VERSION),
        "migration_policy": CONFIG_MIGRATION_POLICY,
        "config_hash": str(config_hash or ""),
        "code_hash": str(code_hash or ""),
        "rule_inventory_hash": str(rule_hash or _rule_inventory_hash()),
        "artifact_ids": artifact_ids or {},
        "rule_inventory_version": _rule_inventory_hash(),  # ADD THIS
        "rule_inventory": RULE_INVENTORY,
    }



# ----------------------------
# Authentication Guard (Phase 1)
# ----------------------------
# NOTE: We use a simple route-level check pattern instead of middleware.
# The @app.middleware("http") approach was causing session cookies to not persist
# because responses returned directly from middleware bypass SessionMiddleware's
# response processing (which commits the session cookie).
#
# Solution: Check auth at the start of each protected route, or use the
# 401 exception handler to redirect. The login route sets the session normally.

def _auth_guard(request: Request) -> bool:
    """
    Check if request should be allowed through.
    Returns True if allowed, False if should redirect to login.
    For use at the start of route handlers if needed.
    """
    path = request.url.path

    # Allow public routes
    if path in PUBLIC_ROUTES:
        return True

    # Allow public prefixes
    for prefix in PUBLIC_ROUTE_PREFIXES:
        if path.startswith(prefix):
            return True

    # Check if authenticated
    if _is_authenticated(request):
        # Verify user is still active
        user_id = _current_user_id(request)
        if user_id:
            user = _get_user_by_id(user_id)
            if user and user.get("is_active"):
                # HIGH(7): Check session version - invalidate if role changed
                session_version = request.session.get(AUTH_SESSION_VERSION_KEY, 1)
                current_version = user.get("session_version", 1)
                if session_version != current_version:
                    # Session invalid - role changed since login
                    request.session.clear()
                    return False
                return True
            # User deactivated - clear session
            request.session.clear()
        return False

    # Check dev bypass mode
    dev_bypass_enabled = _parse_bool(os.getenv("SME_EW_DEV_BYPASS", "false"), default=False)
    if dev_bypass_enabled:
        try:
            client_host = str(request.client.host if request.client else "")
            if client_host in ("127.0.0.1", "::1", "localhost"):
                return True
        except Exception:
            pass

    return False


def _require_auth(request: Request):
    """Raise HTTPException if not authenticated."""
    if not _auth_guard(request):
        # D1: Log denied access before raising
        _log_access(
            _tenant_id(request),
            None,  # No actor for unauthenticated
            "none",
            "deny:unauthenticated",
            request.url.path,
            allowed=False
        )
        raise HTTPException(status_code=401, detail="Authentication required")


def _has_accepted_tos(request: Request) -> bool:
    """Check if the current user has accepted the current TOS version."""
    user_id = _current_user_id(request)
    if not user_id:
        return False
    user = _get_user_by_id(user_id)
    if not user:
        return False
    accepted_version = user.get("tos_version")
    return accepted_version == TOS_VERSION


def _require_tos(request: Request):
    """
    Raise HTTPException if TOS not accepted.
    Uses 428 (Precondition Required) to indicate TOS acceptance needed.
    """
    path = request.url.path
    # Exempt routes from TOS check
    for exempt in TOS_ROUTES_EXEMPT:
        if path == exempt or path.startswith(exempt):
            return
    if not _has_accepted_tos(request):
        # D1: Log denied access before raising
        _log_access(
            _tenant_id(request),
            _actor_id(request),
            _access_role(request),
            "deny:tos_not_accepted",
            request.url.path,
            allowed=False
        )
        raise HTTPException(status_code=428, detail="TOS acceptance required")


def require_user(
    request: Request,
    *,
    min_role: Optional[str] = None,
    action: str = "view",
    resource: str = ""
) -> Dict[str, Any]:
    """
    Unified enforcement guard (Task B mandate):
    1) Authentication
    2) TOS acceptance (unless exempt)
    3) Role-based authorization (optional)

    Returns user dict or raises HTTPException.
    """
    # Step 1: Authentication
    _require_auth(request)
    user_id = _current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = _get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Step 2: TOS (unless route is exempt)
    path = request.url.path
    if not any(path.startswith(p) if p.endswith('/') else path == p for p in TOS_ROUTES_EXEMPT):
        _require_tos(request)

    # Step 3: Role (if specified)
    if min_role:
        _require_role(request, min_role, action, resource)
    else:
        # D1: Log successful auth+TOS access (role guard logs separately)
        _log_access(_tenant_id(request), _actor_id(request), _access_role(request), action, resource, allowed=True)

    return user


# Custom SessionError handler - critical session failures
@app.exception_handler(SessionError)
async def session_error_handler(request: Request, exc: SessionError):
    """Handle session failures with friendly error page for HTML, 500 JSON for API."""
    accept = str(request.headers.get("accept") or "").lower()
    path = request.url.path
    ip = _get_client_ip(request)

    logger.error("SessionError handler triggered: path=%s ip=%s", path, ip)

    if "text/html" in accept:
        # Return friendly HTML error page
        return HTMLResponse(
            content="""
            <!doctype html>
            <html>
            <head><meta charset="utf-8"><title>Session Error</title></head>
            <body style="font-family: system-ui, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px;">
                <h1 style="color: #c00;">Session Error</h1>
                <p>Your session could not be accessed. This is usually temporary.</p>
                <p><strong>Please try:</strong></p>
                <ul>
                    <li>Refreshing the page</li>
                    <li>Clearing your browser cookies for this site</li>
                    <li><a href="/login">Logging in again</a></li>
                </ul>
                <p style="color: #666; font-size: 14px;">If this persists, contact support.</p>
            </body>
            </html>
            """,
            status_code=500,
        )
    return JSONResponse({"detail": "Session error", "code": "SESSION_UNAVAILABLE"}, status_code=500)


# Custom 401 handler that redirects to login for HTML requests
@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc: HTTPException):
    """Handle 401 by redirecting to login for HTML, JSON for API."""
    accept = str(request.headers.get("accept") or "").lower()
    path = request.url.path
    # D2: API routes ALWAYS return JSON (never redirect)
    if path.startswith("/api/") or "text/html" not in accept:
        return JSONResponse({
            "error": "unauthenticated",
            "message": exc.detail or "Authentication required",
            "path": path
        }, status_code=401)
    return RedirectResponse(url="/login", status_code=302)


# Custom 403 handler for CSRF and permission failures
@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: HTTPException):
    """Handle 403 by redirecting to appropriate page for HTML, JSON for API.

    CSRF failure handling (production-hardened):
    - Authenticated user: redirect to originating page with ?error=csrf
    - Unauthenticated user: redirect to /login?error=session_expired
    - API/JSON requests: return JSON 403
    """
    accept = str(request.headers.get("accept") or "").lower()
    detail = str(exc.detail or "Forbidden")
    path = request.url.path
    ip = _get_client_ip(request)

    # Check if user is authenticated (session has auth key)
    is_authenticated = False
    try:
        is_authenticated = bool(request.session.get(AUTH_SESSION_KEY))
    except Exception:
        pass  # Session unavailable = not authenticated

    # D2: API routes ALWAYS return JSON (never redirect)
    if path.startswith("/api/") or "text/html" not in accept:
        logger.warning("403 Forbidden (API): path=%s ip=%s detail=%s", path, ip, detail)
        error_code = "insufficient_role" if "forbidden" in detail.lower() else "forbidden"
        return JSONResponse({
            "error": error_code,
            "message": detail,
            "path": path
        }, status_code=403)

    # HTML request handling
    if "CSRF" in detail:
        # CSRF failure
        if is_authenticated:
            # Authenticated user: redirect back to originating page
            referer = request.headers.get("referer")
            if referer:
                # Parse referer to extract path, ensure same-origin
                try:
                    from urllib.parse import urlparse, urlencode
                    parsed = urlparse(referer)
                    # Only use referer if it's same host or no host (relative)
                    if not parsed.netloc or parsed.netloc == request.url.netloc:
                        redirect_path = parsed.path or "/"
                        # Add error param
                        sep = "&" if "?" in redirect_path else "?"
                        redirect_url = f"{redirect_path}{sep}error=csrf"
                        logger.warning("CSRF failure (authenticated): path=%s ip=%s -> redirect to %s", path, ip, redirect_path)
                        return RedirectResponse(url=redirect_url, status_code=302)
                except Exception:
                    pass

            # No valid referer: use sensible defaults based on request path
            if path == "/tos":
                redirect_url = "/tos?error=csrf"
            else:
                redirect_url = "/?error=csrf"
            logger.warning("CSRF failure (authenticated, no referer): path=%s ip=%s -> redirect to %s", path, ip, redirect_url)
            return RedirectResponse(url=redirect_url, status_code=302)
        else:
            # Unauthenticated: session expired or never existed
            logger.warning("CSRF failure (unauthenticated): path=%s ip=%s -> redirect to /login", path, ip)
            return RedirectResponse(url="/login?error=session_expired", status_code=302)

    # Other 403s (permission denied, not CSRF)
    logger.warning("403 Forbidden: path=%s ip=%s detail=%s", path, ip, detail)
    from urllib.parse import quote
    return RedirectResponse(url=f"/error?code=403&message={quote(detail)}", status_code=302)


# ----------------------------
# Generic error page route
# ----------------------------
@app.get("/error", response_class=HTMLResponse)
async def error_page(
    request: Request,
    code: str = Query("error"),
    message: str = Query("An error occurred"),
):
    """Display a user-facing error page for redirected errors (e.g., 403 permission denied)."""
    require_user(request)
    tenant_id = _tenant_id(request)
    actor = _actor_id(request)
    role = _access_role(request)
    _log_access(tenant_id, actor, role, "view", f"error:{code}")

    active_run, latest_run_actual = _active_and_latest(request, None)
    run_scope = _run_scope_context(active_run, latest_run_actual)

    # Context-aware messaging for permission-denied errors
    if code == "403":
        display_title = "Access restricted"
        display_message = "You don't have permission to view this page. If you believe this is an error, contact your administrator."
    else:
        display_title = f"Error {code}"
        display_message = message

    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "title": display_title,
            "error_title": display_title,
            "error_message": display_message,
            "schema_help": None,
            "actions": [
                {"label": "Home", "href": "/dashboard"},
                {"label": "History", "href": "/history"},
            ],
            "show_details": False,
            "error_details": None,
            "access_role": role,
            "access_actor": actor,
            "access_tenant": tenant_id,
            **run_scope,
        },
    )


# Custom 428 handler that redirects to TOS page for HTML requests
@app.exception_handler(428)
async def tos_required_handler(request: Request, exc: HTTPException):
    """Handle 428 by redirecting to TOS page for HTML, JSON for API."""
    accept = str(request.headers.get("accept") or "").lower()
    path = request.url.path
    # D2: API routes ALWAYS return JSON (never redirect)
    if path.startswith("/api/") or "text/html" not in accept:
        return JSONResponse({
            "error": "tos_not_accepted",
            "message": exc.detail or "TOS acceptance required",
            "path": path
        }, status_code=428)
    # HTML: Preserve original destination via 'next' parameter
    if path and path != "/tos":
        from urllib.parse import quote
        return RedirectResponse(url=f"/tos?next={quote(path)}", status_code=302)
    return RedirectResponse(url="/tos", status_code=302)


# ----------------------------
# Password Reset Token Helpers (Phase 4)
# ----------------------------
def _generate_reset_token() -> str:
    """Generate a secure random token for password reset."""
    return secrets.token_urlsafe(32)

def _hash_reset_token(token: str) -> str:
    """Hash reset token for storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _create_reset_token(user_id: int) -> str:
    """Create and store a password reset token. Returns the raw token."""
    token = _generate_reset_token()
    token_hash = _hash_reset_token(token)
    expires_at = (datetime.utcnow() + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)).isoformat()

    with db_conn() as conn:
        # Invalidate any existing tokens for this user
        conn.execute("UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                    (datetime.utcnow().isoformat(), user_id))
        conn.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token_hash, expires_at, datetime.utcnow().isoformat()),
        )
        conn.commit()
    return token

def _validate_reset_token(token: str) -> Optional[int]:
    """Validate reset token. Returns user_id if valid, None otherwise."""
    token_hash = _hash_reset_token(token)
    with db_conn() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        if row["used_at"]:
            return None  # Already used
        try:
            expires = datetime.fromisoformat(str(row["expires_at"]))
            if datetime.utcnow() > expires:
                return None  # Expired
        except Exception:
            return None
        return int(row["user_id"])

def _consume_reset_token(token: str) -> bool:
    """Mark token as used. Returns True if successful."""
    token_hash = _hash_reset_token(token)
    with db_conn() as conn:
        result = conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (datetime.utcnow().isoformat(), token_hash),
        )
        conn.commit()
        return result.rowcount > 0

def _dev_mail_outbox_add(recipient: str, subject: str, body: str, link: str) -> None:
    """Add email to dev outbox (dev mode only)."""
    if _SME_EW_ENV == "production":
        logger.warning("Dev mail outbox not available in production")
        return

    outbox_path = BASE_DIR / DEV_MAIL_OUTBOX_FILE
    entries = []
    try:
        if outbox_path.exists():
            entries = json.loads(outbox_path.read_text())
    except Exception:
        entries = []

    entries.append({
        "id": secrets.token_hex(8),
        "created_at": datetime.utcnow().isoformat(),
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "link": link,
    })

    # Keep only last N entries
    entries = entries[-MAX_DEV_OUTBOX_ENTRIES:]

    try:
        outbox_path.write_text(json.dumps(entries, indent=2))
    except Exception as e:
        logger.warning("Could not write dev mail outbox: %s", e)

    # Also log to console in dev mode
    logger.info("=" * 60)
    logger.info("DEV MAIL OUTBOX - Password Reset Link")
    logger.info("  To: %s", recipient)
    logger.info("  Link: %s", link)
    logger.info("=" * 60)


# ----------------------------
# Authentication Routes (Phase 1, 4)
# ----------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = Query(None)):
    """Display login form."""
    return _render_or_fallback(
        request,
        "login.html",
        {
            "request": request,
            "title": "Login",
            "error": error,
        },
        fallback_title="Login",
        fallback_html="""
        <form method="post" action="/login" style="max-width:400px;">
            <div style="margin-bottom:16px;">
                <label>Email</label><br>
                <input type="email" name="email" required style="width:100%; padding:8px;">
            </div>
            <div style="margin-bottom:16px;">
                <label>Password</label><br>
                <input type="password" name="password" required style="width:100%; padding:8px;">
            </div>
            <button type="submit" style="padding:10px 20px;">Login</button>
        </form>
        <p><a href="/forgot-password">Forgot password?</a></p>
        """,
    )

@app.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    """Process login form."""
    ip_address = _get_client_ip(request)

    # Rate limiting on login attempts
    rate_key = f"login:{ip_address}"
    if not _rate_limit_allow(rate_key, 10, 60):  # 10 attempts per minute
        _log_auth_event(TENANT_DEFAULT, "login_rate_limited", ip_address=ip_address)
        return RedirectResponse(url="/login?error=rate_limited", status_code=302)

    # Find user
    user = _get_user_by_email(email.lower().strip())

    if not user:
        _log_auth_event(TENANT_DEFAULT, "login_failed_no_user", details={"email": email}, ip_address=ip_address)
        return RedirectResponse(url="/login?error=invalid", status_code=302)

    if not user.get("is_active"):
        _log_auth_event(user["tenant_id"], "login_failed_inactive", user_id=user["id"], ip_address=ip_address)
        return RedirectResponse(url="/login?error=invalid", status_code=302)

    if not check_password_hash(user.get("password_hash", ""), password):
        _log_auth_event(user["tenant_id"], "login_failed_password", user_id=user["id"], ip_address=ip_address)
        return RedirectResponse(url="/login?error=invalid", status_code=302)

    # Success - set session
    request.session[AUTH_SESSION_KEY] = user["id"]
    request.session[AUTH_TENANT_KEY] = user["tenant_id"]
    request.session[AUTH_ROLE_KEY] = user["role"]
    request.session[AUTH_EMAIL_KEY] = user["email"]
    request.session[AUTH_SESSION_VERSION_KEY] = user.get("session_version", 1)  # HIGH(7): Store session version

    # Update last login
    with db_conn() as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?",
                    (datetime.utcnow().isoformat(), user["id"]))
        conn.commit()

    _log_auth_event(user["tenant_id"], "login_success", user_id=user["id"], ip_address=ip_address)

    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/logout")
async def logout(request: Request, csrf_token: Optional[str] = Form(None)):
    """Process logout."""
    _require_csrf(request, csrf_token)
    user_id = _current_user_id(request)
    tenant_id = _tenant_id(request)
    ip_address = _get_client_ip(request)

    if user_id:
        _log_auth_event(tenant_id, "logout", user_id=user_id, ip_address=ip_address)

    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# ----------------------------
# TOS (Terms of Service) Routes
# ----------------------------
@app.get("/tos", response_class=HTMLResponse)
async def tos_page(request: Request, next: Optional[str] = Query(None)):
    """Display Terms of Service acceptance page."""
    logger.info("TOS GET - next parameter: %s", next)
    _require_auth(request)
    user_id = _current_user_id(request)
    user = _get_user_by_id(user_id) if user_id else None
    already_accepted = user and user.get("tos_version") == TOS_VERSION
    logger.info("TOS GET - user_id: %s, already_accepted: %s", user_id, already_accepted)

    # ISSUE 3 FIX: Do NOT redirect already-accepted users - allow viewing TOS
    # Only redirect if they are NOT already accepted AND this is NOT the TOS page itself

    # Get CSRF token BEFORE building fallback HTML so it's available for both paths
    csrf = _get_csrf_token(request)
    next_input = f'<input type="hidden" name="next" value="{next}">' if next else ""

    return _render_or_fallback(
        request,
        "tos.html",
        {
            "request": request,
            "title": "Terms of Service",
            "tos_version": TOS_VERSION,
            "already_accepted": already_accepted,
            "next": next,
            "csrf_token": csrf,  # Explicitly pass CSRF token
            "access_role": _access_role(request),
            "access_actor": _actor_id(request),
            "access_tenant": _tenant_id(request),
        },
        fallback_title="Terms of Service",
        fallback_html=f"""
        <h2>Terms of Service (v{TOS_VERSION})</h2>
        <div style="max-width:700px; margin:20px 0; padding:16px; border:1px solid var(--border,#ddd); border-radius:4px; max-height:400px; overflow-y:auto;">
            <h3>Disclaimer</h3>
            <p><strong>Norvion is NOT financial advice.</strong> This tool provides deterministic analysis of uploaded transaction data for informational purposes only. It does not predict future outcomes, make autonomous decisions, or provide investment, accounting, or legal advice.</p>
            <h3>Data Processing</h3>
            <p>All analysis is performed locally using deterministic rules. No data is transmitted to external AI services or third parties for analysis. Your uploaded data remains within your environment.</p>
            <h3>Limitation of Liability</h3>
            <p>The information provided by this tool is for general informational purposes only. You are solely responsible for any decisions made based on this information. Consult qualified professionals for financial, legal, or business advice.</p>
            <h3>Acceptance</h3>
            <p>By clicking "I Accept", you acknowledge that you have read, understood, and agree to these terms.</p>
        </div>
        {"<p><em>You have already accepted this version.</em></p>" if already_accepted else ""}
        <form method="post" action="/tos">
            <input type="hidden" name="csrf_token" value="{csrf}">
            {next_input}
            <button type="submit" style="padding:10px 20px; margin-right:10px;">I Accept</button>
            <a href="/logout" style="padding:10px 20px; text-decoration:none; color:var(--muted);">Decline &amp; Logout</a>
        </form>
        """,
    )


@app.post("/tos")
async def tos_accept(request: Request, csrf_token: Optional[str] = Form(None), next: Optional[str] = Form(None)):
    """Process TOS acceptance."""
    logger.info("TOS POST received - csrf_token: %s, next: %s", "present" if csrf_token else "missing", next)
    _require_csrf(request, csrf_token)
    _require_auth(request)
    user_id = _current_user_id(request)
    logger.info("TOS POST - user_id: %s", user_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    # ISSUE 5 FIX: Check if user has already accepted current TOS version (idempotency)
    user = _get_user_by_id(user_id)
    if user and user.get("tos_version") == TOS_VERSION:
        # Already accepted - no-op, do not re-write DB or duplicate audit log
        logger.info("User %s already accepted TOS version %s - idempotent no-op", user_id, TOS_VERSION)
    else:
        # Record TOS acceptance
        with db_conn() as conn:
            conn.execute(
                "UPDATE users SET tos_accepted_at = ?, tos_version = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), TOS_VERSION, user_id),
            )
            conn.commit()

        _log_auth_event(
            _tenant_id(request),
            "tos_accepted",
            user_id=user_id,
            details={"tos_version": TOS_VERSION},
            ip_address=_get_client_ip(request),
        )

        logger.info("User %s accepted TOS version %s", user_id, TOS_VERSION)

    # Task C: Validate next parameter (no open redirects), default to /dashboard
    redirect_url = "/dashboard"
    if next and next.startswith("/") and not next.startswith("//"):
        redirect_url = next
    logger.info("Redirecting to: %s", redirect_url)
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request, sent: Optional[str] = Query(None)):
    """Display forgot password form."""
    # In production, password reset is disabled without configured mail provider
    is_disabled = _SME_EW_ENV == "production"

    if is_disabled:
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Feature Unavailable",
                "error_title": "Password Reset Unavailable",
                "error_message": "Self-service password reset is not available in this environment. Please contact your system administrator to reset your password.",
                "schema_help": None,
                "actions": [{"label": "Back to Login", "href": "/login"}],
                "show_details": False,
                "error_details": None,
            },
            fallback_title="Feature Unavailable",
            fallback_html="""
            <h2>Password Reset Unavailable</h2>
            <p>Self-service password reset is not available in this environment.</p>
            <p>Please contact your system administrator to reset your password.</p>
            <p><a href="/login">Back to login</a></p>
            """,
        )

    return _render_or_fallback(
        request,
        "forgot_password.html",
        {
            "request": request,
            "title": "Forgot Password",
            "sent": bool(sent),
            "is_dev_mode": True,
        },
        fallback_title="Forgot Password",
        fallback_html="""
        <div style="background:#fff3cd; border:1px solid #ffc107; padding:12px; margin-bottom:16px; border-radius:4px;">
            <strong>Development Mode:</strong> Reset links are logged to console and dev_mail_outbox.json (not emailed).
        </div>
        <p>Enter your email address to receive a password reset link.</p>
        <form method="post" action="/forgot-password" style="max-width:400px;">
            <div style="margin-bottom:16px;">
                <label>Email</label><br>
                <input type="email" name="email" required style="width:100%; padding:8px;">
            </div>
            <button type="submit" style="padding:10px 20px;">Send Reset Link</button>
        </form>
        <p><a href="/login">Back to login</a></p>
        """,
    )

@app.post("/forgot-password")
async def forgot_password_submit(request: Request, email: str = Form(...)):
    """Process forgot password form."""
    ip_address = _get_client_ip(request)

    # In production, password reset is disabled without configured mail provider
    if _SME_EW_ENV == "production":
        _log_auth_event(
            TENANT_DEFAULT,
            "password_reset_blocked_production",
            details={"email": email, "reason": "disabled_in_production"},
            ip_address=ip_address,
        )
        return RedirectResponse(url="/forgot-password", status_code=302)

    # Rate limit (dev mode only)
    rate_key = f"forgot:{ip_address}"
    if not _rate_limit_allow(rate_key, 5, 300):  # 5 attempts per 5 minutes
        return RedirectResponse(url="/forgot-password?sent=1", status_code=302)

    # Always respond with same message (no user enumeration)
    user = _get_user_by_email(email.lower().strip())

    if user and user.get("is_active"):
        # Create token
        token = _create_reset_token(user["id"])

        # Build reset link
        host = request.headers.get("host", "localhost:8000")
        scheme = "http"  # Dev mode only
        reset_link = f"{scheme}://{host}/reset-password/{token}"

        # Dev mode: log to console and outbox
        _dev_mail_outbox_add(
            recipient=user["email"],
            subject="Password Reset Request",
            body=f"Click the link to reset your password: {reset_link}",
            link=reset_link,
        )

        _log_auth_event(user["tenant_id"], "password_reset_requested", user_id=user["id"], ip_address=ip_address)
    else:
        _log_auth_event(TENANT_DEFAULT, "password_reset_no_user", details={"email": email}, ip_address=ip_address)

    # Always redirect with sent=1 (no user enumeration)
    return RedirectResponse(url="/forgot-password?sent=1", status_code=302)

@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str, error: Optional[str] = Query(None)):
    """Display reset password form."""
    # Validate token exists and is valid
    user_id = _validate_reset_token(token)
    if not user_id:
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Invalid Link",
                "error_title": "Invalid or Expired Link",
                "error_message": "This password reset link is invalid or has expired. Please request a new one.",
                "actions": [{"label": "Request New Link", "href": "/forgot-password"}],
            },
            fallback_title="Invalid Link",
            fallback_html="<p>Invalid or expired link. <a href='/forgot-password'>Request a new one</a>.</p>",
        )

    csrf = _get_csrf_token(request)
    return _render_or_fallback(
        request,
        "reset_password.html",
        {
            "request": request,
            "title": "Reset Password",
            "token": token,
            "error": error,
            "csrf_token": csrf,
        },
        fallback_title="Reset Password",
        fallback_html=f"""
        <form method="post" action="/reset-password/{token}" style="max-width:400px;">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <div style="margin-bottom:16px;">
                <label>New Password (min {PASSWORD_MIN_LENGTH} characters)</label><br>
                <input type="password" name="password" required minlength="{PASSWORD_MIN_LENGTH}" style="width:100%; padding:8px;">
            </div>
            <div style="margin-bottom:16px;">
                <label>Confirm Password</label><br>
                <input type="password" name="confirm_password" required style="width:100%; padding:8px;">
            </div>
            <button type="submit" style="padding:10px 20px;">Reset Password</button>
        </form>
        """,
    )

@app.post("/reset-password/{token}")
async def reset_password_submit(
    request: Request,
    token: str,
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: Optional[str] = Form(None),
):
    """Process password reset."""
    _require_csrf(request, csrf_token)
    ip_address = _get_client_ip(request)

    # Validate token
    user_id = _validate_reset_token(token)
    if not user_id:
        return RedirectResponse(url=f"/reset-password/{token}?error=invalid_token", status_code=302)

    # Validate passwords match
    if password != confirm_password:
        return RedirectResponse(url=f"/reset-password/{token}?error=mismatch", status_code=302)

    # Validate password policy
    valid, error_msg = _validate_password(password)
    if not valid:
        return RedirectResponse(url=f"/reset-password/{token}?error=policy", status_code=302)

    # Get user
    user = _get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url=f"/reset-password/{token}?error=invalid_token", status_code=302)

    # Update password
    password_hash = generate_password_hash(password)
    with db_conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()

    # Consume token
    _consume_reset_token(token)

    _log_auth_event(user["tenant_id"], "password_reset_completed", user_id=user_id, ip_address=ip_address)

    return RedirectResponse(url="/login?reset=1", status_code=302)


# ----------------------------
# Step-Up Authentication Routes (Phase 5)
# ----------------------------
@app.get("/stepup", response_class=HTMLResponse)
async def stepup_page(request: Request, next: Optional[str] = Query("/dashboard"), error: Optional[str] = Query(None)):
    """Display step-up authentication form."""
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    return _render_or_fallback(
        request,
        "stepup.html",
        {
            "request": request,
            "title": "Confirm Identity",
            "next": next,
            "error": error,
            "user_email": _actor_id(request),
        },
        fallback_title="Confirm Identity",
        fallback_html=f"""
        <p>Please re-enter your password to continue.</p>
        <form method="post" action="/stepup" style="max-width:400px;">
            <input type="hidden" name="next" value="{next}">
            <div style="margin-bottom:16px;">
                <label>Password</label><br>
                <input type="password" name="password" required style="width:100%; padding:8px;">
            </div>
            <button type="submit" style="padding:10px 20px;">Confirm</button>
        </form>
        """,
    )

@app.post("/stepup")
async def stepup_submit(
    request: Request,
    password: str = Form(...),
    next: str = Form("/dashboard"),
    csrf_token: Optional[str] = Form(None),
):
    """Process step-up authentication."""
    _require_csrf(request, csrf_token)
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    ip_address = _get_client_ip(request)
    user_id = _current_user_id(request)
    tenant_id = _tenant_id(request)

    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    # Get user with password hash
    email = _actor_id(request)
    user = _get_user_by_email(email)

    if not user or not check_password_hash(user.get("password_hash", ""), password):
        _log_auth_event(tenant_id, "stepup_failed", user_id=user_id, ip_address=ip_address)
        # Sanitize next URL: allow only relative paths starting with "/" but NOT "//" (scheme-relative)
        safe_next = next if (next.startswith("/") and not next.startswith("//")) else "/dashboard"
        return RedirectResponse(url=f"/stepup?next={safe_next}&error=invalid", status_code=302)

    # Set step-up verification
    _set_stepup(request)
    _log_auth_event(tenant_id, "stepup_success", user_id=user_id, ip_address=ip_address)

    # Sanitize next URL: allow only relative paths starting with "/" but NOT "//" (scheme-relative)
    safe_next = next if (next.startswith("/") and not next.startswith("//")) else "/dashboard"
    return RedirectResponse(url=safe_next, status_code=302)


# ----------------------------
# User Management Routes (Phase 3 - Admin only)
# ----------------------------
@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    stepup_required: Optional[str] = Query(None),
    stepup_error: Optional[str] = Query(None),
    filter: str = Query("active"),
):
    """List users (manager and admin)."""
    _require_role(request, "manager", "view", "admin_users")
    tenant_id = _tenant_id(request)

    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, tenant_id, email, role, is_active, created_at, last_login_at FROM users WHERE tenant_id = ? ORDER BY is_active DESC, created_at DESC",
            (tenant_id,),
        ).fetchall()

    all_users = [
        {
            "id": int(r["id"]),
            "email": str(r["email"]),
            "role": str(r["role"]),
            "is_active": bool(r["is_active"]),
            "created_at": str(r["created_at"]),
            "last_login_at": str(r["last_login_at"]) if r["last_login_at"] else None,
        }
        for r in rows
    ]

    # Filter users by active/inactive/all
    if filter == "active":
        users = [u for u in all_users if u["is_active"]]
    elif filter == "inactive":
        users = [u for u in all_users if not u["is_active"]]
    else:
        users = all_users

    active_run, latest_run = _active_and_latest(request)
    return _render_or_fallback(
        request,
        "admin_users.html",
        {
            "request": request,
            "title": "User Management",
            "users": users,
            "all_users_count": len(all_users),
            "active_users_count": len([u for u in all_users if u["is_active"]]),
            "inactive_users_count": len([u for u in all_users if not u["is_active"]]),
            "roles": AUTH_ROLES,
            "active_run_id": active_run.get("id") if active_run else None,
            "latest_run_id": latest_run.get("id") if latest_run else None,
            "run_qs": _run_qs(active_run, latest_run),
            "stepup_required": stepup_required == "1",
            "stepup_error": stepup_error,
            "filter": filter,
        },
        fallback_title="User Management",
        fallback_html="<p>User management requires admin_users.html template.</p>",
    )

@app.post("/admin/users/create")
async def admin_create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
    csrf_token: Optional[str] = Form(None),
    stepup_password: Optional[str] = Form(None),
):
    """Create new user (manager and admin, requires step-up)."""
    _require_csrf(request, csrf_token)
    _require_role(request, "manager", "create", "user")

    # Step-up inline: if not verified and no password provided, redirect to form with error
    if not _require_stepup(request):
        if not stepup_password:
            # No step-up password provided, redirect to prompt
            return RedirectResponse(url=f"/admin/users?stepup_required=1", status_code=302)

        # Verify step-up password inline
        user_id = _current_user_id(request)
        tenant_id = _tenant_id(request)
        ip_address = _get_client_ip(request)
        actor_email = _actor_id(request)
        user = _get_user_by_email(actor_email)

        if not user or not check_password_hash(user.get("password_hash", ""), stepup_password):
            _log_auth_event(tenant_id, "stepup_failed", user_id=user_id, ip_address=ip_address)
            return RedirectResponse(url=f"/admin/users?stepup_error=invalid", status_code=302)

        # Step-up successful, set session flag
        _set_stepup(request)
        _log_auth_event(tenant_id, "stepup_success", user_id=user_id, ip_address=ip_address)

    tenant_id = _tenant_id(request)
    ip_address = _get_client_ip(request)
    actor_id = _actor_id(request)
    current_user_id = _current_user_id(request)
    actor_role = _access_role(request)

    # Validate
    valid, error_msg = _validate_password(password)
    if not valid:
        raise HTTPException(status_code=400, detail=error_msg)

    if role not in AUTH_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    # Manager role restriction: can only create viewer or operator roles
    if actor_role == "manager" and role not in ["viewer", "operator"]:
        raise HTTPException(status_code=403, detail="Managers can only create users with Viewer or Operator roles")

    # Check email not already used
    existing = _get_user_by_email(email.lower().strip(), tenant_id)
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")

    # Create user
    password_hash = generate_password_hash(password)
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (tenant_id, email.lower().strip(), password_hash, role, datetime.utcnow().isoformat()),
        )
        new_user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()

    _log_auth_event(
        tenant_id, "user_created",
        user_id=current_user_id,
        actor_id=actor_id,
        target_user_id=new_user_id,
        details={"email": email, "role": role},
        ip_address=ip_address,
    )

    return RedirectResponse(url="/admin/users", status_code=302)

@app.post("/admin/users/{user_id}/update")
async def admin_update_user(
    request: Request,
    user_id: int,
    role: str = Form(...),
    is_active: bool = Form(True),
    csrf_token: Optional[str] = Form(None),
    stepup_password: Optional[str] = Form(None),
):
    """Update user role/status (manager and admin, requires step-up)."""
    _require_csrf(request, csrf_token)
    _require_role(request, "manager", "update", "user")

    # Step-up inline: if not verified and no password provided, redirect to form with error
    if not _require_stepup(request):
        if not stepup_password:
            # No step-up password provided, redirect to prompt
            return RedirectResponse(url=f"/admin/users?stepup_required=1", status_code=302)

        # Verify step-up password inline
        current_user_id = _current_user_id(request)
        tenant_id = _tenant_id(request)
        ip_address = _get_client_ip(request)
        actor_email = _actor_id(request)
        user = _get_user_by_email(actor_email)

        if not user or not check_password_hash(user.get("password_hash", ""), stepup_password):
            _log_auth_event(tenant_id, "stepup_failed", user_id=current_user_id, ip_address=ip_address)
            return RedirectResponse(url=f"/admin/users?stepup_error=invalid", status_code=302)

        # Step-up successful, set session flag
        _set_stepup(request)
        _log_auth_event(tenant_id, "stepup_success", user_id=current_user_id, ip_address=ip_address)

    tenant_id = _tenant_id(request)
    ip_address = _get_client_ip(request)
    actor_id = _actor_id(request)
    current_user_id = _current_user_id(request)
    actor_role = _access_role(request)

    if role not in AUTH_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    # Verify user belongs to tenant
    target_user = _get_user_by_id(user_id)
    if not target_user or target_user["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent any user from changing their own role (only when role change is requested)
    if role is not None and user_id == current_user_id and role != target_user["role"]:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    # Manager role restrictions
    if actor_role == "manager":
        # Managers cannot modify users who are manager or admin
        if target_user["role"] in ["manager", "admin"]:
            raise HTTPException(status_code=403, detail="Managers cannot modify Manager or Admin users")

        # Managers can only assign viewer or operator roles (when role is provided)
        if role is not None and role not in ["viewer", "operator"]:
            raise HTTPException(status_code=403, detail="Managers can only assign Viewer or Operator roles")

    # HIGH(7): Check if role is changing - if so, increment session_version to invalidate existing sessions
    role_changed = target_user["role"] != role

    # Update
    with db_conn() as conn:
        if role_changed:
            # Increment session_version to force re-login
            conn.execute(
                "UPDATE users SET role = ?, is_active = ?, session_version = session_version + 1 WHERE id = ? AND tenant_id = ?",
                (role, 1 if is_active else 0, user_id, tenant_id),
            )
        else:
            conn.execute(
                "UPDATE users SET role = ?, is_active = ? WHERE id = ? AND tenant_id = ?",
                (role, 1 if is_active else 0, user_id, tenant_id),
            )
        conn.commit()

    _log_auth_event(
        tenant_id, "user_updated",
        user_id=current_user_id,
        actor_id=actor_id,
        target_user_id=user_id,
        details={"role": role, "is_active": is_active},
        ip_address=ip_address,
    )

    return RedirectResponse(url="/admin/users", status_code=302)


# ----------------------------
# Routes
# ----------------------------
@app.get("/", response_class=RedirectResponse)
def home_redirect(request: Request):
    require_user(request)  # Auth + TOS enforcement before redirect to prevent page flash
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "home")
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/home", response_class=RedirectResponse)
def home_alias(request: Request):
    require_user(request)  # Auth + TOS enforcement
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "home")
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/latest", response_class=RedirectResponse)
def return_to_latest(request: Request):
    """Clear any selected historical run and return to the latest dataset."""
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "latest_redirect")
    _clear_active_run(request)
    tenant_id = _tenant_id(request)
    latest_id = _get_latest_run_id(tenant_id)
    if latest_id is not None:
        return RedirectResponse(url=f"/run/{int(latest_id)}", status_code=302)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/healthz", response_class=JSONResponse)
def healthz(request: Request):
    """
    Health endpoint with DB connectivity check (P1-04).
    Public route — no authentication, no audit logging (high-frequency endpoint).
    Returns 503 if database is unavailable.
    """
    # P1-04: Database connectivity check
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False

    if not db_ok:
        return JSONResponse(
            {
                "ok": False,
                "app": APP_TITLE,
                "error": "db_unavailable",
                "utc": datetime.utcnow().isoformat()
            },
            status_code=503
        )

    return JSONResponse({
        "ok": True,
        "app": APP_TITLE,
        "utc": datetime.utcnow().isoformat()
    })


@app.get("/api/health", response_class=JSONResponse)
def api_health(request: Request):
    """
    P0-02: Health endpoint (API path alias).
    Public route — delegates to healthz() for single source of truth.
    """
    return healthz(request)


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, run_id: Optional[int] = Query(None)):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "upload")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    s = read_settings(_tenant_id(request))
    run_scope = _run_scope_context(active_run, latest_run_actual)
    return _render_or_fallback(
        request,
        "index.html",
        {
            "request": request,
            "s": s,
            "title": APP_TITLE,
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title=APP_TITLE,
        fallback_html="""
        <p>Upload a CSV at <code>/analyze</code> (POST multipart form field <code>file</code>).</p>
        <p>Or use the UI if <code>templates/index.html</code> exists.</p>
        """,
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, run_id: Optional[int] = Query(None)):
    # manager role can view settings (Phase 3 RBAC)
    _require_role(request, "manager", "view", "settings")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    tenant_id = _tenant_id(request)
    s = read_settings(tenant_id)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    with db_conn() as conn:
        trow = conn.execute(
            "SELECT settings_hash, updated_at FROM tenant_settings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        grow = None
        if not trow:
            grow = conn.execute(
                "SELECT updated_at FROM settings WHERE id = 1",
            ).fetchone()
    settings_scope = "tenant" if trow else "global_fallback"
    settings_hash = str(trow["settings_hash"]) if trow else _canonical_json_hash(s)
    settings_updated_at = str(trow["updated_at"]) if trow else (str(grow["updated_at"]) if grow else "")
    _log_access(
        tenant_id,
        _actor_id(request),
        _access_role(request),
        "view",
        f"settings_scope:{settings_scope}:{settings_hash}",
    )
    # Check for success message after save
    saved = request.query_params.get("saved") == "1"
    return _render_or_fallback(
        request,
        "settings.html",
        {
            "request": request,
            "s": s,
            "title": "Settings",
            "settings_scope": settings_scope,
            "settings_hash": settings_hash,
            "settings_updated_at": settings_updated_at,
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
            "access_role": _access_role(request),
            "access_actor": _actor_id(request),
            "access_tenant": tenant_id,
            "saved": saved,
        },
        fallback_title="Settings",
        fallback_html=(
            "<p>Settings template missing. Updates are disabled in this read-only environment.</p>"
            f"<p>Scope: <code>{settings_scope}</code> • hash: <code>{settings_hash}</code>"
            + (f" • updated: <code>{settings_updated_at}</code>" if settings_updated_at else "")
            + "</p>"
        ),
    )


@app.post("/settings")
def settings_save(
    request: Request,
    currency: str = Form("AUD"),
    starting_cash: float = Form(25000),
    window_days: int = Form(90),
    burn_days: int = Form(30),
    low_cash_buffer_days: int = Form(21),
    expense_spike_pct: float = Form(0.35),
    revenue_drop_pct: float = Form(0.25),
    concentration_threshold: float = Form(0.45),
    large_txn_sigma: float = Form(3.0),
    recurring_min_hits: int = Form(3),
    overdue_days: int = Form(7),
    recent_compare_days: int = Form(30),
    demo_mode: Any = Form(True),
    enable_integrations_scaffold: Any = Form(True),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    _require_role(request, "manager", "update", "settings")
    tenant_id = _tenant_id(request)

    # Read current settings to preserve fields not in form
    current = read_settings(tenant_id)

    # Build updated settings with validated/clamped values
    updated = {
        "config_version": current.get("config_version", CONFIG_VERSION),
        "currency": str(currency).upper()[:3] if currency else "AUD",
        "starting_cash": _clamp_float(starting_cash, 0, 1e12, 25000),
        "window_days": _clamp_int(window_days, 7, 365, 90),
        "burn_days": _clamp_int(burn_days, 7, 180, 30),
        "low_cash_buffer_days": _clamp_int(low_cash_buffer_days, 1, 90, 21),
        "expense_spike_pct": _clamp_float(expense_spike_pct, 0.01, 1.0, 0.35),
        "revenue_drop_pct": _clamp_float(revenue_drop_pct, 0.01, 1.0, 0.25),
        "concentration_threshold": _clamp_float(concentration_threshold, 0.1, 1.0, 0.45),
        "large_txn_sigma": _clamp_float(large_txn_sigma, 1.0, 10.0, 3.0),
        "recurring_min_hits": _clamp_int(recurring_min_hits, 2, 12, 3),
        "overdue_days": _clamp_int(overdue_days, 1, 90, 7),
        "recent_compare_days": _clamp_int(recent_compare_days, 7, 180, 30),
        "demo_mode": _parse_bool(demo_mode, default=True),
        "enable_integrations_scaffold": _parse_bool(enable_integrations_scaffold, default=True),
        # Preserve webhook_secret and other security-sensitive fields from current settings
        "webhook_secret": current.get("webhook_secret", "CHANGE_ME_DEMO_SECRET"),
        "enable_categorisation_rules": current.get("enable_categorisation_rules", True),
        "enable_regex_rules": current.get("enable_regex_rules", False),
    }

    # Save to tenant_settings
    write_tenant_settings(tenant_id, updated)

    # Audit log
    _log_access(
        tenant_id,
        _actor_id(request),
        _access_role(request),
        "update",
        f"settings:{_canonical_json_hash(updated)}",
    )

    logger.info("Settings updated by %s for tenant %s", _actor_id(request), tenant_id)

    accept = str(request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse({"status": "ok", "settings_hash": _canonical_json_hash(updated)})
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.post("/analyze")
async def analyze(request: Request, file: UploadFile = File(...), csrf_token: Optional[str] = Form(None)):
    _require_csrf(request, csrf_token)
    # operator role can upload CSV (Phase 3 RBAC)
    _require_role(request, "operator", "create", "run:analyze")
    tenant_id = _tenant_id(request)
    if not _rate_limit_allow(f"{tenant_id}:upload", RATE_LIMIT_UPLOADS, RATE_LIMIT_WINDOW_S):
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Upload limited",
                "error_title": "Upload limited",
                "error_message": "Too many uploads for this tenant. Please wait and try again.",
                "schema_help": None,
                "actions": [
                    {"label": "Back to Upload", "href": "/upload"},
                    {"label": "Home", "href": "/dashboard"},
                ],
            },
            fallback_title="Upload limited",
            fallback_html="<p>Too many uploads for this tenant. Please wait and try again.</p>",
        )

    filename = str(file.filename or "")
    content_type = str(file.content_type or "").lower().strip()
    has_csv_ext = filename.lower().endswith(".csv")
    if not has_csv_ext and content_type not in CSV_CONTENT_TYPES:
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Upload failed",
                "error_title": "Upload failed",
                "error_message": "Unsupported file type. Please upload a .csv file.",
                "schema_help": None,
                "actions": [
                    {"label": "Back to Upload", "href": "/upload"},
                    {"label": "Home", "href": "/dashboard"},
                ],
            },
            fallback_title="Upload failed",
            fallback_html="<p>Unsupported file type. Please upload a .csv file.</p>",
        )

    # Read content and enforce size
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Upload failed",
                "error_title": "Upload failed",
                "error_message": f"That file is too large for this environment (max {MAX_UPLOAD_BYTES} bytes).",
                "schema_help": None,
                "actions": [
                    {"label": "Back to Upload", "href": "/upload"},
                    {"label": "Home", "href": "/dashboard"},
                    {"label": "History", "href": "/history"},
                ],
            },
            fallback_title="Upload failed",
            fallback_html=f"<p>That file is too large for this environment (max {MAX_UPLOAD_BYTES} bytes).</p>",
        )

    s = read_settings(tenant_id)
    settings_hash = _hash_settings(s)
    file_sha = hashlib.sha256(content).hexdigest()
    code_hash = _code_version_hash()
    rule_hash = _rule_inventory_hash()

    # Idempotency: if same file + same settings already analyzed, reuse the existing run
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "file_sha256") and _table_has_column(conn, "runs", "settings_hash"):
            if _table_has_column(conn, "runs", "tenant_id"):
                row = conn.execute(
                    "SELECT id, params_json FROM runs WHERE file_sha256 = ? AND settings_hash = ? AND COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 1",
                    (file_sha, settings_hash, TENANT_DEFAULT, tenant_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT id, params_json FROM runs WHERE file_sha256 = ? AND settings_hash = ? ORDER BY id DESC LIMIT 1",
                    (file_sha, settings_hash),
                ).fetchone()
            if row:
                params = safe_json_loads(row["params_json"], {}) or {}
                if (
                    str(params.get("code_hash") or "") == str(code_hash)
                    and str(params.get("rule_inventory_hash") or "") == str(rule_hash)
                ):
                    # Persist run context so navigating elsewhere keeps the selected run.
                    try:
                        request.session[_session_key_for_tenant(tenant_id)] = int(row["id"])
                    except Exception:
                        pass
                    return RedirectResponse(url=f"/run/{int(row['id'])}", status_code=303)

    raw_df = None
    try:
        # Demo safety: cap rows at read-time to avoid memory blowups.
        raw_df = pd.read_csv(io.BytesIO(content), nrows=MAX_UPLOAD_ROWS + 1)
        if isinstance(raw_df, pd.DataFrame) and len(raw_df) > MAX_UPLOAD_ROWS:
            return _render_or_fallback(
                request,
                "error.html",
                {
                    "request": request,
                    "title": "Upload failed",
                    "error_title": "Upload failed",
                    "error_message": f"That CSV has too many rows for this environment (max {MAX_UPLOAD_ROWS:,}). Please export a smaller date range and try again.",
                    "schema_help": {
                        "missing_required": [],
                        "expected_headers": ["date", "amount", "type", "category", "counterparty", "description"],
                        "example_header_row": "date,amount,type,category,counterparty,description",
                        "note": "Previous runs are saved and unaffected by a failed upload.",
                    },
                    "actions": [
                        {"label": "Back to Upload", "href": "/upload"},
                        {"label": "Home", "href": "/dashboard"},
                        {"label": "History", "href": "/history"},
                    ],
                },
                fallback_title="Upload failed",
                fallback_html=f"<p>That CSV has too many rows for this environment (max {MAX_UPLOAD_ROWS:,}).</p>",
            )

        df, normalization = normalise_csv(raw_df, return_report=True)

        # P0-01: Defensive polarity validation (prevent silent inversion)
        if "type" in df.columns and "amount" in df.columns:
            income_rows = df[df["type"] == "income"]
            expense_rows = df[df["type"] == "expense"]
            income_negative_count = (income_rows["amount"] < 0).sum() if len(income_rows) > 0 else 0
            expense_positive_count = (expense_rows["amount"] > 0).sum() if len(expense_rows) > 0 else 0
            income_inverted = len(income_rows) > 0 and income_negative_count > len(income_rows) * 0.5
            expense_inverted = len(expense_rows) > 0 and expense_positive_count > len(expense_rows) * 0.5
            if income_inverted or expense_inverted:
                return _render_or_fallback(
                    request,
                    "error.html",
                    {
                        "request": request,
                        "title": "Upload failed",
                        "error_title": "CSV validation failed",
                        "error_message": "Amount polarity appears inverted. Income transactions should be positive, expenses should be negative.",
                        "schema_help": {
                            "missing_required": [],
                            "expected_headers": ["date", "amount", "type", "category", "counterparty", "description"],
                            "example_header_row": "date,amount,type,category,counterparty,description",
                            "note": "Ensure amounts follow standard accounting conventions: positive for income, negative for expenses.",
                        },
                        "actions": [
                            {"label": "Back to Upload", "href": "/upload"},
                            {"label": "Home", "href": "/dashboard"},
                        ],
                    },
                    fallback_title="CSV validation failed",
                    fallback_html="<p>Amount polarity appears inverted. Income transactions should be positive, expenses should be negative.</p>",
                )

        contract = _ledger_contract_report(df)
        run_created_at = datetime.utcnow().isoformat()
        # Categorisation (deterministic, DB-backed)
        with db_conn() as conn:
            df, cat_report = apply_deterministic_categorisation(df, s, conn, run_created_at=run_created_at)
        summary, alerts, quality = build_summary_and_alerts(df, s)
        summary = _attach_run_to_run_summary(summary, _latest_run_summary_meta(tenant_id))
    except Exception as e:
        safe_msg = _safe_log_message(e)
        if safe_msg:
            logger.info("Analyze error: %s: %s", e.__class__.__name__, safe_msg)
        else:
            logger.info("Analyze error: %s", e.__class__.__name__)

        # Build schema-help (strict + explainable). No stack traces shown to end users.
        expected_headers = ["date", "amount", "type", "category", "counterparty", "description"]
        missing_required: List[str] = []

        try:
            if isinstance(raw_df, pd.DataFrame):
                cols = [c.strip().lower() for c in raw_df.columns]
                # mirror the rename map used in normalise_csv (only for explaining missing columns)
                rename_map = {
                    "transaction_date": "date",
                    "txn_date": "date",
                    "posted_date": "date",
                    "value": "amount",
                    "total": "amount",
                }
                mapped = {rename_map.get(c, c) for c in cols}
                for req in ["date", "amount"]:
                    if req not in mapped:
                        missing_required.append(req)
        except Exception:
            missing_required = []

        if not missing_required and "CSV missing required column" in str(e):
            # Fall back to parsing the message
            try:
                missing_required = [str(e).split(":")[-1].strip()]
            except Exception:
                missing_required = []

        schema_help = {
            "missing_required": missing_required,
            "expected_headers": expected_headers,
            "example_header_row": ",".join(expected_headers),
            "note": "Previous runs are saved and unaffected by a failed upload.",
        }

        msg = (
            "We couldn't analyse that CSV. This usually means the file is missing required columns or has an unsupported format."
            if missing_required
            else "We couldn't analyse that CSV. Please check the file format and try again."
        )

        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Upload failed",
                "error_title": "Upload failed",
                "error_message": msg,
                "schema_help": schema_help,
                "actions": [
                    {"label": "Back to Upload", "href": "/upload"},
                    {"label": "Home", "href": "/dashboard"},
                    {"label": "History", "href": "/history"},
                ],
            },
            fallback_title="Upload failed",
            fallback_html=f"<p>{msg}</p><pre style='background:#f6f6f6;padding:12px;border-radius:8px;white-space:pre-wrap;'>{json.dumps(schema_help, indent=2)}</pre>",
        )
    alerts_payload = [a.__dict__ for a in alerts]

    # Provenance / run params (never store secrets)
    try:
        contract
    except Exception:
        contract = {"schema_version": LEDGER_SCHEMA_VERSION, "adapter_version": ADAPTER_VERSION}
    try:
        cat_report
    except Exception:
        cat_report = {"enabled": False, "applied": 0}
    try:
        normalization
    except Exception:
        normalization = {}
    artifact_ids = _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)
    # Build full, auditable run parameters (provenance + contract + categorisation)
    # Secrets are stripped inside _build_run_params
    safe_filename = ""
    try:
        safe_filename = Path(str(file.filename or "")).name
    except Exception:
        safe_filename = str(file.filename or "")
    if not safe_filename:
        safe_filename = "upload.csv"
    params = _build_run_params(
        settings=s,
        source=_safe_source_block("csv_upload", "upload", {"filename": safe_filename}),
        contract=contract,
        cat_report=cat_report,
        normalization=normalization,
        config_hash=settings_hash,
        code_hash=code_hash,
        rule_hash=rule_hash,
        artifact_ids=artifact_ids,
    )

    with db_conn() as conn:
        run_id = _insert_run_row(
            conn=conn,
            created_at=run_created_at,
            filename=str(safe_filename),
            params_json=json.dumps(params),
            summary_json=json.dumps(summary),
            alerts_json=json.dumps(alerts_payload),
            quality_json=json.dumps(quality),
            file_sha256=hashlib.sha256(content).hexdigest(),
            settings_hash=_hash_settings(s),
            tenant_id=tenant_id,
        )
        conn.commit()

    # Update alert memory / resolved status based on this run (single-connection inside)
    try:
        update_alert_memory_for_run(int(run_id), alerts_payload, tenant_id)
    except Exception as e:
        safe_msg = _safe_log_message(e)
        if safe_msg:
            logger.warning("Alert memory update failed (non-fatal): %s: %s", e.__class__.__name__, safe_msg)
        else:
            logger.warning("Alert memory update failed (non-fatal): %s", e.__class__.__name__)

    # Demo-friendly: persist active run context and land on the run page (audit trail)
    try:
        request.session[_session_key_for_tenant(tenant_id)] = int(run_id)
    except Exception:
        pass
    return RedirectResponse(url=f"/run/{run_id}", status_code=303)


@app.get("/history", response_class=HTMLResponse)
def history(request: Request, run_id: Optional[int] = Query(None)):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "history")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    tenant_id = _tenant_id(request)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            rows = conn.execute(
                "SELECT id, created_at, filename, summary_json, quality_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 200",
                (TENANT_DEFAULT, tenant_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, filename, summary_json, quality_json FROM runs ORDER BY id DESC LIMIT 200"
            ).fetchall()

    runs = []
    for r in rows:
        summary = safe_json_loads(r["summary_json"], {}) or {}
        quality = safe_json_loads(r["quality_json"], {}) or {}
        runs.append(
            {
                "id": int(r["id"]),
                "created_at": str(r["created_at"]),
                "filename": str(r["filename"]),
                "end_date": summary.get("end_date"),
                "currency": summary.get("currency", "AUD"),
                "current_cash": float(summary.get("current_cash", 0.0)),
                "runway_days": float(summary.get("runway_days", 0.0)),
                "quality_score": float(quality.get("score", 0.0)),
            }
        )

    return _render_or_fallback(
        request,
        "history.html",
        {
            "request": request,
            "runs": runs,
            "title": "History",
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title="History",
        fallback_html="<p>History template missing. Use <code>/run/&lt;id&gt;</code> or <code>/api/runs</code>.</p>",
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts_control_panel(request: Request, run_id: Optional[int] = Query(None)):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "alerts")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    tenant_id = _tenant_id(request)
    # Always have a chosen snapshot (active if present, else latest)
    latest_run = active_run or latest_run_actual
    latest_alerts_map = _latest_alert_map(latest_run)

    sev_rank = {"critical": 0, "warning": 1, "info": 2}

    # Snapshot-mode: ONLY show alerts triggered in the latest run.
    # This prevents "residual" alerts from prior runs appearing on the Alerts page.
    alert_ids_now = list(latest_alerts_map.keys())

    state_by_id: Dict[str, sqlite3.Row] = {}
    if alert_ids_now:
        lookup_ids = _tenant_alert_ids(tenant_id, alert_ids_now)
        placeholders = ",".join(["?"] * len(lookup_ids))
        with db_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id
                FROM alert_state
                WHERE alert_id IN ({placeholders})
                """,
                tuple(lookup_ids),
            ).fetchall()
        for r in rows:
            raw_id = str(r["alert_id"])
            base_id = _strip_tenant_alert_id(tenant_id, raw_id)
            is_namespaced = raw_id.startswith(f"{tenant_id}:")
            if base_id in state_by_id and not is_namespaced:
                continue
            state_by_id[base_id] = r

    alerts_with_details: List[Dict[str, Any]] = []
    for aid, live in latest_alerts_map.items():
        r = state_by_id.get(aid)

        status = str(r["status"]) if r else "review"
        note = str(r["note"] or "") if r else ""
        updated_at = str(r["updated_at"] or "") if r else ""
        last_score = float(r["last_score"] or 0.0) if r else float(alert_score(live))
        last_seen_run_id = r["last_seen_run_id"] if r else (int(latest_run["id"]) if latest_run else None)

        alerts_with_details.append(
            {
                "alert_id": aid,
                "status": status,
                "note": note,
                "updated_at": updated_at,
                "last_score": last_score,
                "last_seen_run_id": last_seen_run_id,
                "title": live.get("title") or aid,
                "severity": live.get("severity") or "info",
                "why": live.get("why") or "",
                "suggested_actions": live.get("suggested_actions") or [],
                "signal_strength": live.get("signal_strength") or "",
                "suppressed": bool(live.get("suppressed")),
                "suppression_reason": live.get("suppression_reason") or "",
                "quality_context": live.get("quality_context") or {},
                "is_triggered_now": True,  # by construction (latest run only)
            }
        )

    # Needs attention: still triggered + status=review (top 5)
    needs_attention = [a for a in alerts_with_details if a["status"] == "review"]
    needs_attention.sort(
        key=lambda x: (sev_rank.get(str(x.get("severity")), 9), -float(x.get("last_score") or 0.0))
    )
    needs_attention = needs_attention[:5]

    # Active: triggered now + not resolved
    all_active = [a for a in alerts_with_details if a["status"] != "resolved"]
    all_active.sort(
        key=lambda x: (
            sev_rank.get(str(x.get("severity")), 9),
            -float(x.get("last_score") or 0.0),
            str(x.get("alert_id") or ""),
        )
    )

    # Quieted/resolved (snapshot-mode): only show items that are STILL triggered now
    # but the user has set to noted/actioned/ignore/snoozed/resolved.
    quiet_statuses = {"noted", "actioned", "ignore", "snoozed", "resolved"}
    quieted_resolved = [a for a in alerts_with_details if a["status"] in quiet_statuses]
    quieted_resolved.sort(
        key=lambda x: (0 if x.get("status") == "resolved" else 1, str(x.get("updated_at") or "")),
        reverse=True,
    )

    summary = latest_run.get("summary", {}) if latest_run else {}
    quality = latest_run.get("quality", {}) if latest_run else {}

    return _render_or_fallback(
        request,
        "alerts.html",
        {
            "request": request,
            "title": "Alerts",
            "latest_run": latest_run,
            "needs_attention": needs_attention,
            "all_active": all_active,
            "quieted_resolved": quieted_resolved,
            "active_run_id": (latest_run.get("id") if latest_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(latest_run, latest_run_actual),
            "run_scope": run_scope,
            "summary": summary,
            "quality": quality,
        },
        fallback_title="Alerts",
        fallback_html="<p>Alerts template missing. Use <code>/api/alerts/state</code> for JSON.</p>",
    )



@app.post("/alerts/{alert_id}/update")
def update_alert_status(
    request: Request,
    alert_id: str,
    status: str = Form(...),
    note: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    # operator role can update alert status/note (Phase 3 RBAC)
    _require_role(request, "operator", "update", f"alert:{alert_id}")
    status = str(status).strip().lower()
    if status not in {"noted", "actioned", "acknowledged", "ignore", "snoozed", "review"}:
        status = "review"
    note_clean = str(note or "").strip()

    # Prefer active run context if the user is browsing history; fall back to latest.
    # This keeps scoring consistent with what the user is looking at.
    tenant_id = _tenant_id(request)
    latest_run_id = _get_latest_run_id(tenant_id)
    latest_run = _latest_run_snapshot(tenant_id)
    active_id = _get_active_run_id(request, None)
    if latest_run_id is None:
        return _read_only_response(
            request,
            "Run is read-only",
            "Status updates are only permitted on the latest run.",
            "historical_run_read_only",
        )
    if active_id is not None and int(active_id) != int(latest_run_id):
        return _read_only_response(
            request,
            "Run is read-only",
            "Status updates are only permitted on the latest run.",
            "historical_run_read_only",
        )
    chosen = _run_snapshot(active_id, tenant_id) if active_id is not None else latest_run
    run_id = int(chosen["id"]) if chosen else None
    score = 0.0
    if chosen:
        amap = _latest_alert_map(chosen)
        a = amap.get(str(alert_id))
        if a:
            score = float(alert_score(a))

    alert_key = _tenant_alert_id(tenant_id, alert_id)
    upsert_alert_state(alert_id=alert_key, status=status, note=note_clean, run_id=run_id, score=score)
    insert_alert_event(run_id=run_id, alert_id=alert_key, event_type="user_feedback", status=status, note=note_clean)
    return RedirectResponse(url=f"/alerts#{alert_id}", status_code=303)


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(
    request: Request,
    alert_id: str,
    readonly: bool = Query(False),
    run_id: Optional[int] = Query(None),
    events_page: int = Query(1, ge=1)
):
    require_user(request)  # Auth + TOS
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    run_qs = _run_qs(active_run, latest_run_actual)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    role = _access_role(request)
    tenant_id = _tenant_id(request)
    _log_access(tenant_id, _actor_id(request), role, "view", f"alert:{alert_id}")
    alert_key = _tenant_alert_id(tenant_id, alert_id)
    is_latest = False
    if active_run and latest_run_actual:
        try:
            is_latest = int(active_run.get("id")) == int(latest_run_actual.get("id"))
        except Exception:
            is_latest = False
    role = _access_role(request)
    can_update = bool(
        is_latest
        and not bool(readonly)
        and role in ("operator", "manager", "admin")
    )

    # Pagination for alert events
    events_per_page = 50
    events_offset = (events_page - 1) * events_per_page

    with db_conn() as conn:
        state = conn.execute(
            """
            SELECT alert_id, status, note, updated_at, last_seen_run_id, last_score
            FROM alert_state
            WHERE alert_id = ?
            """,
            (alert_key,),
        ).fetchone()

        if _role_rank(role) >= _role_rank("auditor"):
            _log_access(tenant_id, _actor_id(request), role, "view", f"audit:alert:{alert_id}")

            # Get total count for pagination
            total_events = conn.execute(
                """
                SELECT COUNT(*) as count
                FROM alert_events
                WHERE alert_id = ?
                """,
                (alert_key,),
            ).fetchone()["count"]

            # Get paginated events
            events = conn.execute(
                """
                SELECT created_at, run_id, event_type, status, note
                FROM alert_events
                WHERE alert_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (alert_key, events_per_page, events_offset),
            ).fetchall()
        else:
            events = []
            total_events = 0

        recent_runs = []

    chosen = active_run or latest_run_actual
    if chosen:
        with db_conn() as conn:
            if _table_has_column(conn, "runs", "tenant_id"):
                latest = conn.execute(
                    "SELECT id, alerts_json FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                    (int(chosen["id"]), TENANT_DEFAULT, tenant_id),
                ).fetchone()
            else:
                latest = conn.execute(
                    "SELECT id, alerts_json FROM runs WHERE id = ?",
                    (int(chosen["id"]),),
                ).fetchone()
    else:
        latest = None

    # P1-B4: Historical Alert Comparison - fetch prior occurrences of this alert type
    appearances: List[Dict[str, Any]] = []
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            historical_rows = conn.execute(
                "SELECT id, created_at, alerts_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 50",
                (TENANT_DEFAULT, tenant_id),
            ).fetchall()
        else:
            historical_rows = conn.execute(
                "SELECT id, created_at, alerts_json FROM runs ORDER BY id DESC LIMIT 50"
            ).fetchall()

    for hr in historical_rows:
        hr_alerts = safe_json_loads(hr["alerts_json"], []) or []
        for hr_alert in hr_alerts:
            if isinstance(hr_alert, dict) and str(hr_alert.get("id")) == str(alert_id):
                # Found this alert type in a historical run
                hr_evidence = hr_alert.get("evidence", {}) if isinstance(hr_alert, dict) else {}
                appearances.append({
                    "run_id": int(hr["id"]),
                    "created_at": str(hr["created_at"]),
                    "severity": str(hr_alert.get("severity", "")),
                    "evidence": dict(hr_evidence) if isinstance(hr_evidence, dict) else {},
                })
                break  # Only count once per run

    alert_details = None
    if latest:
        arr = safe_json_loads(latest["alerts_json"], []) or []
        for a in arr:
            if isinstance(a, dict) and str(a.get("id")) == str(alert_id):
                alert_details = a
                break

    # Calculate pagination metadata
    total_pages = (total_events + events_per_page - 1) // events_per_page if total_events > 0 else 1
    has_prev_page = events_page > 1
    has_next_page = events_page < total_pages

    return _render_or_fallback(
        request,
        "alert_detail.html",
        {
            "request": request,
            "title": f"Alert: {alert_id}",
            "alert_id": alert_id,
            "state": (
                dict(
                    state,
                    alert_id=_strip_tenant_alert_id(tenant_id, str(state["alert_id"] or "")),
                )
                if state
                else None
            ),
            "events": [dict(e) for e in events],
            "audit_allowed": bool(_role_rank(role) >= _role_rank("auditor")),
            "appearances": appearances,
            "alert_details": alert_details,
            "readonly": bool(readonly),
            "can_update": can_update,
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": run_qs,
            "run_scope": run_scope,
            "events_page": events_page,
            "events_per_page": events_per_page,
            "total_events": total_events,
            "total_pages": total_pages,
            "has_prev_page": has_prev_page,
            "has_next_page": has_next_page,
        },
        fallback_title=f"Alert: {alert_id}",
        fallback_html="<p>Alert detail template missing. Use <code>/api/alerts/state</code> and <code>/api/alerts/events</code>.</p>",
    )

@app.get("/insights", response_class=HTMLResponse)
def insights(request: Request, run_id: Optional[int] = Query(None)):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "summary")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    latest_run = active_run or latest_run_actual
    run_scope = _run_scope_context(active_run, latest_run_actual)

    if not latest_run:
        return _render_or_fallback(
            request,
            "insights.html",
            {"request": request, "title": "Summary", "empty": True, "run_scope": run_scope},
            fallback_title="Summary",
            fallback_html="<p>No runs yet. Upload a CSV on <code>/upload</code>.</p>",
        )

    summary = latest_run.get("summary") or {}
    alerts = latest_run.get("alerts") or []
    quality = latest_run.get("quality") or {}
    return _render_or_fallback(
        request,
        "insights.html",
        {
            "request": request,
            "title": "Summary",
            "empty": False,
            "latest_run": latest_run,
            "summary": summary,
            "alerts": alerts,
            "quality": quality,
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title="Summary",
        fallback_html="<p>Summary template missing.</p>",
    )




@app.get("/digest", response_class=RedirectResponse)
def digest_redirect(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "digest_redirect")
    return RedirectResponse(url="/insights", status_code=302)


@app.get("/insights/weekly", response_class=HTMLResponse)
def weekly_insights(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "insights_weekly")
    active_run, latest_run_actual = _active_and_latest(request, None)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        clause, params = _alert_id_filter_clause(tenant_id)
        unresolved = conn.execute(
            f"""
            SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id
            FROM alert_state
            WHERE status != 'resolved' AND {clause}
            ORDER BY
              CASE status WHEN 'review' THEN 0 ELSE 1 END,
              updated_at DESC
            """,
            params,
        ).fetchall()

        events = conn.execute(
            f"""
            SELECT created_at, alert_id, event_type, status, note, run_id
            FROM alert_events
            WHERE datetime(created_at) >= datetime('now', '-7 days')
              AND {clause}
            ORDER BY created_at DESC
            LIMIT 800
            """,
            params,
        ).fetchall()

    events_list = []
    for e in events:
        item = dict(e)
        item["alert_id"] = _strip_tenant_alert_id(tenant_id, str(item.get("alert_id") or ""))
        events_list.append(item)
    return _render_or_fallback(
        request,
        "weekly_digest.html",
        {
            "request": request,
            "title": "Weekly Summary",
            "unresolved": [
                dict(
                    dict(r),
                    alert_id=_strip_tenant_alert_id(tenant_id, str(r["alert_id"] or "")),
                )
                for r in unresolved
            ],
            "new_events": [e for e in events_list if e.get("event_type") == "auto_new"],
            "reopened_events": [e for e in events_list if e.get("event_type") == "auto_reopened"],
            "worsened_events": [e for e in events_list if e.get("event_type") == "auto_worsened"],
            "resolved_events": [e for e in events_list if e.get("event_type") == "auto_resolved"],
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title="Weekly Summary",
        fallback_html="<p>Weekly digest template missing. Use <code>/api/alerts/events?days=7</code>.</p>",
    )


@app.get("/digest/weekly", response_class=RedirectResponse)
def weekly_digest_redirect(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "digest_weekly_redirect")
    return RedirectResponse(url="/insights/weekly", status_code=302)


# ----------------------------
# Unified dashboard
# ----------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def unified_dashboard(request: Request, tab: str = "overview", run_id: Optional[int] = Query(None)):
    require_user(request)  # Auth + TOS enforcement
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "dashboard")
    active_run, latest_run_actual = _active_and_latest(request, run_id)
    run_scope = _run_scope_context(active_run, latest_run_actual)

    # Backward-compat: templates historically used `latest_run` as the primary snapshot.
    # In run-context mode, we treat it as the *active* snapshot.
    latest_run = active_run or latest_run_actual
    if not latest_run:
        return _render_or_fallback(
            request,
            "dashboard_unified.html",
            {
                "request": request,
                "title": "Dashboard",
                "tab": (tab or "overview").lower(),
                "latest_run": None,
                "active_run_id": None,
                "latest_run_id": None,
                "run_qs": "",
                "run_scope": run_scope,
            },
            fallback_title="Dashboard",
            fallback_html="<p>No data yet. Upload a CSV to generate your first dashboard.</p>",
        )

    return _render_or_fallback(
        request,
        "dashboard_unified.html",
        {
            "request": request,
            "title": "Dashboard",
            "tab": (tab or "overview").lower(),
            "latest_run": latest_run,
            "authorized_entities": _authorized_entities_for_actor(request),
            "active_run_id": (latest_run.get('id') if latest_run else None),
            "latest_run_id": (latest_run_actual.get('id') if latest_run_actual else None),
            "run_qs": _run_qs(latest_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title="Dashboard",
        fallback_html="<p>Dashboard template missing. Use <code>/run/&lt;id&gt;</code> or JSON endpoints under <code>/api</code>.</p>",
    )


@app.get("/run/{run_id}", response_class=HTMLResponse)
def view_run(request: Request, run_id: int):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", f"run:{run_id}")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return HTMLResponse("Run not found", status_code=404)

    try:
        request.session[_session_key_for_tenant(tenant_id)] = int(run_id)
    except Exception:
        pass

    summary = safe_json_loads(row["summary_json"], {}) or {}
    alerts = safe_json_loads(row["alerts_json"], []) or []
    quality = safe_json_loads(row["quality_json"], {}) or {}
    params = safe_json_loads(row["params_json"], {}) or {}
    feedback = get_feedback_map(run_id, tenant_id)
    state = get_alert_state_map(tenant_id)
    run_entity_id = str(row["tenant_id"]) if ("tenant_id" in row.keys() and row["tenant_id"] is not None) else TENANT_DEFAULT
    latest_run_id = _get_latest_run_id(tenant_id)
    is_latest = bool(latest_run_id is not None and int(run_id) == int(latest_run_id))
    run_scope = {
        "run_id": int(run_id),
        "created_at": str(row["created_at"]),
        "filename": str(row["filename"]),
        "tenant_id": str(run_entity_id),
        "is_latest": bool(is_latest),
    }

    alerts_display = _apply_effective_feedback(alerts, feedback, state)

    # E1: Extract provenance data for surfacing
    provenance = {
        "snapshot_id": int(run_id),
        "created_at": str(row["created_at"]),
        "file_sha256": params.get("file_sha256", "N/A"),
        "settings_hash": params.get("settings_hash", "N/A"),
        "rule_inventory_hash": params.get("rule_inventory_hash", "N/A"),
        "code_hash": params.get("code_hash", "N/A"),
    }

    # P0-C1: Fetch recent runs for period-over-period table
    recent_runs = []
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            recent_rows = conn.execute(
                "SELECT id, created_at, summary_json, alerts_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT 10",
                (TENANT_DEFAULT, tenant_id),
            ).fetchall()
        else:
            recent_rows = conn.execute(
                "SELECT id, created_at, summary_json, alerts_json FROM runs ORDER BY id DESC LIMIT 10"
            ).fetchall()

    for rr in recent_rows:
        rr_summary = safe_json_loads(rr["summary_json"], {}) or {}
        rr_alerts = safe_json_loads(rr["alerts_json"], []) or []
        recent_runs.append({
            "id": int(rr["id"]),
            "created_at": str(rr["created_at"]),
            "window_start": rr_summary.get("window_start_date"),
            "window_end": rr_summary.get("end_date"),
            "window_income": rr_summary.get("window_income"),
            "window_expense": rr_summary.get("window_expense"),
            "window_net": rr_summary.get("window_net_change"),
            "recent_income": rr_summary.get("recent_income"),
            "recent_expense": rr_summary.get("recent_expense"),
            "current_cash": rr_summary.get("current_cash"),
            "runway_days": rr_summary.get("runway_days"),
            "alert_count": len([a for a in rr_alerts if isinstance(a, dict)]),
            "currency": rr_summary.get("currency", "AUD"),
        })

    # P0-C2: Same-Period-Prior-Year Comparison - find matching period from 1 year ago
    prior_year_run = None
    current_window_start = summary.get("window_start_date")
    current_window_end = summary.get("end_date")

    if current_window_start and current_window_end:
        try:
            from datetime import datetime, timedelta

            # Parse current period dates
            current_start_dt = datetime.strptime(current_window_start, "%Y-%m-%d")
            current_end_dt = datetime.strptime(current_window_end, "%Y-%m-%d")

            # Calculate prior year period (subtract 365 days)
            prior_start_dt = current_start_dt - timedelta(days=365)
            prior_end_dt = current_end_dt - timedelta(days=365)

            # Search for runs matching the prior year period (within 7-day tolerance)
            with db_conn() as conn:
                if _table_has_column(conn, "runs", "tenant_id"):
                    all_rows = conn.execute(
                        "SELECT id, created_at, summary_json, alerts_json FROM runs WHERE COALESCE(tenant_id, ?) = ? AND id < ? ORDER BY id DESC",
                        (TENANT_DEFAULT, tenant_id, run_id),
                    ).fetchall()
                else:
                    all_rows = conn.execute(
                        "SELECT id, created_at, summary_json, alerts_json FROM runs WHERE id < ? ORDER BY id DESC",
                        (run_id,),
                    ).fetchall()

            # Find best matching run (closest to prior year period)
            best_match = None
            best_match_score = float('inf')

            for ar in all_rows:
                ar_summary = safe_json_loads(ar["summary_json"], {}) or {}
                ar_start = ar_summary.get("window_start_date")
                ar_end = ar_summary.get("end_date")

                if ar_start and ar_end:
                    try:
                        ar_start_dt = datetime.strptime(ar_start, "%Y-%m-%d")
                        ar_end_dt = datetime.strptime(ar_end, "%Y-%m-%d")

                        # Calculate overlap distance (days off from ideal prior year period)
                        start_diff = abs((ar_start_dt - prior_start_dt).days)
                        end_diff = abs((ar_end_dt - prior_end_dt).days)
                        total_diff = start_diff + end_diff

                        # Accept if within 14-day total tolerance and better than current best
                        if total_diff <= 14 and total_diff < best_match_score:
                            best_match_score = total_diff
                            ar_alerts = safe_json_loads(ar["alerts_json"], []) or []
                            best_match = {
                                "run_id": int(ar["id"]),
                                "created_at": str(ar["created_at"]),
                                "window_start": ar_start,
                                "window_end": ar_end,
                                "window_income": ar_summary.get("window_income"),
                                "window_expense": ar_summary.get("window_expense"),
                                "window_net": ar_summary.get("window_net_change"),
                                "current_cash": ar_summary.get("current_cash"),
                                "runway_days": ar_summary.get("runway_days"),
                                "alert_count": len([a for a in ar_alerts if isinstance(a, dict)]),
                                "currency": ar_summary.get("currency", "AUD"),
                            }
                    except (ValueError, TypeError):
                        continue

            prior_year_run = best_match

        except (ValueError, TypeError, ImportError):
            prior_year_run = None

    return _render_or_fallback(
        request,
        "dashboard.html",
        {
            "request": request,
            "title": "Dashboard",
            "run_id": run_id,
            "filename": row["filename"],
            "created_at": row["created_at"],
            "run_entity_id": run_entity_id,
            "authorized_entities": _authorized_entities_for_actor(request),
            "summary": summary,
            "alerts": alerts_display,
            "quality": quality,
            "params": params,
            "feedback": feedback,
            "can_update": bool(is_latest and _access_role(request) in ("operator", "manager", "admin")),
            "active_run_id": int(run_id),
            "latest_run_id": latest_run_id,
            "run_qs": f"?run_id={int(run_id)}" if (latest_run_id and int(run_id) != int(latest_run_id)) else "",
            "run_scope": run_scope,
            "provenance": provenance,  # E1
            "recent_runs": recent_runs,  # P0-C1
            "prior_year_run": prior_year_run,  # P0-C2
        },
        fallback_title=f"Run {run_id}",
        fallback_html="<p>Run template missing. Use <code>/run/&lt;id&gt;/json</code>.</p>",
    )


@app.post("/run/{run_id}/feedback")
def save_feedback(
    request: Request,
    run_id: int,
    alert_id: str = Form(...),
    status: str = Form(...),
    note: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    # operator role can update alert status/note (Phase 3 RBAC)
    _require_role(request, "operator", "update", f"run:{run_id}:feedback")
    status = str(status).strip().lower()
    if status not in {"noted", "actioned", "acknowledged", "ignore", "snoozed", "review"}:
        status = "review"
    note_clean = str(note or "").strip()
    tenant_id = _tenant_id(request)
    alert_key = _tenant_alert_id(tenant_id, alert_id)
    latest_run_id = _get_latest_run_id(tenant_id)

    score = 0.0
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            run_row = conn.execute(
                "SELECT id, alerts_json FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
            if not run_row:
                return HTMLResponse("Run not found", status_code=404)
        else:
            run_row = conn.execute(
                "SELECT id, alerts_json FROM runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            if not run_row:
                return HTMLResponse("Run not found", status_code=404)
        if latest_run_id is None or int(run_id) != int(latest_run_id):
            return _read_only_response(
                request,
                "Run is read-only",
                "Status updates are only permitted on the latest run.",
                "historical_run_read_only",
            )
        conn.execute(
            """
            INSERT INTO alert_feedback (run_id, alert_id, status, note, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id, alert_id) DO UPDATE SET
                status=excluded.status,
                note=excluded.note,
                updated_at=excluded.updated_at
            """,
            (run_id, alert_key, status, note_clean, datetime.utcnow().isoformat()),
        )
        alerts = safe_json_loads(run_row["alerts_json"], []) if run_row else []
        if isinstance(alerts, list):
            for a in alerts:
                if isinstance(a, dict) and str(a.get("id")) == str(alert_id):
                    score = float(alert_score(a))
                    break
        # Persist status across future runs (memory) + event
        upsert_alert_state(alert_id=alert_key, status=status, note=note_clean, run_id=run_id, score=score, conn=conn)
        insert_alert_event(run_id=run_id, alert_id=alert_key, event_type="user_feedback", status=status, note=note_clean, conn=conn)
        conn.commit()

    return RedirectResponse(url=f"/run/{run_id}", status_code=303)


@app.get("/run/{run_id}/json")
def run_json(request: Request, run_id: int):
    require_user(request, min_role="auditor", action="export", resource=f"run:{run_id}:json")  # Auth + TOS + auditor
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", f"run:{run_id}:json")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "run not found"}, status_code=404)

    params = safe_json_loads(row["params_json"], {}) or {}
    run_tenant_id = str(row["tenant_id"]) if ("tenant_id" in row.keys() and row["tenant_id"] is not None) else TENANT_DEFAULT
    run_obj = {
        "run_id": int(row["id"]),
        "created_at": str(row["created_at"]),
        "provider": str((params.get("source") or {}).get("provider") or ""),
        "config_hash": str(params.get("config_hash") or ""),
        "code_hash": str(params.get("code_hash") or ""),
        "tenant_id": run_tenant_id,
    }
    # Sanitize alerts to remove advisory content
    alerts_raw = safe_json_loads(row["alerts_json"], []) or []
    alerts = [_sanitize_alert_for_export(a) if isinstance(a, dict) else a for a in alerts_raw]
    return JSONResponse(
        {
            "id": int(row["id"]),
            "created_at": row["created_at"],
            "filename": row["filename"],
            "tenant_id": run_tenant_id,
            "params": params,
            "run": run_obj,
            "summary": safe_json_loads(row["summary_json"], {}) or {},
            "alerts": alerts,
            "quality": safe_json_loads(row["quality_json"], {}) or {},
            "feedback": get_feedback_map(run_id, tenant_id),
        }
    )


@app.get("/api/report/{run_id}", response_class=JSONResponse)
def api_report(request: Request, run_id: int):
    _require_role(request, "auditor", "export", f"report:{run_id}")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "run not found"}, status_code=404)
    return JSONResponse({"report": _build_report_from_run(row)})


@app.get("/api/report/{run_id}/export.json", response_class=JSONResponse)
def api_report_export_json(request: Request, run_id: int):
    _require_role(request, "auditor", "export", f"report:{run_id}:json")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "run not found"}, status_code=404)
    return JSONResponse(_build_report_from_run(row))


@app.get("/api/report/{run_id}/export.csv", response_class=PlainTextResponse)
def api_report_export_csv(request: Request, run_id: int):
    _require_role(request, "auditor", "export", f"report:{run_id}:csv")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return PlainTextResponse("run not found", status_code=404)
    report = _build_report_from_run(row)
    rows: List[List[Any]] = []
    for k, v in (report.get("summary") or {}).items():
        rows.append(["summary", str(k), str(v)])
    for a in report.get("alerts") or []:
        if not isinstance(a, dict):
            continue
        rows.append(
            [
                "alert",
                str(a.get("id") or ""),
                str(a.get("severity") or ""),
                str(a.get("title") or ""),
                str(a.get("suppressed") or False),
                str(a.get("suppression_reason") or ""),
            ]
        )
    audit = report.get("audit") or {}
    if isinstance(audit, dict):
        for k in ["config_version", "config_hash", "code_hash", "rule_inventory_hash", "tenant_id", "ingest_id"]:
            rows.append(["audit", str(k), str(audit.get(k) or "")])
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["record_type", "key", "severity_or_title", "title_or_value", "suppressed", "suppression_reason"])
    for r in rows:
        # Apply CSV formula injection protection to all cells
        writer.writerow([_safe_csv_cell(x) for x in r])
    return PlainTextResponse(out.getvalue(), media_type="text/csv")


@app.get("/api/report/{run_id}/export.pdf")
def api_report_export_pdf(request: Request, run_id: int):
    _require_role(request, "auditor", "export", f"report:{run_id}:pdf")
    # PDF export is not available in the current version
    accept = str(request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        return _render_or_fallback(
            request,
            "error.html",
            {
                "request": request,
                "title": "Feature Not Available",
                "error_title": "PDF Export Not Available",
                "error_message": "PDF export is not available in the current version. Please use CSV export for data extraction.",
                "schema_help": None,
                "actions": [
                    {"label": "Export CSV", "href": f"/api/report/{run_id}/export.csv"},
                    {"label": "Back to Dashboard", "href": "/dashboard"},
                ],
                "show_details": False,
                "error_details": None,
            },
            fallback_title="Feature Not Available",
            fallback_html=f'<p>PDF export is not available. <a href="/api/report/{run_id}/export.csv">Export CSV instead</a>.</p>',
        )
    return JSONResponse({"error": "PDF export not available", "alternative": f"/api/report/{run_id}/export.csv"}, status_code=501)

def _bundle_hash(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _json_response_deterministic(payload: Any, status_code: int = 200) -> PlainTextResponse:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return PlainTextResponse(body, media_type="application/json", status_code=status_code)

@app.get("/api/export/bundle/{run_id}", response_class=JSONResponse)
def api_export_bundle(request: Request, run_id: int):
    _require_role(request, "auditor", "export", f"bundle:{run_id}")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "run not found"}, status_code=404)

    params = safe_json_loads(row["params_json"], {}) or {}
    with db_conn() as conn:
        events = conn.execute(
            """
            SELECT id, created_at, run_id, alert_id, event_type, status, note
            FROM alert_events
            WHERE run_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (int(run_id),),
        ).fetchall()
        clause, params_clause = _alert_id_filter_clause(tenant_id)
        state_rows = conn.execute(
            f"""
            SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id
            FROM alert_state
            WHERE {clause}
            ORDER BY alert_id ASC
            """,
            params_clause,
        ).fetchall()

    alerts = safe_json_loads(row["alerts_json"], []) or []
    quality = safe_json_loads(row["quality_json"], {}) or {}
    summary = safe_json_loads(row["summary_json"], {}) or {}
    audit = {
        "events": [dict(e) for e in events],
        "state": [dict(s) for s in state_rows],
    }
    source = params.get("source") if isinstance(params, dict) else {}
    provenance = {
        "config_version": str(params.get("config_version") or ""),
        "config_hash": str(params.get("config_hash") or ""),
        "code_hash": str(params.get("code_hash") or ""),
        "rule_inventory_hash": str(params.get("rule_inventory_hash") or ""),
        "rule_inventory_version": str(params.get("rule_inventory_version") or ""),
        "ingest_id": str(source.get("ingest_id") or "") if isinstance(source, dict) else "",
        "file_sha256": str(row["file_sha256"]) if ("file_sha256" in row.keys()) and row["file_sha256"] is not None else "",
        "settings_hash": str(row["settings_hash"]) if ("settings_hash" in row.keys()) and row["settings_hash"] is not None else "",
    }
    bundle = {
        "run": {
            "id": int(row["id"]),
            "created_at": str(row["created_at"]),
            "filename": str(row["filename"]),
            "tenant_id": str(row["tenant_id"]) if ("tenant_id" in row.keys()) and row["tenant_id"] is not None else TENANT_DEFAULT,
            "summary": summary,
        },
        "alerts": alerts,
        "quality": quality,
        "params": params,
        "audit": audit,
        "provenance": provenance,
    }
    bundle["bundle_hash"] = _bundle_hash(bundle)
    return JSONResponse(bundle)


# ----------------------------
# DISABLED: Advisory strategies function
# ----------------------------
# WARNING: This function contains advisory/recommendation content that violates
# the non-advisory enterprise posture. It is DISABLED and MUST NOT be exposed.
# The /strategies route passes strategies=[] to prevent exposure.
# DO NOT enable this function without enterprise policy approval.
# ----------------------------
def _rule_based_strategies_DISABLED(latest_run: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """DISABLED: Contains advisory content. Do not call."""
    if not latest_run:
        return []

    summary = latest_run.get("summary") or {}
    alerts = latest_run.get("alerts") or []
    currency = str(summary.get("currency", "AUD"))

    strategies: List[Dict[str, Any]] = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        aid = str(a.get("id"))
        if aid == "runway_tight":
            strategies.append(
                {
                    "title": "14-day cash protection plan",
                    "why": "Runway is below buffer. Protect cash and prevent surprise obligations.",
                    "actions": [
                        "Create a 14-day payment calendar (payroll, tax, rent, key suppliers).",
                        "Negotiate deferrals on non-critical spend; pause discretionary expenses temporarily.",
                        "Accelerate receivables: send reminders + offer immediate-payment option where appropriate.",
                    ],
                }
            )
        elif aid == "expense_spike":
            strategies.append(
                {
                    "title": "Expense spike triage",
                    "why": "Spending has jumped vs the prior period. Validate, isolate, and decide if structural.",
                    "actions": [
                        "Confirm whether spike is one-off (annual bill, stock build) vs a new baseline.",
                        "Audit top category/vendor for the period; validate duplicates/errors.",
                        "If baseline increased: update forecast + increase pricing/volume targets accordingly.",
                    ],
                }
            )
        elif aid == "revenue_drop":
            strategies.append(
                {
                    "title": "Revenue recovery sprint",
                    "why": "Income dropped vs prior period. Determine timing vs demand and respond fast.",
                    "actions": [
                        "Segment: late invoicing vs fewer sales. Use invoices/AR where available.",
                        "Re-activate warm leads and upsell existing customers in the next 7–14 days.",
                        "If pipeline issue: focus on 1–2 channels and tighten weekly cadence (targets + actions).",
                    ],
                }
            )
        elif aid == "overdue_receivables":
            strategies.append(
                {
                    "title": "AR collections playbook",
                    "why": "Overdue receivables create cash timing risk.",
                    "actions": [
                        "Call top 3 overdue accounts first; agree exact payment date/time.",
                        "Introduce staged reminders (pre-due, due, +7, +14).",
                        "Consider deposits/part-payments for new work if chronic overdue persists.",
                    ],
                }
            )
        elif aid == "expense_concentration":
            strategies.append(
                {
                    "title": "Supplier dependency risk reduction",
                    "why": "High concentration increases disruption and pricing risk.",
                    "actions": [
                        "Confirm terms and upcoming price changes with key supplier(s).",
                        "Identify a secondary supplier for critical items over the next quarter.",
                        "Track concentration monthly and set a 'max share' guideline.",
                    ],
                }
            )

    # Always include one generic "operating rhythm" strategy
    strategies.append(
        {
            "title": "Weekly CFO rhythm (15 minutes)",
            "why": "Turns this app into a habit, not a dashboard you forget.",
            "actions": [
                "Review: cash runway, top alerts, and invoice/AR movement.",
                "Pick 1 action for this week (collections, pricing, cost, pipeline).",
                "Update 1 assumption (next month expense, next month sales) to keep forecasts honest.",
            ],
        }
    )

    # De-duplicate by title
    seen = set()
    uniq = []
    for s in strategies:
        t = s.get("title")
        if t in seen:
            continue
        seen.add(t)
        uniq.append(s)
    return uniq


@app.get("/strategies", response_class=HTMLResponse)
def strategies_page(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "strategies")
    tenant_id = _tenant_id(request)
    active_id = _get_active_run_id(request, None)
    latest = _latest_run_snapshot(tenant_id)
    active = _run_snapshot(active_id, tenant_id) if active_id is not None else None
    chosen = active or latest
    strategies: List[Dict[str, Any]] = []

    return _render_or_fallback(
    request,
    "strategies.html",
    {"request": request, "title": "Prompts", "latest_run": chosen, "strategies": strategies},
    fallback_title="Prompts",
    fallback_html="".join([
        "<p><strong>Prompts</strong> (disabled in audit mode).</p>",
        "<p style='color:#666;'>No stored prompts are available for this view.</p>",
    ]),
)


@app.get("/swot", response_class=HTMLResponse)
def swot_page(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "swot")
    tenant_id = _tenant_id(request)
    active_id = _get_active_run_id(request, None)
    latest = _latest_run_snapshot(tenant_id)
    active = _run_snapshot(active_id, tenant_id) if active_id is not None else None
    chosen = active or latest
    if not chosen:
        return _render_or_fallback(
            request,
            "swot.html",
            {"request": request, "title": "Observations", "empty": True},
            fallback_title="Observations",
            fallback_html="<p>No run yet. Upload a CSV first.</p>",
        )

    payload = {"strengths": [], "opportunities": [], "threats": []}

    return _render_or_fallback(
        request,
        "swot.html",
        {"request": request, "title": "Observations", "latest_run": chosen, "swot": payload, "empty": False},
        fallback_title="Observations",
        fallback_html="".join([
            "<p><strong>Observations</strong> (disabled in audit mode).</p>",
            "<p style='color:#666;'>No stored observations are available for this view.</p>",
        ]),
    )


# ----------------------------
# NEW: Integrations scaffold (API + simple page)
# ----------------------------
@app.get("/integrations", response_class=HTMLResponse)
def integrations_page(request: Request):
    require_user(request)
    _require_role(request, "admin", "view", "integrations")
    active_run, latest_run_actual = _active_and_latest(request, None)
    run_scope = _run_scope_context(active_run, latest_run_actual)
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        cols = set(_table_columns(conn, "integrations"))
        if "tenant_id" in cols:
            rows = conn.execute(
                """
                SELECT id, tenant_id, provider, status, metadata_json, secret_ref, created_at, updated_at
                FROM integrations
                WHERE tenant_id = ?
                ORDER BY provider ASC, id ASC
                """,
                (tenant_id,),
            ).fetchall()
        else:
            rows = []

    items = [
        {
            "id": int(r["id"]) if "id" in r.keys() else None,
            "tenant_id": str(r["tenant_id"] or ""),
            "provider": str(r["provider"] or ""),
            "status": str(r["status"] or "disabled"),
            "metadata_json": str(r["metadata_json"] or ""),
            "secret_ref": str(r["secret_ref"] or ""),
            "created_at": str(r["created_at"] or ""),
            "updated_at": str(r["updated_at"] or ""),
        }
        for r in rows
    ]

    return _render_or_fallback(
        request,
        "integrations.html",
        {
            "request": request,
            "title": "Integrations",
            "integrations": items,
            "active_run_id": (active_run.get("id") if active_run else None),
            "latest_run_id": (latest_run_actual.get("id") if latest_run_actual else None),
            "run_qs": _run_qs(active_run, latest_run_actual),
            "run_scope": run_scope,
        },
        fallback_title="Integrations (Disabled)",
        fallback_html="".join([
            "<p><strong>Integrations are disabled</strong>; no external calls occur.</p>",
            "<p>No integration records are stored for this tenant.</p>",
        ]),
    )



# ----------------------------
# NEW: Categorisation Rules API (demo-safe, deterministic)
# ----------------------------
@app.get("/api/rules", response_class=JSONResponse)
def api_rules(request: Request):
    _require_role(request, "admin", "view", "rules")
    with db_conn() as conn:
        vendor = _load_vendor_rules(conn)
        desc = _load_description_rules(conn)
        overrides = _load_override_rules(conn, datetime.utcnow().isoformat())
    return JSONResponse({"vendor_rules": vendor, "description_rules": desc, "overrides": overrides})


@app.get("/api/rules/changes", response_class=JSONResponse)
def api_rule_changes(
    request: Request,
    limit: int = 50,
    status: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
):
    _require_role(request, "auditor", "view", "rules:changes")
    limit = max(1, min(int(limit), 200))
    tenant_id = _tenant_id(request)
    raw_status = str(status or "").strip().lower()
    if status is not None and not raw_status:
        return JSONResponse({"error": "status required"}, status_code=400)
    if status and raw_status not in RULE_CHANGE_STATUSES:
        return JSONResponse({"error": "invalid_status"}, status_code=400)
    status_norm = raw_status
    rule_norm = _safe_text(rule_id, 120).strip() if rule_id else ""
    if rule_id and not rule_norm:
        return JSONResponse({"error": "rule_id invalid"}, status_code=400)
    if rule_norm and rule_norm not in RULE_INDEX:
        return JSONResponse({"error": "unknown_rule_id"}, status_code=400)
    _log_access(tenant_id, _actor_id(request), _access_role(request), "view", "rules:changes")
    with db_conn() as conn:
        if status_norm and rule_norm:
            rows = conn.execute(
                """
                SELECT id, tenant_id, created_at, rule_id, version_tag, status, effective_at,
                       approver_id, rationale, metadata_json
                FROM rule_changes
                WHERE tenant_id = ? AND status = ? AND rule_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (tenant_id, status_norm, rule_norm, limit),
            ).fetchall()
        elif status_norm:
            rows = conn.execute(
                """
                SELECT id, tenant_id, created_at, rule_id, version_tag, status, effective_at,
                       approver_id, rationale, metadata_json
                FROM rule_changes
                WHERE tenant_id = ? AND status = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (tenant_id, status_norm, limit),
            ).fetchall()
        elif rule_norm:
            rows = conn.execute(
                """
                SELECT id, tenant_id, created_at, rule_id, version_tag, status, effective_at,
                       approver_id, rationale, metadata_json
                FROM rule_changes
                WHERE tenant_id = ? AND rule_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (tenant_id, rule_norm, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, tenant_id, created_at, rule_id, version_tag, status, effective_at,
                       approver_id, rationale, metadata_json
                FROM rule_changes
                WHERE tenant_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    out = []
    now_utc = datetime.utcnow().replace(microsecond=0)
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "tenant_id": str(r["tenant_id"]),
                "created_at": str(r["created_at"]),
                "rule_id": str(r["rule_id"]),
                "rule_name": str(RULE_INDEX.get(str(r["rule_id"]), {}).get("rule") or ""),
                "version_tag": str(r["version_tag"]),
                "status": str(r["status"]),
                "effective_at": str(r["effective_at"]),
                "effective_in_future": _effective_in_future(r["effective_at"], now_utc),
                "effective_bucket": _effective_bucket(r["effective_at"], now_utc),
                "approver_id": str(r["approver_id"]),
                "rationale": str(r["rationale"]),
                "metadata": safe_json_loads(r["metadata_json"], {}) or {},
            }
        )
    return JSONResponse(
        {
            "changes": out,
            "limit": limit,
            "returned": len(out),
            "status": status_norm or None,
            "rule_id": rule_norm or None,
        }
    )


@app.get("/api/rules/changes/{change_id}", response_class=JSONResponse)
def api_rule_change_detail(request: Request, change_id: int):
    _require_role(request, "auditor", "view", "rules:changes:detail")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        row = conn.execute(
            """
            SELECT id, tenant_id, created_at, rule_id, version_tag, status, effective_at,
                   approver_id, rationale, metadata_json
            FROM rule_changes
            WHERE tenant_id = ? AND id = ?
            """,
            (tenant_id, int(change_id)),
        ).fetchone()
    if not row:
        return JSONResponse({"error": "not_found"}, status_code=404)
    now_utc = datetime.utcnow().replace(microsecond=0)
    payload = {
        "id": int(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "created_at": str(row["created_at"]),
        "rule_id": str(row["rule_id"]),
        "rule_name": str(RULE_INDEX.get(str(row["rule_id"]), {}).get("rule") or ""),
        "version_tag": str(row["version_tag"]),
        "status": str(row["status"]),
        "effective_at": str(row["effective_at"]),
        "effective_in_future": _effective_in_future(row["effective_at"], now_utc),
        "effective_bucket": _effective_bucket(row["effective_at"], now_utc),
        "approver_id": str(row["approver_id"]),
        "rationale": str(row["rationale"]),
        "metadata": safe_json_loads(row["metadata_json"], {}) or {},
    }
    return JSONResponse(payload)


@app.post("/api/rules/changes", response_class=JSONResponse)
def api_create_rule_change(
    request: Request,
    rule_id: str = Form(...),
    version_tag: str = Form(...),
    status: str = Form("draft"),
    effective_at: str = Form(...),
    approver_id: str = Form(""),
    rationale: str = Form(""),
    metadata_json: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "update", "rules:changes:create")
    tenant_id = _tenant_id(request)
    rid = _safe_text(rule_id, 120).strip()
    vtag = _safe_version_tag(version_tag)
    if not rid:
        return JSONResponse({"error": "rule_id required"}, status_code=400)
    if rid not in RULE_INDEX:
        return JSONResponse({"error": "unknown_rule_id"}, status_code=400)
    if not vtag:
        return JSONResponse({"error": "version_tag required"}, status_code=400)
    raw_status = str(status or "").strip().lower()
    if raw_status and raw_status not in RULE_CHANGE_STATUSES:
        return JSONResponse({"error": "invalid_status"}, status_code=400)
    status_norm = _safe_rule_change_status(status)
    eff_dt = _parse_effective_at(effective_at)
    if eff_dt is None:
        return JSONResponse({"error": "effective_at required (ISO-8601)"}, status_code=400)
    if eff_dt.microsecond != 0:
        eff_dt = eff_dt.replace(microsecond=0)

    approver = _safe_text(approver_id, 120).strip()
    reason = _safe_text(rationale, 500).strip()
    if status_norm == "approved" and not approver:
        approver = _safe_text(_actor_id(request), 120).strip()
    if status_norm in {"approved", "active"}:
        if not approver:
            return JSONResponse({"error": "approver_id required for approval"}, status_code=400)
        if not reason:
            return JSONResponse({"error": "rationale required for approval"}, status_code=400)
        if len(reason) > 120:
            return JSONResponse({"error": "rationale too long"}, status_code=400)
        if eff_dt < datetime.utcnow():
            return JSONResponse({"error": "effective_at must be in the future"}, status_code=400)
    if status_norm == "active":
        return JSONResponse({"error": "active status requires separate activation workflow"}, status_code=400)

    if status_norm == "draft":
        if eff_dt < datetime.utcnow():
            return JSONResponse({"error": "effective_at must be in the future"}, status_code=400)

    meta_obj: Dict[str, Any] = {}
    meta_raw = str(metadata_json or "").strip()
    if meta_raw:
        if len(meta_raw) > 2000:
            return JSONResponse({"error": "metadata_json too large"}, status_code=400)
        try:
            parsed = json.loads(meta_raw)
        except Exception:
            return JSONResponse({"error": "metadata_json must be valid JSON"}, status_code=400)
        if not isinstance(parsed, dict):
            return JSONResponse({"error": "metadata_json must be a JSON object"}, status_code=400)
        meta_obj = parsed

    created_at = datetime.utcnow().replace(microsecond=0).isoformat()
    metadata_out = dict(meta_obj)
    metadata_out.setdefault("request_actor", _safe_text(_actor_id(request), 120))
    metadata_out.setdefault("request_role", _safe_text(_access_role(request), 40))
    metadata_out.setdefault("request_tenant", _safe_text(tenant_id, 120))
    with db_conn() as conn:
        existing = conn.execute(
            """
            SELECT id FROM rule_changes
            WHERE tenant_id = ? AND rule_id = ? AND version_tag = ?
            LIMIT 1
            """,
            (tenant_id, rid, vtag),
        ).fetchone()
        if existing:
            return JSONResponse({"error": "rule_version_conflict"}, status_code=409)
        cur = conn.execute(
            """
            INSERT INTO rule_changes
            (tenant_id, created_at, rule_id, version_tag, status, effective_at, approver_id, rationale, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                created_at,
                rid,
                vtag,
                status_norm,
                eff_dt.isoformat(),
                approver,
                reason,
                json.dumps(metadata_out, sort_keys=True, separators=(",", ":")),
            ),
        )
        conn.commit()
        change_id = int(cur.lastrowid or 0)
    return JSONResponse({"ok": True, "change_id": change_id})


@app.post("/api/rules/vendor", response_class=JSONResponse)
def api_add_vendor_rule(
    request: Request,
    vendor: str = Form(...),
    category: str = Form(...),
    match_type: str = Form("equals"),
    priority: int = Form(100),
    is_enabled: Any = Form(True),
    note: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "update", "rules:vendor")
    v = _safe_text(vendor, MAX_RULE_TEXT_LEN).strip()
    c = _safe_text(category, MAX_RULE_TEXT_LEN).strip() or "Uncategorised"
    mt = _safe_match_type(match_type, {"equals", "contains", "startswith"}, "equals")
    pr = _clamp_int(priority, 0, 10_000, 100)
    en = 1 if _parse_bool(is_enabled, True) else 0
    n = _safe_text(note, 500)
    if not v:
        return JSONResponse({"error": "vendor required"}, status_code=400)
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO vendor_rules (vendor, match_type, category, is_enabled, priority, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (v, mt, c, en, pr, n, datetime.utcnow().isoformat()),
        )
        conn.commit()
    return JSONResponse({"ok": True})


@app.post("/api/rules/description", response_class=JSONResponse)
def api_add_description_rule(
    request: Request,
    pattern: str = Form(...),
    category: str = Form(...),
    match_type: str = Form("contains"),
    priority: int = Form(100),
    is_enabled: Any = Form(True),
    note: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "update", "rules:description")
    p = _safe_text(pattern, MAX_RULE_TEXT_LEN).strip()
    c = _safe_text(category, MAX_RULE_TEXT_LEN).strip() or "Uncategorised"
    mt = _safe_match_type(match_type, {"equals", "contains", "startswith", "regex"}, "contains")
    pr = _clamp_int(priority, 0, 10_000, 100)
    en = 1 if _parse_bool(is_enabled, True) else 0
    n = _safe_text(note, 500)
    if not p:
        return JSONResponse({"error": "pattern required"}, status_code=400)
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO description_rules (pattern, match_type, category, is_enabled, priority, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (p, mt, c, en, pr, n, datetime.utcnow().isoformat()),
        )
        conn.commit()
    return JSONResponse({"ok": True})


@app.post("/api/rules/override", response_class=JSONResponse)
def api_add_override_rule(
    request: Request,
    target_field: str = Form(...),
    pattern: str = Form(...),
    category: str = Form(...),
    match_type: str = Form("equals"),
    is_enabled: Any = Form(True),
    note: str = Form(""),
    csrf_token: Optional[str] = Form(None),
):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "update", "rules:override")
    tf = _safe_text(target_field, 20).strip().lower()
    if tf not in {"counterparty", "description"}:
        return JSONResponse({"error": "target_field must be counterparty or description"}, status_code=400)
    p = _safe_text(pattern, MAX_RULE_TEXT_LEN).strip()
    c = _safe_text(category, MAX_RULE_TEXT_LEN).strip() or "Uncategorised"
    mt = _safe_match_type(match_type, {"equals", "contains", "startswith", "regex"}, "equals")
    en = 1 if _parse_bool(is_enabled, True) else 0
    n = _safe_text(note, 500)
    if not p:
        return JSONResponse({"error": "pattern required"}, status_code=400)
    conf = _confidence_for_rule("override", mt)
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO categorisation_overrides
            (target_field, pattern, match_type, category, confidence, is_enabled, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tf, p, mt, c, conf, en, n, datetime.utcnow().isoformat()),
        )
        conn.commit()
    return JSONResponse({"ok": True})


@app.post("/api/rules/vendor/{rule_id}/delete", response_class=JSONResponse)
def api_delete_vendor_rule(request: Request, rule_id: int, csrf_token: Optional[str] = Form(None)):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "delete", f"rules:vendor:{rule_id}")
    with db_conn() as conn:
        conn.execute("DELETE FROM vendor_rules WHERE id = ?", (int(rule_id),))
        conn.commit()
    return JSONResponse({"ok": True})


@app.post("/api/rules/description/{rule_id}/delete", response_class=JSONResponse)
def api_delete_description_rule(request: Request, rule_id: int, csrf_token: Optional[str] = Form(None)):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "delete", f"rules:description:{rule_id}")
    with db_conn() as conn:
        conn.execute("DELETE FROM description_rules WHERE id = ?", (int(rule_id),))
        conn.commit()
    return JSONResponse({"ok": True})


@app.post("/api/rules/override/{rule_id}/delete", response_class=JSONResponse)
def api_delete_override_rule(request: Request, rule_id: int, csrf_token: Optional[str] = Form(None)):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "delete", f"rules:override:{rule_id}")
    with db_conn() as conn:
        conn.execute("DELETE FROM categorisation_overrides WHERE id = ?", (int(rule_id),))
        conn.commit()
    return JSONResponse({"ok": True})


# ----------------------------
# NEW: Cheap + legal ingestion testing (no paid APIs)
# ----------------------------
def _generate_synthetic_transactions(seed: int = 42, days: int = 120, rows_per_day: int = 8) -> pd.DataFrame:
    rng = np.random.default_rng(int(seed))
    days = max(14, min(int(days), 3660))
    rows_per_day = max(1, min(int(rows_per_day), 200))
    end = pd.Timestamp.utcnow().normalize()
    start = end - pd.Timedelta(days=days - 1)
    dates = pd.date_range(start, end, freq="D")

    vendors_exp = ["Vendor A", "Vendor B", "Vendor C", "Cloud Provider X", "Vendor D", "Supplier E", "Software Co", "Ad Platform 1", "Ad Platform 2"]
    vendors_inc = ["Client A", "Client B", "Client C", "Payment Processor 1", "Payment Processor 2"]
    cats_exp = ["Rent", "Utilities", "Software", "Marketing", "Supplies", "Travel", "Contractors"]
    cats_inc = ["Sales"]

    rows = []
    for d in dates:
        for _ in range(rows_per_day):
            is_expense = bool(rng.random() < 0.72)
            if is_expense:
                vendor = str(rng.choice(vendors_exp))
                category = str(rng.choice(cats_exp))
                amt = float(np.round(rng.lognormal(mean=4.0, sigma=0.6), 2))
                amt = -amt
                ttype = "expense"
                desc = f"{vendor} - {category}"
            else:
                vendor = str(rng.choice(vendors_inc))
                category = str(rng.choice(cats_inc))
                amt = float(np.round(rng.lognormal(mean=5.0, sigma=0.7), 2))
                ttype = "income"
                desc = f"{vendor} - invoice payment"
            rows.append(
                {
                    "date": str(pd.Timestamp(d).date()),
                    "amount": amt,
                    "type": ttype,
                    "category": "Uncategorised",  # force rule engine to show value
                    "counterparty": vendor if rng.random() > 0.05 else "Unknown",
                    "description": desc,
                }
            )
    df = pd.DataFrame(rows)
    return df

@app.post("/dev/generate-and-ingest", response_class=JSONResponse)
def dev_generate_and_ingest(
    request: Request,
    seed: int = Form(42),
    days: int = Form(120),
    rows_per_day: int = Form(8),
):
    """
    Dev-only helper (demo-safe):
    -Generates synthetic transactions (cheap + legal)
    -Ingests them using the SAME pipeline as /api/ingest/simulate
    -Returns the new run_id
    """
    _require_dev_mode(request)  # Hard production gate
    _require_role(request, "admin", "create", "run:dev_generate")
    s = read_settings(_tenant_id(request))
    tenant_id = _tenant_id(request)

    df = _generate_synthetic_transactions(seed=seed, days=days, rows_per_day=rows_per_day)
    df, normalization = normalise_csv(df, return_report=True)
    contract = _ledger_contract_report(df)
    run_created_at = datetime.utcnow().isoformat()
    with db_conn() as conn:
        df, cat_report = apply_deterministic_categorisation(df, s, conn, run_created_at=run_created_at)
    summary, alerts, quality = build_summary_and_alerts(df, s)
    summary = _attach_run_to_run_summary(summary, _latest_run_summary_meta(tenant_id))
    alerts_payload = [a.__dict__ for a in alerts]

    tx_bytes = df.to_csv(index=False).encode("utf-8")
    file_sha = hashlib.sha256(tx_bytes).hexdigest()
    settings_hash = _hash_settings(s)
    code_hash = _code_version_hash()
    rule_hash = _rule_inventory_hash()
    artifact_ids = _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)

    params = _build_run_params(
        settings=s,
        source=_safe_source_block(
            "synthetic",
            "synthetic_generator",
            {"note": f"seed={seed},days={days},rpd={rows_per_day}", "filename": "synthetic.csv"},
        ),
        contract=contract,
        cat_report=cat_report,
        normalization=normalization,
        config_hash=settings_hash,
        code_hash=code_hash,
        rule_hash=rule_hash,
        artifact_ids=artifact_ids,
    )
    with db_conn() as conn:
        run_id = _insert_run_row(
            conn=conn,
            created_at=run_created_at,
            filename="synthetic.csv",
            params_json=json.dumps(params),
            summary_json=json.dumps(summary),
            alerts_json=json.dumps(alerts_payload),
            quality_json=json.dumps(quality),
            file_sha256=file_sha,
            settings_hash=settings_hash,
            tenant_id=tenant_id,
        )
        conn.commit()
    try:
        update_alert_memory_for_run(int(run_id), alerts_payload, tenant_id)
    except Exception:
        pass
    return JSONResponse({"ok": True, "run_id": int(run_id), "alerts": alerts_payload})

@app.get("/dev/generate-sample", response_class=PlainTextResponse)
def dev_generate_sample(request: Request, seed: int = 42, days: int = 120, rows_per_day: int = 8):
    """Download a demo CSV (cheap + legal)."""
    _require_dev_mode(request)  # Hard production gate
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "dev_generate_sample")
    df = _generate_synthetic_transactions(seed=seed, days=days, rows_per_day=rows_per_day)
    csv = df.to_csv(index=False)
    return PlainTextResponse(csv, media_type="text/csv")


@app.post("/api/ingest/local", response_class=JSONResponse)
def api_ingest_local(request: Request, path: str = Form(...), provider: str = Form("local_drop")):
    """Ingest a CSV from demo_data/ only (safe path)."""
    _require_dev_mode(request)  # Hard production gate
    _require_role(request, "admin", "create", f"run:ingest_local:{provider}")
    tenant_id = _tenant_id(request)
    s = read_settings(tenant_id)

    rel = _safe_text(path, 200).strip().lstrip("/").lstrip("\\")
    if not rel:
        return JSONResponse({"error": "path required"}, status_code=400)
    # Force within DEMO_DATA_DIR
    DEMO_DATA_DIR.mkdir(parents=True, exist_ok=True)
    full = (DEMO_DATA_DIR / rel).resolve()
    if DEMO_DATA_DIR.resolve() not in full.parents and full != DEMO_DATA_DIR.resolve():
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if not full.exists() or not full.is_file():
        return JSONResponse({"error": "file not found in demo_data/"}, status_code=404)
    if full.suffix.lower() not in {".csv"}:
        return JSONResponse({"error": "only .csv allowed"}, status_code=400)

    content = full.read_bytes()
    if len(content) > MAX_UPLOAD_BYTES:
        return JSONResponse({"error": "file too large for this environment"}, status_code=413)

    settings_hash = _hash_settings(s)
    file_sha = hashlib.sha256(content).hexdigest()

    raw_df = pd.read_csv(io.BytesIO(content), nrows=MAX_UPLOAD_ROWS + 1)
    if isinstance(raw_df, pd.DataFrame) and len(raw_df) > MAX_UPLOAD_ROWS:
        return JSONResponse({"error": f"too many rows (max {MAX_UPLOAD_ROWS:,})"}, status_code=400)

    df, normalization = normalise_csv(raw_df, return_report=True)
    contract = _ledger_contract_report(df)
    run_created_at = datetime.utcnow().isoformat()
    with db_conn() as conn:
        df, cat_report = apply_deterministic_categorisation(df, s, conn, run_created_at=run_created_at)
    summary, alerts, quality = build_summary_and_alerts(df, s)
    summary = _attach_run_to_run_summary(summary, _latest_run_summary_meta(tenant_id))
    alerts_payload = [a.__dict__ for a in alerts]
    code_hash = _code_version_hash()
    rule_hash = _rule_inventory_hash()
    artifact_ids = _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)

    params = _build_run_params(
        settings=s,
        source=_safe_source_block(provider, "local_file", {"path": str(rel), "filename": str(full.name)}),
        contract=contract,
        cat_report=cat_report,
        normalization=normalization,
        config_hash=settings_hash,
        code_hash=code_hash,
        rule_hash=rule_hash,
        artifact_ids=artifact_ids,
    )

    with db_conn() as conn:
        run_id = _insert_run_row(
            conn=conn,
            created_at=run_created_at,
            filename=str(full.name),
            params_json=json.dumps(params),
            summary_json=json.dumps(summary),
            alerts_json=json.dumps(alerts_payload),
            quality_json=json.dumps(quality),
            file_sha256=file_sha,
            settings_hash=settings_hash,
            tenant_id=tenant_id,
        )
        conn.commit()
    try:
        update_alert_memory_for_run(int(run_id), alerts_payload, tenant_id)
    except Exception:
        pass
    return JSONResponse({"ok": True, "run_id": int(run_id), "alerts": alerts_payload})


@app.post("/api/ingest/simulate", response_class=JSONResponse)
def api_ingest_simulate(
    request: Request,
    seed: int = Form(42),
    days: int = Form(120),
    rows_per_day: int = Form(8),
    provider: str = Form("synthetic"),
):
    """Generate synthetic data and ingest as a run (cheap + legal)."""
    _require_dev_mode(request)  # Hard production gate
    _require_role(request, "admin", "create", f"run:ingest_simulate:{provider}")
    """Generate synthetic data and ingest as a run (cheap + legal)."""
    tenant_id = _tenant_id(request)
    s = read_settings(tenant_id)
    df = _generate_synthetic_transactions(seed=seed, days=days, rows_per_day=rows_per_day)
    df, normalization = normalise_csv(df, return_report=True)
    contract = _ledger_contract_report(df)
    run_created_at = datetime.utcnow().isoformat()
    with db_conn() as conn:
        df, cat_report = apply_deterministic_categorisation(df, s, conn, run_created_at=run_created_at)
    summary, alerts, quality = build_summary_and_alerts(df, s)
    summary = _attach_run_to_run_summary(summary, _latest_run_summary_meta(tenant_id))
    alerts_payload = [a.__dict__ for a in alerts]

    tx_bytes = df.to_csv(index=False).encode("utf-8")
    file_sha = hashlib.sha256(tx_bytes).hexdigest()
    settings_hash = _hash_settings(s)
    code_hash = _code_version_hash()
    rule_hash = _rule_inventory_hash()
    artifact_ids = _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)

    params = _build_run_params(
        settings=s,
        source=_safe_source_block(
            provider,
            "synthetic_generator",
            {"note": f"seed={seed},days={days},rpd={rows_per_day}", "filename": f"{provider}_synthetic.csv"},
        ),
        contract=contract,
        cat_report=cat_report,
        normalization=normalization,
        config_hash=settings_hash,
        code_hash=code_hash,
        rule_hash=rule_hash,
        artifact_ids=artifact_ids,
    )
    with db_conn() as conn:
        run_id = _insert_run_row(
            conn=conn,
            created_at=run_created_at,
            filename=f"{provider}_synthetic.csv",
            params_json=json.dumps(params),
            summary_json=json.dumps(summary),
            alerts_json=json.dumps(alerts_payload),
            quality_json=json.dumps(quality),
            file_sha256=file_sha,
            settings_hash=settings_hash,
            tenant_id=tenant_id,
        )
        conn.commit()
    try:
        update_alert_memory_for_run(int(run_id), alerts_payload, tenant_id)
    except Exception:
        pass
    return JSONResponse({"ok": True, "run_id": int(run_id), "alerts": alerts_payload})


@app.get("/api/latest", response_class=JSONResponse)
def api_latest(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "latest")
    tenant_id = _tenant_id(request)
    latest = _latest_run_snapshot(tenant_id)
    return JSONResponse({"latest": latest})


@app.get("/api/rules/registry", response_class=JSONResponse)
def api_rules_registry(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "rules:registry")
    return JSONResponse({"version": _rule_inventory_hash(), "rules": RULE_INVENTORY})


@app.get("/api/runs", response_class=JSONResponse)
def api_runs(request: Request, limit: int = 50):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "runs")
    limit = max(1, min(int(limit), 200))
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            rows = conn.execute(
                "SELECT id, created_at, filename, summary_json, quality_json FROM runs WHERE COALESCE(tenant_id, ?) = ? ORDER BY id DESC LIMIT ?",
                (TENANT_DEFAULT, tenant_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, filename, summary_json, quality_json FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    out = []
    for r in rows:
        summary = safe_json_loads(r["summary_json"], {}) or {}
        quality = safe_json_loads(r["quality_json"], {}) or {}
        out.append(
            {
                "id": int(r["id"]),
                "created_at": str(r["created_at"]),
                "filename": str(r["filename"]),
                "end_date": summary.get("end_date"),
                "currency": summary.get("currency", "AUD"),
                "current_cash": float(summary.get("current_cash", 0.0)),
                "runway_days": float(summary.get("runway_days", 0.0)),
                "quality_score": float(quality.get("score", 0.0)),
            }
        )
    return JSONResponse({"runs": out})


@app.get("/api/ui/dashboard", response_class=PlainTextResponse)
def api_ui_dashboard(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "ui:dashboard")
    tenant_id = _tenant_id(request)
    latest = _latest_run_snapshot(tenant_id)
    return _json_response_deterministic({"latest": latest})


@app.get("/api/ui/run/{run_id}", response_class=PlainTextResponse)
def api_ui_run(request: Request, run_id: int):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", f"ui:run:{run_id}")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                (run_id, TENANT_DEFAULT, tenant_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return _json_response_deterministic({"error": "run not found"}, status_code=404)

    params = safe_json_loads(row["params_json"], {}) or {}
    run_tenant_id = str(row["tenant_id"]) if ("tenant_id" in row.keys() and row["tenant_id"] is not None) else TENANT_DEFAULT
    payload = {
        "id": int(row["id"]),
        "created_at": str(row["created_at"]),
        "filename": str(row["filename"]),
        "tenant_id": run_tenant_id,
        "params": params,
        "summary": safe_json_loads(row["summary_json"], {}) or {},
        "alerts": safe_json_loads(row["alerts_json"], []) or [],
        "quality": safe_json_loads(row["quality_json"], {}) or {},
        "feedback": get_feedback_map(run_id, tenant_id),
        "alert_state": get_alert_state_map(tenant_id),
    }
    return _json_response_deterministic(payload)


@app.get("/api/ui/history", response_class=PlainTextResponse)
def api_ui_history(request: Request, limit: int = 200):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "ui:history")
    tenant_id = _tenant_id(request)
    limit = max(1, min(int(limit), 200))
    with db_conn() as conn:
        if _table_has_column(conn, "runs", "tenant_id"):
            rows = conn.execute(
                """
                SELECT id, created_at, filename, summary_json, quality_json, tenant_id
                FROM runs
                WHERE COALESCE(tenant_id, ?) = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (TENANT_DEFAULT, tenant_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, created_at, filename, summary_json, quality_json
                FROM runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    out = []
    for r in rows:
        summary = safe_json_loads(r["summary_json"], {}) or {}
        quality = safe_json_loads(r["quality_json"], {}) or {}
        out.append(
            {
                "run_id": int(r["id"]),
                "created_at": str(r["created_at"]),
                "filename": str(r["filename"]),
                "tenant_id": str(r["tenant_id"]) if ("tenant_id" in r.keys() and r["tenant_id"] is not None) else TENANT_DEFAULT,
                "end_date": summary.get("end_date"),
                "currency": summary.get("currency", "AUD"),
                "current_cash": float(summary.get("current_cash", 0.0)),
                "runway_days": float(summary.get("runway_days", 0.0)),
                "quality_score": float(quality.get("score", 0.0)),
            }
        )
    return _json_response_deterministic({"runs": out})


@app.get("/api/ui/alerts", response_class=PlainTextResponse)
def api_ui_alerts(request: Request):
    require_user(request, min_role="auditor", action="view", resource="ui:alerts")  # Auth + TOS + auditor
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "ui:alerts")
    tenant_id = _tenant_id(request)
    latest = _latest_run_snapshot(tenant_id)
    with db_conn() as conn:
        clause, params = _alert_id_filter_clause(tenant_id)
        rows = conn.execute(
            f"""
            SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id
            FROM alert_state
            WHERE {clause}
            ORDER BY alert_id ASC
            """,
            params,
        ).fetchall()
    payload = {
        "latest_run": latest,
        "alert_state": [dict(r) for r in rows],
    }
    return _json_response_deterministic(payload)


@app.get("/api/ui/alerts/{alert_id}", response_class=PlainTextResponse)
def api_ui_alert_detail(request: Request, alert_id: str):
    require_user(request, min_role="auditor", action="view", resource=f"ui:alert:{alert_id}")  # Auth + TOS + auditor
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", f"ui:alert:{alert_id}")
    tenant_id = _tenant_id(request)
    latest = _latest_run_snapshot(tenant_id)
    alert_details = None
    if latest:
        for a in latest.get("alerts") or []:
            if isinstance(a, dict) and str(a.get("id") or "") == str(alert_id):
                alert_details = a
                break
    candidates = _tenant_alert_ids(tenant_id, [alert_id])
    state_row = None
    events_rows: List[Dict[str, Any]] = []
    with db_conn() as conn:
        if candidates:
            placeholders = ",".join(["?"] * len(candidates))
            state_rows = conn.execute(
                f"""
                SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id
                FROM alert_state
                WHERE alert_id IN ({placeholders})
                ORDER BY alert_id ASC
                """,
                tuple(candidates),
            ).fetchall()
            if state_rows:
                for r in state_rows:
                    raw_id = str(r["alert_id"])
                    if raw_id.startswith(f"{tenant_id}:"):
                        state_row = dict(r)
                        break
                if state_row is None:
                    state_row = dict(state_rows[0])
            events = conn.execute(
                f"""
                SELECT created_at, run_id, alert_id, event_type, status, note
                FROM alert_events
                WHERE alert_id IN ({placeholders})
                ORDER BY created_at DESC, id DESC
                """,
                tuple(candidates),
            ).fetchall()
            events_rows = [dict(e) for e in events]
    if alert_details is None and state_row is None and not events_rows:
        return _json_response_deterministic({"error": "alert not found"}, status_code=404)
    payload = {
        "alert_id": str(alert_id),
        "latest_run_id": int(latest["id"]) if latest else None,
        "alert_details": alert_details,
        "alert_state": state_row,
        "alert_events": events_rows,
    }
    return _json_response_deterministic(payload)


@app.get("/api/ui/access/events", response_class=PlainTextResponse)
def api_ui_access_events(request: Request):
    require_user(request, min_role="auditor", action="view", resource="ui:access_events")  # Auth + TOS + auditor
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "ui:access_events")
    tenant_id = _tenant_id(request)
    actor_id = _actor_id(request)
    with db_conn() as conn:
        if actor_id:
            exists = conn.execute(
                """
                SELECT 1
                FROM access_events
                WHERE tenant_id = ? AND actor_id = ?
                LIMIT 1
                """,
                (tenant_id, actor_id),
            ).fetchone()
        else:
            exists = None
        if actor_id and not exists:
            rows = []
        else:
            rows = conn.execute(
                """
                SELECT created_at, tenant_id, actor_id, role, action, resource, allowed
                FROM access_events
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT 1000
                """,
                (tenant_id,),
            ).fetchall()
    payload = {"events": [dict(r) for r in rows]}
    return _json_response_deterministic(payload)


# PRE-AI: AI endpoints are DISABLED and removed from route registration.
# NORVION is deterministic and non-advisory. AI features are not available.
# The routes below are preserved for reference only and are NOT registered with FastAPI.
# They are inside an `if False:` block to ensure they are never executed or registered.

if False:
    # These routes are NEVER registered. This block is never executed.

    @app.post("/api/ai/explanation-requests", response_class=PlainTextResponse)
    async def api_ai_explanation_requests_create(request: Request):
        _require_role(request, "auditor", "create", "ai:explanation_request")
        tenant_id = _tenant_id(request)
        actor_id = _actor_id(request)
        try:
            body = await request.json()
        except Exception:
            return _json_response_deterministic({"error": "invalid_json"}, status_code=400)
        target_type = str(body.get("target_type") or "").strip().lower()
        target_id = str(body.get("target_id") or "").strip()
        if target_type not in {"run", "alert", "report"}:
            return _json_response_deterministic({"error": "invalid_target_type"}, status_code=400)
        if not target_id:
            return _json_response_deterministic({"error": "target_id_required"}, status_code=400)

        run_id_raw = body.get("run_id")
        run_id: Optional[int] = None
        snapshot_id = ""
        report_id = ""

        if target_type == "run":
            try:
                run_id = int(run_id_raw) if run_id_raw is not None else int(target_id)
            except Exception:
                return _json_response_deterministic({"error": "invalid_run_id"}, status_code=400)
            if str(run_id) != target_id:
                return _json_response_deterministic({"error": "run_id_mismatch"}, status_code=400)
            row = _run_row_for_tenant(run_id, tenant_id)
            if not row:
                return _json_response_deterministic({"error": "run not found"}, status_code=404)
            params = safe_json_loads(row["params_json"], {}) or {}
            artifact_ids = params.get("artifact_ids") if isinstance(params, dict) else None
            if isinstance(artifact_ids, dict):
                snapshot_id = str(artifact_ids.get("snapshot_id") or "")
                report_id = str(artifact_ids.get("report_id") or "")

        if target_type == "alert":
            if run_id_raw is None:
                return _json_response_deterministic({"error": "run_id_required"}, status_code=400)
            try:
                run_id = int(run_id_raw)
            except Exception:
                return _json_response_deterministic({"error": "invalid_run_id"}, status_code=400)
            row = _run_row_for_tenant(run_id, tenant_id)
            if not row:
                return _json_response_deterministic({"error": "run not found"}, status_code=404)
            alerts = safe_json_loads(row["alerts_json"], []) or []
            found = any(
                isinstance(a, dict) and str(a.get("id") or "") == target_id
                for a in alerts
            )
            if not found:
                return _json_response_deterministic({"error": "alert not found"}, status_code=404)
            params = safe_json_loads(row["params_json"], {}) or {}
            artifact_ids = params.get("artifact_ids") if isinstance(params, dict) else None
            if isinstance(artifact_ids, dict):
                snapshot_id = str(artifact_ids.get("snapshot_id") or "")
                report_id = str(artifact_ids.get("report_id") or "")

        if target_type == "report":
            if run_id_raw is None:
                return _json_response_deterministic({"error": "run_id_required"}, status_code=400)
            try:
                run_id = int(run_id_raw)
            except Exception:
                return _json_response_deterministic({"error": "invalid_run_id"}, status_code=400)
            row = _run_row_for_tenant(run_id, tenant_id)
            if not row:
                return _json_response_deterministic({"error": "run not found"}, status_code=404)
            params = safe_json_loads(row["params_json"], {}) or {}
            artifact_ids = params.get("artifact_ids") if isinstance(params, dict) else None
            if not isinstance(artifact_ids, dict) or not artifact_ids.get("report_id"):
                return _json_response_deterministic({"error": "report_id_unavailable"}, status_code=400)
            if str(artifact_ids.get("report_id")) != target_id:
                return _json_response_deterministic({"error": "report_id_mismatch"}, status_code=400)
            snapshot_id = str(artifact_ids.get("snapshot_id") or "")
            report_id = str(artifact_ids.get("report_id") or "")

        enabled_flag = _ai_explanations_enabled(read_settings(tenant_id))
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO explanation_requests
                (created_at, tenant_id, actor_id, target_type, target_id, run_id, snapshot_id, report_id, enabled_flag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    tenant_id,
                    actor_id or "",
                    target_type,
                    target_id,
                    run_id,
                    snapshot_id,
                    report_id,
                    1 if enabled_flag else 0,
                ),
            )
            row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
            conn.commit()
        return _json_response_deterministic(
            {"ok": True, "request_id": int(row["id"]) if row else None, "enabled_flag": bool(enabled_flag)}
        )

    @app.get("/api/ai/explanation-requests", response_class=PlainTextResponse)
    def api_ai_explanation_requests_list(request: Request, limit: int = 200):
        _require_role(request, "auditor", "view", "ai:explanation_requests")
        tenant_id = _tenant_id(request)
        actor_id = _actor_id(request)
        limit = max(1, min(int(limit), 200))
        with db_conn() as conn:
            if actor_id:
                exists = conn.execute(
                    """
                    SELECT 1
                    FROM access_events
                    WHERE tenant_id = ? AND actor_id = ?
                    LIMIT 1
                    """,
                    (tenant_id, actor_id),
                ).fetchone()
            else:
                exists = None
            if actor_id and not exists:
                rows = []
            else:
                rows = conn.execute(
                    """
                    SELECT id, created_at, tenant_id, actor_id, target_type, target_id, run_id, snapshot_id, report_id, enabled_flag
                    FROM explanation_requests
                    WHERE tenant_id = ?
                    ORDER BY created_at ASC, id ASC
                    LIMIT ?
                    """,
                    (tenant_id, limit),
                ).fetchall()
        return _json_response_deterministic({"requests": [dict(r) for r in rows]})

    @app.get("/api/ai/explanations/{request_id}", response_class=PlainTextResponse)
    def api_ai_explanation_output_gate(request: Request, request_id: int):
        _require_role(request, "auditor", "view", f"ai:explanation_output:{request_id}")
        tenant_id = _tenant_id(request)
        settings = read_settings(tenant_id)
        if not _ai_explanations_enabled(settings):
            return _json_response_deterministic({"error": "explanations_disabled"}, status_code=403)
        with db_conn() as conn:
            row = conn.execute(
                """
                SELECT id, created_at, tenant_id, actor_id, target_type, target_id, run_id, snapshot_id, report_id, enabled_flag
                FROM explanation_requests
                WHERE tenant_id = ? AND id = ?
                """,
                (tenant_id, int(request_id)),
            ).fetchone()
        if not row:
            return _json_response_deterministic({"error": "explanation_request_not_found"}, status_code=404)
        payload = {
            "request_id": int(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "created_at": str(row["created_at"]),
            "actor_id": str(row["actor_id"] or ""),
            "target_type": str(row["target_type"]),
            "target_id": str(row["target_id"]),
            "run_id": int(row["run_id"]) if row["run_id"] is not None else None,
            "snapshot_id": str(row["snapshot_id"] or ""),
            "report_id": str(row["report_id"] or ""),
            "enabled_flag_at_request_time": bool(row["enabled_flag"]),
            "status": "no_output",
        }
        return _json_response_deterministic(payload)


@app.get("/api/alerts/state", response_class=JSONResponse)
def api_alert_state(request: Request):
    require_user(request)  # Auth + TOS
    _log_access(_tenant_id(request), _actor_id(request), _access_role(request), "view", "alert_state")
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        clause, params = _alert_id_filter_clause(tenant_id)
        rows = conn.execute(
            f"SELECT alert_id, status, note, updated_at, last_score, last_seen_run_id FROM alert_state WHERE {clause} ORDER BY updated_at DESC",
            params,
        ).fetchall()
    alerts_out = []
    for r in rows:
        item = dict(r)
        item["alert_id"] = _strip_tenant_alert_id(tenant_id, str(item.get("alert_id") or ""))
        alerts_out.append(item)
    return JSONResponse({"alerts": alerts_out})


@app.get("/api/alerts/events", response_class=JSONResponse)
def api_alert_events(request: Request, days: int = 7):
    _require_role(request, "auditor", "view", "audit:events")
    days = max(1, min(int(days), 90))
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        clause, params = _alert_id_filter_clause(tenant_id)
        rows = conn.execute(
            """
            SELECT created_at, run_id, alert_id, event_type, status, note
            FROM alert_events
            WHERE datetime(created_at) >= datetime('now', ?)
              AND {clause}
            ORDER BY created_at DESC
            LIMIT 2000
            """.format(clause=clause),
            (f"-{days} days",) + params,
        ).fetchall()
    events_out = []
    for r in rows:
        item = dict(r)
        item["alert_id"] = _strip_tenant_alert_id(tenant_id, str(item.get("alert_id") or ""))
        events_out.append(item)
    return JSONResponse({"events": events_out, "days": days})


@app.get("/api/access/events", response_class=JSONResponse)
def api_access_events(request: Request, days: int = 7):
    _require_role(request, "admin", "view", "audit:access_events")
    days = max(1, min(int(days), 90))
    tenant_id = _tenant_id(request)
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT created_at, tenant_id, actor_id, role, action, resource, allowed
            FROM access_events
            WHERE tenant_id = ?
              AND datetime(created_at) >= datetime('now', ?)
            ORDER BY created_at DESC
            LIMIT 2000
            """,
            (tenant_id, f"-{days} days"),
        ).fetchall()
    return JSONResponse({"events": [dict(r) for r in rows], "days": days})


@app.get("/access/events", response_class=HTMLResponse)
def access_events_page(request: Request):
    _require_role(request, "admin", "view", "audit:access_events_ui")
    tenant_id = _tenant_id(request)
    actor_id = _actor_id(request)
    with db_conn() as conn:
        if actor_id:
            exists = conn.execute(
                """
                SELECT 1
                FROM access_events
                WHERE tenant_id = ? AND actor_id = ?
                LIMIT 1
                """,
                (tenant_id, actor_id),
            ).fetchone()
        else:
            exists = None
        if actor_id and not exists:
            rows = []
        else:
            rows = conn.execute(
                """
                SELECT created_at, tenant_id, actor_id, role, action, resource, allowed
                FROM access_events
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT 1000
                """,
                (tenant_id,),
            ).fetchall()
    events = [dict(r) for r in rows]
    return _render_or_fallback(
        request,
        "access_events.html",
        {
            "request": request,
            "title": "Access events",
            "events": events,
            "tenant_id": tenant_id,
        },
        fallback_title="Access events",
        fallback_html="<p>No access events view template found.</p>",
    )


@app.post("/api/webhook/transactions", response_class=JSONResponse)
async def api_webhook_transactions(request: Request):
    """Integration ingest endpoint (scaffold).

    POST JSON:
      {
        "secret": "...",
        "provider": "xero|stripe|shopify|...",
        "transactions": [ ... ]
      }

    For demo: we only validate secret and store as a 'run' if transactions are in CSV-like format.
    """
    # Demo safety: basic request size guard (prevents accidental DoS via huge JSON).
    try:
        cl = request.headers.get("content-length")
        if cl is not None and int(cl) > MAX_WEBHOOK_BYTES:
            return JSONResponse({"error": "payload too large"}, status_code=413)
    except Exception:
        pass

    body = await request.json()
    # SECURITY: Validate webhook secret FIRST (before any session/role checks)
    secret = str(body.get("secret") or "")
    # Get tenant from payload or header for secret lookup
    tenant_id = str(body.get("tenant_id") or request.headers.get("X-Tenant-ID") or TENANT_DEFAULT)
    s = read_settings(tenant_id)
    effective_secret = _effective_webhook_secret(s)
    # Production enforcement: reject requests if webhook_secret is demo default
    if _SME_EW_ENV == "production" and effective_secret == "CHANGE_ME_DEMO_SECRET":
        logger.error("Webhook rejected: webhook_secret is demo default in production mode")
        return JSONResponse({"error": "webhook_secret not configured for production"}, status_code=503)
    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(secret, effective_secret):
        logger.warning("Webhook rejected: invalid secret")
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    # Secret valid, now apply rate limit
    if not _rate_limit_allow(f"{tenant_id}:webhook", RATE_LIMIT_UPLOADS, RATE_LIMIT_WINDOW_S):
        return JSONResponse({"error": "rate limited"}, status_code=429)

    provider = str(body.get("provider") or "unknown")
    idempotency_key = _idempotency_key_from_request(request, body)
    tx = body.get("transactions") or []
    if not isinstance(tx, list) or len(tx) == 0:
        return JSONResponse({"error": "missing transactions[]"}, status_code=400)
    if len(tx) > MAX_UPLOAD_ROWS:
        return JSONResponse(
            {"error": f"too many transactions for this environment (max {MAX_UPLOAD_ROWS:,})"},
            status_code=400,
        )
    request_hash = ""
    if idempotency_key:
        request_hash = _ingest_request_hash(provider, "webhook_scaffold", tx)
        with db_conn() as conn:
            existing = conn.execute(
                """
                SELECT run_id, request_hash
                FROM ingest_requests
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (tenant_id, idempotency_key),
            ).fetchone()
        if existing:
            if str(existing["request_hash"] or "") != request_hash:
                return JSONResponse({"error": "idempotency_key_conflict"}, status_code=409)
            with db_conn() as conn:
                if _table_has_column(conn, "runs", "tenant_id"):
                    row = conn.execute(
                        "SELECT alerts_json FROM runs WHERE id = ? AND COALESCE(tenant_id, ?) = ?",
                        (int(existing["run_id"]), TENANT_DEFAULT, tenant_id),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT alerts_json FROM runs WHERE id = ?",
                        (int(existing["run_id"]),),
                    ).fetchone()
            alerts_payload = safe_json_loads(row["alerts_json"], []) if row else []
            return JSONResponse(
                {
                    "ok": True,
                    "run_id": int(existing["run_id"]),
                    "alerts": alerts_payload,
                    "idempotent": True,
                    "ingest_id": idempotency_key,
                }
            )
    # Expect each txn dict to already be in our normalized shape, or close.
    df = pd.DataFrame(tx)
    try:
        df, normalization = normalise_csv(df, return_report=True)
        contract = _ledger_contract_report(df)
        run_created_at = datetime.utcnow().isoformat()
        with db_conn() as conn:
            df, cat_report = apply_deterministic_categorisation(df, s, conn, run_created_at=run_created_at)
        summary, alerts, quality = build_summary_and_alerts(df, s)
        summary = _attach_run_to_run_summary(summary, _latest_run_summary_meta(tenant_id))
    except Exception as e:
        safe_msg = _safe_log_message(e)
        if safe_msg:
            logger.info("Webhook parse/analyse failed: %s: %s", e.__class__.__name__, safe_msg)
        else:
            logger.info("Webhook parse/analyse failed: %s", e.__class__.__name__)
        return JSONResponse(
            {"error": "parse/analyse failed (invalid transaction format or missing required fields)"},
            status_code=400,
        )

    payload = [a.__dict__ for a in alerts]
    file_sha = hashlib.sha256(json.dumps(tx, sort_keys=True).encode("utf-8")).hexdigest()
    settings_hash = _hash_settings(s)
    code_hash = _code_version_hash()
    rule_hash = _rule_inventory_hash()
    artifact_ids = _derive_artifact_ids(file_sha, settings_hash, code_hash, rule_hash)
    params = _build_run_params(
        settings=s,
        source=_safe_source_block(
            provider,
            "webhook_scaffold",
            {"filename": f"{provider}_webhook.json", "ingest_id": idempotency_key},
        ),
        contract=contract,
        cat_report=cat_report,
        normalization=normalization,
        config_hash=settings_hash,
        code_hash=code_hash,
        rule_hash=rule_hash,
        artifact_ids=artifact_ids,
    )

    with db_conn() as conn:
        run_id = _insert_run_row(
            conn=conn,
            created_at=run_created_at,
            filename=f"{provider}_webhook.json",
            params_json=json.dumps(params),
            summary_json=json.dumps(summary),
            alerts_json=json.dumps(payload),
            quality_json=json.dumps(quality),
            file_sha256=file_sha,
            settings_hash=settings_hash,
            tenant_id=tenant_id,
        )
        if idempotency_key:
            try:
                conn.execute(
                    """
                    INSERT INTO ingest_requests
                    (tenant_id, idempotency_key, request_hash, run_id, provider, source_mode, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant_id,
                        idempotency_key,
                        request_hash or _ingest_request_hash(provider, "webhook_scaffold", tx),
                        int(run_id),
                        str(provider),
                        "webhook_scaffold",
                        datetime.utcnow().isoformat(),
                    ),
                )
            except Exception:
                pass
        conn.commit()

    # P1-03: Audit logging for successful webhook ingest
    # role="operator" is safe: lowest role with "create" capability in ROLE_CAPABILITIES
    _log_access(
        tenant_id,
        "webhook",  # actor_id
        "operator", # role (in AUTH_ROLES, has "create" capability)
        "create",   # action
        f"run:{run_id}:webhook_ingest",  # resource
        True  # allowed
    )

    try:
        update_alert_memory_for_run(int(run_id), payload, tenant_id)
    except Exception:
        pass

    return JSONResponse(
        {"ok": True, "run_id": int(run_id), "alerts": payload, "ingest_id": idempotency_key or ""}
    )


@app.post("/api/integrations/{provider}/sync_now", response_class=JSONResponse)
def api_integration_sync_now(request: Request, provider: str, csrf_token: Optional[str] = Form(None)):
    _require_csrf(request, csrf_token)
    _require_role(request, "admin", "update", f"integrations:{provider}:sync")
    return JSONResponse({"detail": "integrations_disabled"}, status_code=403)



if __name__ == "__main__":
    # Optional convenience runner:
    #   python app.py
    # Still recommended for dev:
    #   uvicorn app:app --reload
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
