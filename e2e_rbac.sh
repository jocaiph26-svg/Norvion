#!/usr/bin/env bash
# Purpose: RBAC + tenant isolation + session invalidation regression harness.
# Run: ./e2e_rbac.sh
# Success: prints exactly one line -> E2E_RBAC_OK
# Notes: deterministic, local ASGI transport, no network calls.
# Output: creates tmp/ and artifacts/ for test outputs.
set -euo pipefail

mkdir -p tmp artifacts

PYTHONPATH=. python3 - <<'PY'
import os
import re
from pathlib import Path
import logging

db_path = Path("tmp/e2e_rbac.db")
db_path.parent.mkdir(parents=True, exist_ok=True)
if db_path.exists():
    db_path.unlink()

os.environ["SME_EW_DB_PATH"] = str(db_path)

logging.getLogger().setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)
logging.getLogger("sme_early_warning").setLevel(logging.CRITICAL)

import app as app_module
import asyncio
import httpx


def _upsert_user(email: str, role: str, tenant_id: str, password: str) -> int:
    now = app_module._utc_now_iso()
    pw_hash = app_module.generate_password_hash(password)
    with app_module.db_conn() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE tenant_id = ? AND email = ?",
            (tenant_id, email),
        ).fetchone()
        if row:
            user_id = int(row["id"])
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?, role = ?, is_active = 1, tos_version = ?, tos_accepted_at = ?
                WHERE id = ?
                """,
                (pw_hash, role, app_module.TOS_VERSION, now, user_id),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO users
                (tenant_id, email, password_hash, role, is_active, created_at, tos_version, tos_accepted_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (tenant_id, email, pw_hash, role, now, app_module.TOS_VERSION, now),
            )
            user_id = int(cur.lastrowid)
        conn.commit()
        return user_id


def _insert_run(tenant_id: str) -> int:
    now = app_module._utc_now_iso()
    with app_module.db_conn() as conn:
        run_id = app_module._insert_run_row(
            conn,
            created_at=now,
            filename="e2e_rbac.csv",
            params_json="{}",
            summary_json="{}",
            alerts_json="[]",
            quality_json="{}",
            tenant_id=tenant_id,
        )
        conn.commit()
        return int(run_id)


async def _login(client: httpx.AsyncClient, email: str, password: str) -> None:
    resp = await client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )
    assert resp.status_code == 302, f"login failed for {email}: {resp.status_code}"


async def _get_csrf(client: httpx.AsyncClient) -> str:
    resp = await client.get("/settings", follow_redirects=False)
    assert resp.status_code == 200, f"settings failed: {resp.status_code}"
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    assert match, "csrf_token not found in settings HTML"
    return match.group(1)


def _assert_status(resp, expected: int, label: str) -> None:
    assert resp.status_code == expected, f"{label}: expected {expected}, got {resp.status_code}"


app_module.db_init()

tenant_default = app_module.TENANT_DEFAULT
tenant_b = "tenant_b"

admin_email = "rbac_admin@example.com"
manager_email = "rbac_manager@example.com"
tenant_b_email = "rbac_admin_tenant_b@example.com"
demote_email = "rbac_demote_admin@example.com"
deactivate_email = "rbac_deactivate_admin@example.com"
password = "TestPassw0rd!"

_upsert_user(admin_email, "admin", tenant_default, password)
_upsert_user(manager_email, "manager", tenant_default, password)
_upsert_user(tenant_b_email, "admin", tenant_b, password)
demote_id = _upsert_user(demote_email, "admin", tenant_default, password)
deactivate_id = _upsert_user(deactivate_email, "admin", tenant_default, password)

run_id = _insert_run(tenant_default)

async def main() -> None:
    transport = httpx.ASGITransport(app=app_module.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as manager_client:
        await _login(manager_client, manager_email, password)
        csrf_token = await _get_csrf(manager_client)
        resp = await manager_client.post(
            "/admin/users/create",
            data={
                "email": "rbac_new_user@example.com",
                "password": "TempPassw0rd!",
                "role": "viewer",
                "csrf_token": csrf_token,
            },
            follow_redirects=False,
        )
        print(f"MANAGER_CREATE_STATUS={resp.status_code}")
        _assert_status(resp, 403, "manager POST /admin/users/create")

        resp = await manager_client.get("/access/events", follow_redirects=False)
        _assert_status(resp, 403, "manager GET /access/events")

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as admin_client:
        await _login(admin_client, admin_email, password)
        resp = await admin_client.get("/access/events", follow_redirects=False)
        _assert_status(resp, 200, "admin GET /access/events")

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as tenant_b_client:
        await _login(tenant_b_client, tenant_b_email, password)
        resp = await tenant_b_client.get(f"/run/{run_id}", follow_redirects=False)
        _assert_status(resp, 404, "tenant_b GET /run/{run_id} for tenant_default run")

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as demote_client:
        await _login(demote_client, demote_email, password)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as admin_actor:
            await _login(admin_actor, admin_email, password)
            csrf = await _get_csrf(admin_actor)
            resp = await admin_actor.post(
                f"/admin/users/{demote_id}/update",
                data={
                    "role": "viewer",
                    "is_active": "1",
                    "csrf_token": csrf,
                    "stepup_password": password,
                },
                follow_redirects=False,
            )
            _assert_status(resp, 302, "admin demote user")
        resp = await demote_client.get("/access/events", headers={"accept": "text/html"}, follow_redirects=False)
        _assert_status(resp, 302, "demoted user forced re-auth")

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as deactivate_client:
        await _login(deactivate_client, deactivate_email, password)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as admin_actor:
            await _login(admin_actor, admin_email, password)
            csrf = await _get_csrf(admin_actor)
            resp = await admin_actor.post(
                f"/admin/users/{deactivate_id}/update",
                data={
                    "role": "admin",
                    "is_active": "0",
                    "csrf_token": csrf,
                    "stepup_password": password,
                },
                follow_redirects=False,
            )
            _assert_status(resp, 302, "admin deactivate user")
        resp = await deactivate_client.get("/settings", headers={"accept": "text/html"}, follow_redirects=False)
        _assert_status(resp, 302, "deactivated user forced re-auth")

    print("E2E_RBAC_OK")


asyncio.run(main())
PY
