"""Tollgate web API + upload UI.

Run:  uvicorn tollgate.api:create_app --factory --host 127.0.0.1 --port 8080   (single worker)

Every endpoint except /api/health, /api/auth/status and /api/auth/login needs a login (cookie session) or an API
token (`Authorization: Bearer tg_...`). Roles: viewer (read), analyst (+ scan, URL check), admin (+ intel, rules,
users, audit). The master account is an admin that can never be demoted, disabled or deleted, and is the only one
who can create or change other admins.
"""
from __future__ import annotations

import hmac
import json
import os
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, dynamic, intel as intel_mod, paths, redirects, yara_engine
from .accounts import SESSION_HOURS, Accounts, AuthError, public
from .cape import CapeClient, CapeConfig, CapeError
from .db import IOC_TYPES, SEVERITIES, Store
from .engine import analyze_bytes
from .urlcheck import analyze_url

STATIC = Path(__file__).parent / "static"
COOKIE = "tollgate_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PASSWORD_PATHS = {"/api/auth/change-password", "/api/auth/logout", "/api/me", "/api/auth/status"}


@dataclass
class Settings:
    db: str = field(default_factory=paths.default_db)
    max_upload_mb: int = field(default_factory=lambda: int(os.environ.get("TOLLGATE_MAX_UPLOAD_MB", "50")))
    tracer_url: str = field(default_factory=lambda: os.environ.get("TOLLGATE_TRACER_URL", ""))
    tracer_token: str = field(default_factory=lambda: os.environ.get("TOLLGATE_TRACER_TOKEN", ""))
    allow_local_trace: bool = field(default_factory=lambda: os.environ.get("TOLLGATE_ALLOW_LOCAL_TRACE") == "1")
    yara_dirs: list = field(default_factory=yara_engine.dirs_from_env)
    cookie_secure: str = field(default_factory=lambda: os.environ.get("TOLLGATE_COOKIE_SECURE", "auto"))
    trust_proxy: bool = field(default_factory=lambda: os.environ.get("TOLLGATE_TRUST_PROXY") == "1")
    master_username: str = field(default_factory=lambda: os.environ.get("TOLLGATE_MASTER_USERNAME", ""))
    master_password: str = field(default_factory=lambda: os.environ.get("TOLLGATE_MASTER_PASSWORD", ""))
    cape: CapeConfig = field(default_factory=CapeConfig.from_env)

    @property
    def max_upload(self) -> int:
        return self.max_upload_mb * 1024 * 1024


class LoginBody(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=1000)


class ChangePasswordBody(BaseModel):
    current_password: str = Field(max_length=1000)
    new_password: str = Field(max_length=1000)


class UserCreateBody(BaseModel):
    username: str
    password: str = Field(max_length=1000)
    role: str = "analyst"
    must_change: bool = True


class UserPatchBody(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(None, max_length=1000)
    must_change: bool = True
    unlock: bool = False


class TokenBody(BaseModel):
    label: str = Field("token", max_length=80)
    days: int | None = Field(None, ge=1, le=3650)


class DynamicIocItem(BaseModel):
    type: str
    value: str = Field(max_length=4096)
    severity: str = "high"
    family: str | None = Field(None, max_length=100)


class DynamicIocBody(BaseModel):
    items: list[DynamicIocItem] = Field(max_length=100)


class UrlBody(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    trace: bool = False
    record: bool = True


class IocBody(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=4096)
    family: str | None = Field(None, max_length=100)
    source: str = Field("api", max_length=100)
    severity: str = "critical"
    note: str | None = Field(None, max_length=500)


class ImportBody(BaseModel):
    type: str
    text: str = Field(max_length=5_000_000)
    column: str | None = None
    family: str | None = Field(None, max_length=100)
    source: str = Field("api-import", max_length=100)
    severity: str = "critical"


class RegexRuleBody(BaseModel):
    name: str
    regex: str = Field(min_length=1, max_length=2000)
    severity: str = "high"
    description: str = Field("", max_length=300)


class YaraBody(BaseModel):
    name: str
    text: str = Field(max_length=300_000)


def _clean_filename(name: str | None) -> str:
    base = (name or "upload.bin").replace("\\", "/").split("/")[-1]
    return base[:255] or "upload.bin"


def _forward_trace(settings: Settings, url: str) -> redirects.TraceResult:
    req = urllib.request.Request(
        settings.tracer_url.rstrip("/") + "/trace", data=json.dumps({"url": url}).encode(),
        headers={"Content-Type": "application/json", "X-Tracer-Token": settings.tracer_token}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:  # noqa: S310 - operator-configured internal URL
            return redirects.TraceResult.from_dict(json.loads(resp.read(2_000_000)))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise HTTPException(502, f"tracer service unavailable ({exc.__class__.__name__})") from None


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    boot = Store(cfg.db)
    if cfg.master_username and cfg.master_password and not Accounts(boot).has_master():
        try:  # first start only; the password is forced to change at first login
            Accounts(boot).create_user(cfg.master_username, cfg.master_password, is_master=True, must_change=True, created_by="bootstrap")
        except auth.PolicyError as exc:
            raise RuntimeError(f"TOLLGATE_MASTER_USERNAME/PASSWORD rejected: {exc}") from None
    boot.close()
    engine = yara_engine.YaraEngine(cfg.yara_dirs) if yara_engine.available() else None
    cape_client = CapeClient(cfg.cape) if cfg.cape.enabled else None
    app = FastAPI(title="Tollgate", version=__version__, docs_url="/api/docs", redoc_url=None)
    attempts: dict[str, deque] = defaultdict(deque)

    def get_store():
        store = Store(cfg.db, init=False)
        try:
            yield store
        finally:
            store.close()

    def get_acc(store: Store = Depends(get_store)) -> Accounts:
        return Accounts(store)

    def ip_of(request: Request) -> str | None:
        if cfg.trust_proxy and request.headers.get("x-forwarded-for"):
            return request.headers["x-forwarded-for"].split(",")[0].strip()[:64]
        return request.client.host if request.client else None

    def get_user(request: Request, acc: Accounts = Depends(get_acc)) -> dict:
        header = request.headers.get("authorization", "")
        user = None
        if header.lower().startswith("bearer "):
            user = acc.authenticate_token(header[7:].strip())
            if not user:
                raise HTTPException(401, "invalid or expired API token")
        else:
            raw = request.cookies.get(COOKIE)
            found = acc.get_session(raw) if raw else None
            if found:
                user, sess = found
                if request.method not in SAFE_METHODS and not hmac.compare_digest(
                        request.headers.get("x-csrf-token", "").encode(), sess["csrf"].encode()):
                    raise HTTPException(403, "missing or invalid CSRF token")
        if not user:
            raise HTTPException(401, "authentication required")
        if user["must_change_password"] and request.url.path not in PASSWORD_PATHS:
            raise HTTPException(403, "you must change your password before continuing")
        request.state.user = user
        return user

    def need(minimum: str):
        def dep(user: dict = Depends(get_user)) -> dict:
            if auth.rank(user["role"]) < auth.rank(minimum):
                raise HTTPException(403, f"requires the {minimum} role")
            return user
        return dep

    viewer, analyst, admin = need("viewer"), need("analyst"), need("admin")

    def secure_cookie(request: Request) -> bool:
        if cfg.cookie_secure in ("1", "true", "yes"):
            return True
        if cfg.cookie_secure in ("0", "false", "no"):
            return False
        return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.url.path == "/api/scan":
            declared = request.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > cfg.max_upload + 1_048_576:
                return JSONResponse({"detail": f"upload larger than {cfg.max_upload_mb} MB"}, status_code=413)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                   "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- authentication ----------------------------------------------------

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/auth/status")
    def auth_status(request: Request, acc: Accounts = Depends(get_acc)):
        out = {"setup_required": not acc.has_master(), "authenticated": False, "user": None, "csrf": None}
        raw = request.cookies.get(COOKIE)
        found = acc.get_session(raw) if raw else None
        if found:
            out.update(authenticated=True, user=public(found[0]), csrf=found[1]["csrf"])
        return out

    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response, acc: Accounts = Depends(get_acc)):
        ip, now = ip_of(request) or "?", time.monotonic()
        window = attempts[ip]
        while window and now - window[0] > 600:
            window.popleft()
        if len(window) >= 20:
            raise HTTPException(429, "too many login attempts from this address; wait a few minutes")
        window.append(now)
        try:
            user = acc.authenticate(body.username, body.password, ip)
        except AuthError as exc:
            raise HTTPException(401, str(exc)) from None
        token, csrf = acc.create_session(user["id"], ip, request.headers.get("user-agent"))
        response.set_cookie(COOKIE, token, max_age=SESSION_HOURS * 3600, httponly=True, samesite="strict",
                            secure=secure_cookie(request), path="/")
        return {"user": public(user), "csrf": csrf, "must_change_password": bool(user["must_change_password"])}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response, user: dict = Depends(get_user), acc: Accounts = Depends(get_acc)):
        raw = request.cookies.get(COOKIE)
        if raw:
            acc.destroy_session(raw)
        acc.audit(user["username"], "logout", "", ip_of(request))
        response.delete_cookie(COOKIE, path="/")
        return {"result": "ok"}

    @app.post("/api/auth/change-password")
    def change_password(body: ChangePasswordBody, request: Request, user: dict = Depends(get_user), acc: Accounts = Depends(get_acc)):
        if not auth.verify_password(body.current_password, user["password_hash"]):
            raise HTTPException(400, "current password is incorrect")
        if body.current_password == body.new_password:
            raise HTTPException(400, "new password must be different")
        try:
            acc.set_password(user["username"], body.new_password, user["username"], keep_session=request.cookies.get(COOKIE))
        except auth.PolicyError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"result": "ok"}

    @app.get("/api/me")
    def me(user: dict = Depends(get_user)):
        return public(user)

    @app.get("/api/me/tokens")
    def my_tokens(user: dict = Depends(get_user), acc: Accounts = Depends(get_acc)):
        return acc.list_tokens(user["id"])

    @app.post("/api/me/tokens")
    def new_token(body: TokenBody, request: Request, user: dict = Depends(get_user), acc: Accounts = Depends(get_acc)):
        token = acc.create_token(user["id"], body.label, body.days)
        acc.audit(user["username"], "token.create", body.label, ip_of(request))
        return {"token": token, "note": "Copy it now. It is shown only once and stored hashed."}

    @app.delete("/api/me/tokens/{token_id}")
    def revoke_token(token_id: int, request: Request, user: dict = Depends(get_user), acc: Accounts = Depends(get_acc)):
        if not acc.revoke_token(token_id, user["id"]):
            raise HTTPException(404, "no such token")
        acc.audit(user["username"], "token.revoke", str(token_id), ip_of(request))
        return {"result": "ok"}

    # ---- read-only (viewer+) -----------------------------------------------

    @app.get("/api/status")
    def status(_: dict = Depends(viewer), store: Store = Depends(get_store)):
        return {"status": "ok", "version": __version__, "yara": bool(engine and engine.rule_count()),
                "yara_rules": engine.rule_count() if engine else 0,
                "tracing": "tracer" if cfg.tracer_url else ("local" if cfg.allow_local_trace else "disabled"),
                "dynamic": "cape" if cape_client else "disabled", "max_upload_mb": cfg.max_upload_mb,
                **{k: v for k, v in store.stats().items() if k in ("scans", "iocs_total")}}

    @app.get("/api/history")
    def history(limit: int = 50, verdict: str | None = None, q: str | None = None, sha256: str | None = None,
                _: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.history(min(max(limit, 1), 500), verdict, sha256, q)

    @app.get("/api/history/{scan_id}")
    def history_item(scan_id: int, _: dict = Depends(viewer), store: Store = Depends(get_store)):
        rep = store.get_scan(scan_id)
        if rep is None:
            raise HTTPException(404, "no such scan")
        return rep

    @app.get("/api/urls")
    def urls(limit: int = 100, _: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.tracked_urls(min(max(limit, 1), 500))

    @app.get("/api/retro")
    def retro(_: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.retro_hunt()

    @app.get("/api/intel/stats")
    def stats(_: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.stats()

    @app.get("/api/intel/search")
    def search(q: str, _: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.lookup_any(q)

    @app.get("/api/rules")
    def rules(_: dict = Depends(viewer), store: Store = Depends(get_store)):
        return {"regex": store.list_rules(),
                "yara": {"loaded": [os.path.basename(p) for p in (engine.loaded if engine else [])],
                         "rules": engine.rule_count() if engine else 0,
                         "errors": engine.errors if engine else [], "available": yara_engine.available()}}

    # ---- analyst+ ------------------------------------------------------------

    @app.post("/api/scan")
    def scan(file: UploadFile = File(...), record: bool = Form(True), detonate: bool = Form(False),
             user: dict = Depends(analyst), store: Store = Depends(get_store)):
        data = file.file.read(cfg.max_upload + 1)
        if len(data) > cfg.max_upload:
            raise HTTPException(413, f"upload larger than {cfg.max_upload_mb} MB")
        name = _clean_filename(file.filename)
        report = analyze_bytes(data, name, store, source="api", record=record, yara_engine=engine, user=user["username"])
        out = report.to_dict()
        if detonate:                      # explicit, per-scan opt-in: the file is sent to your CAPE server
            if cape_client is None:
                out["dynamic"] = {"error": "dynamic analysis is not configured (set TOLLGATE_CAPE_URL)"}
            else:
                try:
                    task = dynamic.submit(store, cape_client, name, data, report.scan_id, user["username"])
                    Accounts(store).audit(user["username"], "dynamic.submit",
                                          f"{name[:100]} sha256={report.hashes['sha256']} task={task['id']}")
                    out["dynamic"] = {"task_id": task["id"], "status": task["status"]}
                except CapeError as exc:
                    out["dynamic"] = {"error": str(exc)}
        return out

    @app.get("/api/dynamic")
    def list_dynamic(scan_id: int | None = None, limit: int = 50, _: dict = Depends(viewer), store: Store = Depends(get_store)):
        return store.list_dynamic_tasks(scan_id, min(max(limit, 1), 200))

    @app.get("/api/dynamic/{task_id}")
    def get_dynamic(task_id: int, _: dict = Depends(viewer), store: Store = Depends(get_store)):
        task = store.get_dynamic_task(task_id)
        if task is None:
            raise HTTPException(404, "no such dynamic-analysis task")
        warning = None
        if task["status"] not in ("reported", "failed") and cape_client is not None:
            try:
                task = dynamic.refresh(store, cape_client, task_id)
            except CapeError as exc:
                warning = str(exc)
                task = store.get_dynamic_task(task_id)
        out = dict(task)
        if warning:
            out["warning"] = warning
        if task["scan_id"]:
            report = store.get_scan(task["scan_id"])
            if report:
                out["scan"] = {"id": task["scan_id"], "verdict": report["verdict"], "score": report["score"]}
        return out

    @app.post("/api/dynamic/{task_id}/iocs")
    def add_dynamic_iocs(task_id: int, body: DynamicIocBody, request: Request, user: dict = Depends(admin),
                         store: Store = Depends(get_store)):
        task = store.get_dynamic_task(task_id)
        if task is None or not task["summary"]:
            raise HTTPException(404, "no finished analysis with that id")
        sm = task["summary"]
        observed = {"domain": set(sm["network"]["domains"]), "ip": set(sm["network"]["ips"]),
                    "url": set(sm["network"]["urls"]) | set(sm["c2_candidates"]), "sha256": {d["sha256"].lower() for d in sm["dropped"]}}
        added, skipped = 0, []
        for item in body.items:
            if item.type not in observed or item.value not in observed[item.type]:
                skipped.append(item.value[:80])
                continue
            try:
                store.add_ioc(item.type, item.value, item.family or (sm["families"][0] if sm["families"] else None),
                              f"cape:task{task_id}", item.severity, "observed in sandbox run")
                added += 1
            except ValueError:
                skipped.append(item.value[:80])
        Accounts(store).audit(user["username"], "intel.from_dynamic", f"task {task_id}: {added} added, {len(skipped)} skipped", ip_of(request))
        return {"added": added, "skipped": skipped}

    @app.post("/api/url")
    def check_url(body: UrlBody, user: dict = Depends(analyst), store: Store = Depends(get_store)):
        ur = analyze_url(body.url, store)
        if body.record and ur.normalized and "://" in ur.normalized:
            store.track_url(ur.normalized, None, "api")
        out = ur.to_dict()
        if body.trace:
            if cfg.tracer_url:
                result = redirects.assess(_forward_trace(cfg, body.url), store if body.record else None)
            elif cfg.allow_local_trace:
                result = redirects.trace(body.url, store=store if body.record else None)
            else:
                raise HTTPException(503, "redirect tracing is disabled: configure TOLLGATE_TRACER_URL "
                                         "(recommended) or TOLLGATE_ALLOW_LOCAL_TRACE=1")
            Accounts(store).audit(user["username"], "url.trace", ur.normalized or body.url[:200])
            out["trace"] = result.to_dict()
        return out

    # ---- admin ---------------------------------------------------------------

    def bad_request(exc: Exception):
        raise HTTPException(400, str(exc)) from None

    @app.post("/api/intel/ioc")
    def add_ioc(body: IocBody, request: Request, user: dict = Depends(admin), store: Store = Depends(get_store)):
        try:
            result = store.add_ioc(body.type, body.value, body.family, body.source, body.severity, body.note)
        except ValueError as exc:
            bad_request(exc)
        Accounts(store).audit(user["username"], "intel.add", f"{body.type} {body.value[:120]} ({body.severity})", ip_of(request))
        return {"result": result}

    @app.delete("/api/intel/ioc")
    def remove_ioc(type: str, value: str, request: Request, user: dict = Depends(admin), store: Store = Depends(get_store)):
        try:
            removed = store.remove_ioc(type, value)
        except ValueError as exc:
            bad_request(exc)
        Accounts(store).audit(user["username"], "intel.remove", f"{type} {value[:120]}", ip_of(request))
        return {"removed": removed}

    @app.post("/api/intel/import")
    def import_iocs(body: ImportBody, request: Request, user: dict = Depends(admin), store: Store = Depends(get_store)):
        if body.type not in IOC_TYPES or body.severity not in SEVERITIES:
            raise HTTPException(400, "invalid type or severity")
        try:
            result = intel_mod.import_text(store, body.text, body.type, column=body.column, family=body.family,
                                           source=body.source, severity=body.severity)
        except ValueError as exc:
            bad_request(exc)
        Accounts(store).audit(user["username"], "intel.import", f"{body.type} {result}", ip_of(request))
        return result

    @app.post("/api/rules/regex")
    def add_regex_rule(body: RegexRuleBody, request: Request, user: dict = Depends(admin), store: Store = Depends(get_store)):
        try:
            store.add_rule(body.name, body.regex, body.severity, body.description)
        except ValueError as exc:
            bad_request(exc)
        Accounts(store).audit(user["username"], "rule.regex", body.name, ip_of(request))
        return {"result": "ok"}

    @app.post("/api/rules/yara")
    def add_yara(body: YaraBody, request: Request, user: dict = Depends(admin), store: Store = Depends(get_store)):
        if engine is None:
            raise HTTPException(503, "yara-python is not installed")
        try:
            path = yara_engine.add_rule_file(body.name, body.text, cfg.yara_dirs[-1])
        except ValueError as exc:
            bad_request(exc)
        engine.reload()
        Accounts(store).audit(user["username"], "rule.yara", os.path.basename(path), ip_of(request))
        return {"result": "ok", "file": os.path.basename(path), "rules": engine.rule_count()}

    # ---- user management ---------------------------------------------------

    def can_manage(actor: dict, target: dict | None, new_role: str | None = None) -> None:
        """Admins manage viewers/analysts; only the master manages admins; nobody edits themselves here."""
        if actor["is_master"]:
            return
        if (target and (target["role"] == "admin" or target["is_master"])) or new_role == "admin":
            raise HTTPException(403, "only the master account can create or change administrators")

    @app.get("/api/users")
    def list_users(_: dict = Depends(admin), acc: Accounts = Depends(get_acc)):
        return acc.list_users()

    @app.post("/api/users")
    def create_user(body: UserCreateBody, request: Request, actor: dict = Depends(admin), acc: Accounts = Depends(get_acc)):
        can_manage(actor, None, body.role)
        try:
            user = acc.create_user(body.username, body.password, body.role, must_change=body.must_change, created_by=actor["username"])
        except auth.PolicyError as exc:
            bad_request(exc)
        return public(user)

    @app.patch("/api/users/{username}")
    def patch_user(username: str, body: UserPatchBody, request: Request, actor: dict = Depends(admin), acc: Accounts = Depends(get_acc)):
        target = acc.get_user(username)
        if not target:
            raise HTTPException(404, "no such user")
        if target["id"] == actor["id"] and (body.role is not None or body.active is not None):
            raise HTTPException(400, "you cannot change your own role or active state")
        can_manage(actor, target, body.role)
        try:
            if body.role is not None or body.active is not None:
                acc.update_user(username, body.role, body.active, actor["username"])
            if body.password:
                acc.set_password(username, body.password, actor["username"], must_change=body.must_change)
            if body.unlock:
                acc.unlock(username, actor["username"])
        except auth.PolicyError as exc:
            bad_request(exc)
        return public(acc.get_user(username))

    @app.delete("/api/users/{username}")
    def delete_user(username: str, actor: dict = Depends(admin), acc: Accounts = Depends(get_acc)):
        target = acc.get_user(username)
        if not target:
            raise HTTPException(404, "no such user")
        if target["id"] == actor["id"]:
            raise HTTPException(400, "you cannot delete your own account")
        can_manage(actor, target)
        try:
            acc.delete_user(username, actor["username"])
        except auth.PolicyError as exc:
            bad_request(exc)
        return {"result": "ok"}

    @app.get("/api/audit")
    def audit_log(limit: int = 200, _: dict = Depends(admin), acc: Accounts = Depends(get_acc)):
        return acc.audit_log(min(max(limit, 1), 1000))

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
