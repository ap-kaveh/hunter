import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from hashlib import pbkdf2_hmac
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import Config, load_config
from .jobs import Jobs, atomic_json
from .monitor import Monitor
from .rules import RULESET_VERSION, catalog


def init_admin(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    credentials = directory / "admin.json"
    if credentials.exists():
        raise ValueError("Dashboard administrator is already initialized")
    password = secrets.token_urlsafe(18)
    salt = secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()
    atomic_json(credentials, {"username": "admin", "salt": salt, "digest": digest})
    password_file = directory / "initial-password.txt"
    password_file.write_text(password + "\n")
    os.chmod(password_file, 0o600)
    return password_file


class Login(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=200)


class Start(BaseModel):
    mode: str = "demo"
    start: str | None = None
    end: str | None = None


class ConfigEdit(BaseModel):
    yaml: str = Field(max_length=50000)


class SecretEdit(BaseModel):
    value: str = Field(min_length=1, max_length=10000)


def create_app(config_path, data_dir, secure_cookie=True):
    config_path = Path(config_path).resolve()
    directory = Path(data_dir).resolve()
    jobs = Jobs(directory / "jobs", config_path)
    credentials = json.loads((directory / "admin.json").read_text())
    sessions = {}
    failures = {}
    monitor = Monitor(directory)

    @asynccontextmanager
    async def lifespan(app):
        yield
        jobs.close()

    app = FastAPI(title="SOC Hunter", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.jobs = jobs

    @app.middleware("http")
    async def security_headers(request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and urlsplit(origin).netloc != request.headers.get("host"):
                return Response("Invalid origin", status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    def authenticated(request: Request):
        session = sessions.get(request.cookies.get("hunter_session", ""))
        if not session or session["expires"] < time.time():
            raise HTTPException(401, "Sign in to continue")
        if request.method not in ("GET", "HEAD"):
            if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
                raise HTTPException(403, "Invalid request token; reload the page")
        return session

    @app.post("/api/login")
    def login(body: Login, request: Request, response: Response):
        address = request.client.host if request.client else "unknown"
        attempts = [stamp for stamp in failures.get(address, []) if stamp > time.time() - 60]
        if len(attempts) >= 5:
            raise HTTPException(429, "Too many attempts; wait a minute")
        digest = pbkdf2_hmac(
            "sha256", body.password.encode(), bytes.fromhex(credentials["salt"]), 600000
        ).hex()
        if not hmac.compare_digest(body.username, credentials["username"]) or not hmac.compare_digest(
            digest, credentials["digest"]
        ):
            failures[address] = attempts + [time.time()]
            raise HTTPException(401, "Incorrect username or password")
        failures.pop(address, None)
        for token in [key for key, item in sessions.items() if item["expires"] < time.time()]:
            sessions.pop(token, None)
        identifier = secrets.token_urlsafe(32)
        session = {"csrf": secrets.token_urlsafe(32), "expires": time.time() + 8 * 3600}
        sessions[identifier] = session
        response.set_cookie(
            "hunter_session",
            identifier,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=8 * 3600,
        )
        return {"username": "admin", "csrf": session["csrf"]}

    @app.get("/api/session")
    def session(current=Depends(authenticated)):
        return {"username": "admin", "csrf": current["csrf"]}

    @app.get("/api/rules")
    def rules(current=Depends(authenticated)):
        return {"version": RULESET_VERSION, "rules": catalog(load_config(config_path).hunts)}

    @app.get("/api/monitor")
    def monitoring(current=Depends(authenticated)):
        return monitor.snapshot()

    @app.post("/api/logout")
    def logout(request: Request, response: Response, current=Depends(authenticated)):
        sessions.pop(request.cookies.get("hunter_session", ""), None)
        response.delete_cookie("hunter_session")
        return {"ok": True}

    @app.get("/api/jobs")
    def list_jobs(current=Depends(authenticated)):
        return jobs.list()

    @app.post("/api/jobs")
    def start_job(body: Start, current=Depends(authenticated)):
        try:
            return jobs.start(body.mode, body.start, body.end)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/jobs/{job_id}/{action}")
    def control_job(job_id: str, action: str, current=Depends(authenticated)):
        try:
            if action == "publish":
                from .storage import PostgresStore, connect
                from .zammad import Zammad, publish

                job = jobs.get(job_id)
                if job["mode"] != "live" or job["status"] not in ("complete", "partial"):
                    raise ValueError("Only completed live investigations can publish findings")
                config = load_config(str(config_path))
                if not config.zammad.enabled or not config.zammad.customer_id:
                    raise ValueError("Configure and enable the Zammad integration first")
                if not config.zammad.approval_enforcement_verified or not config.zammad.tier2_role_ids:
                    raise ValueError("Verify Tier 2 closure enforcement and configure role IDs first")
                with connect(config.postgres) as connection:
                    store = PostgresStore(connection)
                    result = publish(store, Zammad(config.zammad), store.findings(job["progress"]["id"]))
                return result
            if action == "stop":
                return jobs.stop(job_id)
            if action == "resume":
                return jobs.resume(job_id)
            raise ValueError("Unknown action")
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str, current=Depends(authenticated)):
        try:
            path = jobs.path(job_id) / "report.md"
            if not path.exists():
                raise FileNotFoundError()
            return FileResponse(path, media_type="text/plain", filename=f"hunt-{job_id}.md")
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(404, "Report not available yet") from exc

    @app.get("/api/jobs/{job_id}")
    def job_details(job_id: str, current=Depends(authenticated)):
        try:
            return jobs.get(job_id)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(404, "Hunt not found") from exc

    @app.get("/api/config")
    def get_config(current=Depends(authenticated)):
        config = load_config(str(config_path))
        value = config.model_dump()
        return {"config": value, "yaml": yaml.safe_dump(value, sort_keys=False), "busy": jobs.busy()}

    @app.put("/api/config")
    def set_config(body: ConfigEdit, current=Depends(authenticated)):
        try:
            value = Config.model_validate(yaml.safe_load(body.yaml))
        except Exception as exc:
            raise HTTPException(
                400, "Configuration invalid. Check field names, values and HTTPS URLs."
            ) from exc
        temporary = config_path.with_suffix(".tmp")
        temporary.write_text(yaml.safe_dump(value.model_dump(), sort_keys=False), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(config_path)
        return {
            "ok": True,
            "message": "Saved. Active and resumed hunts keep their original configuration snapshot.",
        }

    @app.put("/api/secrets/{service}")
    def set_secret(service: str, body: SecretEdit, current=Depends(authenticated)):
        mapping = {
            "splunk": ("splunk", "token_file"),
            "zammad": ("zammad", "token_file"),
            "postgres": ("postgres", "password_file"),
            "model": ("model", "api_key_file"),
        }
        if service not in mapping or "\n" in body.value.strip() or "\r" in body.value.strip():
            raise HTTPException(400, "Unknown service or invalid secret")
        if jobs.busy():
            raise HTTPException(409, "Stop active hunts before replacing credentials")
        secret_dir = directory / "secrets"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        path = secret_dir / service
        temporary = path.with_suffix(".tmp")
        temporary.write_text(body.value.strip(), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        config = load_config(str(config_path))
        section, field = mapping[service]
        setattr(getattr(config, section), field, str(path))
        temporary = config_path.with_suffix(".tmp")
        temporary.write_text(yaml.safe_dump(config.model_dump(), sort_keys=False))
        os.chmod(temporary, 0o600)
        temporary.replace(config_path)
        return {"ok": True, "message": "Secret saved; its value will not be returned by the dashboard."}

    @app.post("/api/check/{service}")
    def check(service: str, current=Depends(authenticated)):
        config = load_config(str(config_path))
        try:
            if service == "splunk":
                from .splunk import Splunk

                result = Splunk(config.splunk).check()
            elif service == "zammad":
                from .zammad import Zammad

                result = Zammad(config.zammad).check()
            elif service == "postgres":
                from .storage import connect

                with connect(config.postgres) as connection:
                    result = connection.execute(
                        "SELECT NOT pg_is_in_recovery() AS writable_primary"
                    ).fetchone()
                if not result["writable_primary"]:
                    raise ValueError("Replica endpoint")
            elif service == "model":
                from .model import Investigator

                if config.model.mode != "live":
                    return {
                        "ok": False,
                        "message": "Mock mode selected. Configure the live model to test inference connectivity.",
                    }
                response = Investigator(config.model).client.get("models")
                response.raise_for_status()
                if config.model.name not in [item["id"] for item in response.json()["data"]]:
                    raise ValueError("Model name not available")
                result = {"model_available": True}
            else:
                raise HTTPException(404, "Unknown service")
            return {"ok": True, "result": result}
        except HTTPException:
            raise
        except Exception as exc:
            return {
                "ok": False,
                "error_type": type(exc).__name__,
                "message": "Check endpoint, credential file, CA trust and service permissions. No changes were made.",
            }

    web = Path(__file__).parent / "web"

    @app.get("/")
    def index():
        return FileResponse(web / "index.html")

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ("app.js", "style.css"):
            raise HTTPException(404)
        return FileResponse(web / name)

    return app
