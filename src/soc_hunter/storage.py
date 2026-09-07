import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import PostgresConfig, secret
from .domain import Finding

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS soc_hunter;
CREATE TABLE IF NOT EXISTS soc_hunter.schema_version (version integer PRIMARY KEY);
INSERT INTO soc_hunter.schema_version VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS soc_hunter.runs (
    id uuid PRIMARY KEY, started_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL, data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS soc_hunter.findings (
    id uuid PRIMARY KEY, first_run_id uuid NOT NULL REFERENCES soc_hunter.runs(id),
    candidate_key text NOT NULL, data jsonb NOT NULL,
    review_state text NOT NULL DEFAULT 'open', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS soc_hunter.run_findings (
    run_id uuid REFERENCES soc_hunter.runs(id), finding_id uuid REFERENCES soc_hunter.findings(id),
    PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE IF NOT EXISTS soc_hunter.delivery (
    finding_id uuid PRIMARY KEY REFERENCES soc_hunter.findings(id),
    state text NOT NULL CHECK (state IN ('sending','sent','unknown')),
    ticket_id bigint, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS soc_hunter.reviews (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES soc_hunter.findings(id),
    actor_id bigint NOT NULL, decision text NOT NULL, rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
"""


def connect(config: PostgresConfig):
    return psycopg.connect(
        host=config.host,
        port=config.port,
        dbname=config.database,
        user=config.username,
        password=secret(config.password_file),
        sslmode=config.sslmode,
        sslrootcert=config.ca_file,
        connect_timeout=10,
        row_factory=dict_row,
    )


class PostgresStore:
    def __init__(self, connection):
        self.connection = connection

    def migrate(self):
        self.connection.execute(SCHEMA)
        self.connection.commit()

    def get_run(self, run_id):
        row = self.connection.execute("SELECT data FROM soc_hunter.runs WHERE id=%s", (run_id,)).fetchone()
        if not row:
            raise ValueError("Run checkpoint does not exist")
        return row["data"]

    def save_run(self, run):
        self.connection.execute(
            "INSERT INTO soc_hunter.runs (id,status,data) VALUES (%s,%s,%s) "
            "ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,data=EXCLUDED.data",
            (run["id"], run["status"], Jsonb(run)),
        )
        self.connection.commit()

    def save_finding(self, finding: Finding):
        self.connection.execute(
            "INSERT INTO soc_hunter.findings (id,first_run_id,candidate_key,data) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (id) DO NOTHING",
            (finding.id, finding.run_id, finding.candidate.key, Jsonb(finding.model_dump(mode="json"))),
        )
        self.connection.execute(
            "INSERT INTO soc_hunter.run_findings VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (finding.run_id, finding.id),
        )
        self.connection.commit()

    def findings(self, run_id):
        rows = self.connection.execute(
            "SELECT f.data FROM soc_hunter.findings f JOIN soc_hunter.run_findings r ON f.id=r.finding_id "
            "WHERE r.run_id=%s ORDER BY f.created_at",
            (run_id,),
        ).fetchall()
        return [Finding.model_validate(row["data"]) for row in rows]

    @contextmanager
    def delivery_lock(self, finding_id):
        key = int(finding_id.replace("-", "")[:15], 16)
        self.connection.execute("SELECT pg_advisory_lock(%s)", (key,))
        self.connection.commit()
        try:
            yield
        finally:
            self.connection.rollback()
            self.connection.execute("SELECT pg_advisory_unlock(%s)", (key,))
            self.connection.commit()

    def delivery(self, finding_id):
        return self.connection.execute(
            "SELECT * FROM soc_hunter.delivery WHERE finding_id=%s", (finding_id,)
        ).fetchone()

    def mark_delivery(self, finding_id, state, ticket_id=None):
        self.connection.execute(
            "INSERT INTO soc_hunter.delivery (finding_id,state,ticket_id) VALUES (%s,%s,%s) "
            "ON CONFLICT (finding_id) DO UPDATE SET state=EXCLUDED.state,ticket_id=EXCLUDED.ticket_id,updated_at=now()",
            (finding_id, state, ticket_id),
        )
        self.connection.commit()


class FileStore:
    """Demo only. Live runs must use PostgreSQL; no silent fallback."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, name, value):
        path = self.directory / name
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)

    def save_run(self, run):
        self.write("run.json", run)

    def get_run(self, run_id):
        run = json.loads((self.directory / "run.json").read_text(encoding="utf-8"))
        if run["id"] != run_id:
            raise ValueError("Run checkpoint does not match requested run")
        return run

    def findings(self, run_id):
        findings = []
        for path in self.directory.glob("finding-*.json"):
            finding = Finding.model_validate_json(path.read_text(encoding="utf-8"))
            if finding.run_id == run_id:
                findings.append(finding)
        return findings

    def save_finding(self, finding):
        self.write(f"finding-{finding.id}.json", finding.model_dump(mode="json"))


def now():
    return datetime.now(timezone.utc).isoformat()
