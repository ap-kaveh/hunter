"""Optional integration tests against a disposable database, never the user's HA cluster."""

import os

import psycopg
import pytest
from psycopg.rows import dict_row

from soc_hunter.config import Config
from soc_hunter.fixtures import demo_records
from soc_hunter.runner import hunt
from soc_hunter.storage import PostgresStore


@pytest.mark.skipif(not os.environ.get("HUNTER_TEST_PG_DSN"), reason="Disposable PostgreSQL not configured")
def test_postgres_persistence_and_delivery():
    with psycopg.connect(os.environ["HUNTER_TEST_PG_DSN"], row_factory=dict_row) as connection:
        store = PostgresStore(connection)
        store.migrate()
        store.migrate()
        records, start, end = demo_records()
        run, findings = hunt(Config(), start, end, store, fixture=records)
        assert len(store.findings(run["id"])) == 8
        store.save_finding(findings[0])
        assert len(store.findings(run["id"])) == 8
        with store.delivery_lock(findings[0].id):
            store.mark_delivery(findings[0].id, "sending")
            store.mark_delivery(findings[0].id, "sent", 321)
            assert store.delivery(findings[0].id)["ticket_id"] == 321
