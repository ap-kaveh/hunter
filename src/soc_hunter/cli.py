import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .domain import utc
from .fixtures import demo_records
from .runner import hunt, write_report
from .splunk import Splunk, firewall_summary_query, summary_query
from .storage import FileStore, PostgresStore, connect
from .zammad import Zammad, publish


def main():
    parser = argparse.ArgumentParser(description="Manually initiated on-premises SOC hunts")
    parser.add_argument("--config", default="config.yaml")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-config")
    setup_ui = commands.add_parser("ui-init", help="Create the local dashboard administrator")
    setup_ui.add_argument("--ui-dir", default="data/ui")
    serve = commands.add_parser("serve", help="Run the authenticated local web dashboard")
    serve.add_argument("--ui-dir", default="data/ui")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--tls-cert")
    serve.add_argument("--tls-key")
    commands.add_parser("plan", help="Print the generated, read-only aggregation SPL")
    demo = commands.add_parser("demo", help="Synthetic data and mock model; cannot publish tickets")
    demo.add_argument("--output", default=None)
    live = commands.add_parser(
        "hunt", help="Live bounded search + model; saves to PostgreSQL, does not publish"
    )
    live.add_argument("--start", required=True)
    live.add_argument("--end", required=True)
    commands.add_parser("db-init", help="Create the dedicated soc_hunter schema in the configured database")
    check = commands.add_parser("check", help="Read-only connectivity checks")
    check.add_argument("service", choices=["splunk", "postgres", "zammad", "model"])
    delivery = commands.add_parser("publish", help="Create finding tickets for a saved live run")
    delivery.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.command == "validate-config":
            print("Configuration valid. Connectivity and approval enforcement are not implied.")
        elif args.command == "ui-init":
            from .dashboard import init_admin

            password_path = init_admin(args.ui_dir)
            print(f"Dashboard administrator created. Initial password file: {password_path}")
        elif args.command == "serve":
            import uvicorn

            from .dashboard import create_app

            if bool(args.tls_cert) != bool(args.tls_key):
                raise ValueError("Both TLS certificate and key are required")
            if args.host not in ("127.0.0.1", "localhost", "::1") and not args.tls_cert:
                raise ValueError("TLS is required when exposing the dashboard beyond loopback")
            app = create_app(args.config, args.ui_dir, secure_cookie=bool(args.tls_cert))
            uvicorn.run(
                app,
                host=args.host,
                port=args.port,
                ssl_certfile=args.tls_cert,
                ssl_keyfile=args.tls_key,
                access_log=False,
            )
        elif args.command == "plan":
            print(summary_query(config.splunk, config.hunts))
            if config.hunts.firewall_enabled:
                print("\n" + firewall_summary_query(config.splunk))
        elif args.command == "demo":
            if config.model.mode != "mock":
                raise ValueError("Demo requires model.mode=mock")
            directory = args.output or str(Path(config.data_dir) / "demo")
            records, start, end = demo_records()
            run, findings = hunt(config, start, end, FileStore(directory), fixture=records)
            write_report(directory, run, findings)
            print(
                json.dumps(
                    {
                        "run_id": run["id"],
                        "status": run["status"],
                        "findings": len(findings),
                        "report": str(Path(directory) / "report.md"),
                        "synthetic": True,
                    }
                )
            )
            if run["candidate_failures"]:
                return 2
        elif args.command == "db-init":
            with connect(config.postgres) as connection:
                PostgresStore(connection).migrate()
            print("soc_hunter schema initialized")
        elif args.command == "check":
            if args.service == "splunk":
                result = Splunk(config.splunk).check()
            elif args.service == "zammad":
                result = Zammad(config.zammad).check()
            elif args.service == "postgres":
                with connect(config.postgres) as connection:
                    result = connection.execute(
                        "SELECT NOT pg_is_in_recovery() AS writable_primary"
                    ).fetchone()
                if not result["writable_primary"]:
                    raise ValueError("PostgreSQL endpoint is a replica; use the designated writable endpoint")
            else:
                from .model import Investigator

                if config.model.mode != "live":
                    raise ValueError("Set model.mode=live for a model connectivity check")
                client = Investigator(config.model).client
                response = client.get("models")
                response.raise_for_status()
                ids = [item["id"] for item in response.json()["data"]]
                if config.model.name not in ids:
                    raise ValueError("Configured model name is not served by this endpoint")
                result = {"reachable": True, "model_available": True}
            print(json.dumps(result))
        elif args.command == "hunt":
            start, end = utc(args.start), utc(args.end)
            if config.model.mode != "live":
                raise ValueError("Live hunt requires model.mode=live")
            if start >= end or (end - start).total_seconds() > config.hunts.max_window_hours * 3600:
                raise ValueError("Window must be ordered and within the configured maximum")
            with connect(config.postgres) as connection:
                run, findings = hunt(
                    config, start, end, PostgresStore(connection), splunk=Splunk(config.splunk)
                )
            directory = Path(config.data_dir) / run["id"]
            write_report(directory, run, findings)
            print(
                json.dumps(
                    {
                        "run_id": run["id"],
                        "status": run["status"],
                        "findings": len(findings),
                        "tickets_created": 0,
                        "report": str(directory / "report.md"),
                    }
                )
            )
            if run["status"] != "complete":
                return 2
        elif args.command == "publish":
            if not config.zammad.enabled or not config.zammad.customer_id:
                raise ValueError("Zammad must be configured and enabled")
            if not config.zammad.tier2_role_ids or not config.zammad.approval_enforcement_verified:
                raise ValueError("Tier 2 closure enforcement must be verified in Zammad before publication")
            with connect(config.postgres) as connection:
                store = PostgresStore(connection)
                findings = store.findings(args.run_id)
                print(json.dumps(publish(store, Zammad(config.zammad), findings)))
    except KeyboardInterrupt:
        print(
            "Interrupted; any active search cancellation was attempted and progress retained.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        # Do not expose raw HTTP bodies, tokens, connection strings or log values in errors.
        if isinstance(exc, (ValueError, FileNotFoundError)) and not hasattr(exc, "errors"):
            message = str(exc)
        else:
            message = "Operation failed. Check configuration, service availability and saved run status."
        print(f"{type(exc).__name__}: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
