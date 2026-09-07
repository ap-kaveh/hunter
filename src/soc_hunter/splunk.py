import json
import time
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import quote, urlencode

import httpx

from .config import HuntConfig, SplunkConfig, secret, tls_context
from .domain import Bucket, utc
from .normalize import safe_ip, safe_text


@dataclass
class SearchResult:
    sid: str
    rows: list[dict]
    total: int
    truncated: bool
    warnings: list[str]


def literal(value: str):
    # Used only in eval/where equality expressions, never in raw search predicates.
    return json.dumps(value, ensure_ascii=True)


def waf_fields():
    return (
        ' | eval hunter_src=coalesce(src,srcip,"unknown"), '
        'hunter_app=coalesce(http_host,hostname,policy,"unknown"), '
        'hunter_path=replace(coalesce(http_url,url,"/"),"[?].*$",""), '
        "hunter_status=tonumber(http_retcode)"
    )


def summary_query(config: SplunkConfig, hunts: HuntConfig):
    sensitive = " OR ".join(
        f"like(lower(hunter_path),{literal('%' + p + '%')})" for p in hunts.sensitive_paths
    )
    sensitive = sensitive or "false()"
    return (
        f"search index={config.indexes['waf']} (type=traffic OR type=attack)"
        + waf_fields()
        + f" | eval hunter_sensitive=if({sensitive},1,0), "
        'hunter_attack=if(type="attack",1,0), '
        'hunter_high=if(type="attack" AND (lower(coalesce(severity,severity_level))="high" OR lower(coalesce(severity,severity_level))="critical"),1,0), '
        "hunter_error=if(hunter_status>=400,1,0)"
        " | bin _time span=5m"
        " | stats count dc(hunter_path) as paths sum(hunter_error) as errors "
        "sum(hunter_attack) as attacks sum(hunter_high) as high "
        "sum(hunter_sensitive) as sensitive values(attack_type) as attack_types "
        "values(signature_subclass) as signatures "
        'count(eval(type="traffic")) as traffic_count '
        'dc(eval(if(type="traffic",hunter_path,null()))) as traffic_paths '
        'count(eval(type="traffic" AND hunter_status>=400 AND hunter_status<500)) as client_errors '
        'count(eval(type="traffic" AND hunter_status>=500 AND hunter_status<600)) as server_errors '
        'count(eval(type="traffic" AND (hunter_status=401 OR hunter_status=403))) as auth_rejects '
        'count(eval(type="attack" AND lower(action)="alert")) as alert_only '
        "by _time hunter_src hunter_app"
        " | eval _time=tonumber(_time)"
    )


def firewall_fields():
    return (
        ' | eval hunter_src=coalesce(srcip,src,remip,"unknown"), '
        'hunter_device=coalesce(device_id,devid,"unknown"), hunter_vdom=coalesce(vd,"unknown")'
    )


def firewall_summary_query(config: SplunkConfig):
    return (
        f"search index={config.indexes['firewall']} (type=traffic OR type=utm OR type=event)"
        + firewall_fields()
        + " | bin _time span=5m | stats count "
        'count(eval(type="traffic")) as traffic_count '
        'dc(eval(if(type="traffic" AND tonumber(dstport)>0,dstport,null()))) as ports '
        'dc(eval(if(type="traffic",dstip,null()))) as destinations '
        'count(eval(type="traffic" AND lower(action)="deny")) as denied '
        'count(eval(subtype="ips" AND (lower(severity)="high" OR lower(severity)="critical"))) as ips_high '
        'count(eval(subtype="virus" AND (len(virus)>0 OR len(virusid)>0))) as malware '
        'count(eval(type="event" AND subtype="system" AND lower(action)="login" AND lower(status)="failed")) as admin_failures '
        'count(eval(type="event" AND len(cfgpath)>0 AND (lower(action)="add" OR lower(action)="edit" OR lower(action)="delete"))) as config_changes '
        "by _time hunter_src hunter_device hunter_vdom "
        '| eval _time=tonumber(_time), hunter_source="firewall", hunter_app="firewall"'
    )


def evidence_query(
    config: SplunkConfig,
    source: str,
    src: str,
    application: str | None = None,
    device: str | None = None,
    vdom: str | None = None,
):
    address = "unknown" if src == "unknown" and source == "firewall" and device else str(ip_address(src))
    if source == "waf":
        query = f"search index={config.indexes['waf']} (type=traffic OR type=attack)" + waf_fields()
        query += f" | where hunter_src={literal(address)}"
        if application:
            query += f" AND hunter_app={literal(application)}"
    elif source == "firewall":
        query = (
            f"search index={config.indexes['firewall']}"
            + firewall_fields()
            + f" | where (hunter_src={literal(address)} OR dstip={literal(address)})"
        )
        if device is not None:
            query += f" AND hunter_device={literal(device)}"
        if vdom is not None:
            query += f" AND hunter_vdom={literal(vdom)}"
    else:
        raise ValueError("Unknown evidence source")
    # Do not export _raw/packet bodies. Sorting is explicit and limited by server job/result budgets.
    query += (
        ' | eval hunter_rank=if(type="attack" OR type="utm" OR type="event",0,1) | sort 0 hunter_rank _time'
        " | table _time device_id devid vd src srcip original_src dst dstip dest dst_port dstport "
        "http_host hostname policy policyname policyid http_url url http_method method http_retcode "
        "action attack_type signature_subclass severity severity_level level type sentbyte rcvdbyte "
        "http_request_bytes http_response_bytes sessionid msg_id subtype status cfgpath attack virus virusid remip"
    )
    return query


def as_list(value):
    return value if isinstance(value, list) else [value] if value else []


def buckets(result: SearchResult):
    return [
        Bucket(
            source=row.get("hunter_source", "waf"),
            device=safe_text(row.get("hunter_device", "unknown")),
            vdom=safe_text(row.get("hunter_vdom", "unknown")),
            timestamp=utc(row["_time"]),
            src=safe_ip(row.get("hunter_src")),
            application=safe_text(row.get("hunter_app")),
            count=int(row["count"]),
            paths=int(row.get("paths", 0)),
            errors=int(row.get("errors", 0)),
            attacks=int(row.get("attacks", 0)),
            high=int(row.get("high", 0)),
            sensitive=int(row.get("sensitive", 0)),
            attack_types=[safe_text(v) for v in as_list(row.get("attack_types"))],
            signatures=[safe_text(v) for v in as_list(row.get("signatures"))],
            **{
                name: int(row.get(name, 0) or 0)
                for name in (
                    "traffic_count",
                    "traffic_paths",
                    "client_errors",
                    "server_errors",
                    "auth_rejects",
                    "alert_only",
                    "ports",
                    "destinations",
                    "denied",
                    "ips_high",
                    "malware",
                    "admin_failures",
                    "config_changes",
                )
            },
        )
        for row in result.rows
    ]


class Splunk:
    def __init__(self, config: SplunkConfig, client=None):
        self.config = config
        self.client = client or httpx.Client(
            base_url=config.url,
            headers={"Authorization": f"Bearer {secret(config.token_file)}"},
            verify=tls_context(config.ca_file),
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )
        self.history = []

    def check(self):
        response = self.client.get("/services/server/info", params={"output_mode": "json"})
        response.raise_for_status()
        return {"reachable": True, "server_info_readable": True}

    def search(self, query: str, start: datetime, end: datetime, limit=None):
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError("Search requires an ordered, timezone-aware window")
        cap = limit if limit is not None else self.config.max_results
        response = self.client.post(
            "/services/search/jobs",
            data={
                "search": query,
                "earliest_time": str(start.timestamp()),
                "latest_time": str(end.timestamp()),
                "output_mode": "json",
                "exec_mode": "normal",
                "max_time": self.config.search_timeout_seconds,
                "auto_cancel": max(60, int(self.config.poll_seconds * 10)),
                "status_buckets": 0,
            },
        )
        response.raise_for_status()
        sid = response.json()["sid"]
        path = "/services/search/jobs/" + quote(sid, safe="")
        record = {
            "sid": sid,
            "query": query,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "status": "running",
        }
        self.history.append(record)
        deadline = time.monotonic() + self.config.search_timeout_seconds
        complete = False
        try:
            while True:
                response = self.client.get(path, params={"output_mode": "json"})
                response.raise_for_status()
                state = response.json()["entry"][0]["content"]
                status = state.get("dispatchState")
                if status in ("FAILED", "BAD_INPUT", "QUIT") or str(state.get("isFailed", "0")) in (
                    "1",
                    "True",
                    "true",
                ):
                    raise RuntimeError("Splunk search failed; inspect the recorded job ID")
                if status == "DONE" or str(state.get("isDone", "0")) in ("1", "True", "true"):
                    complete = True
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("Splunk search exceeded its time budget")
                time.sleep(self.config.poll_seconds)
            total = int(state.get("resultCount", 0))
            warnings = []
            if str(state.get("isFinalized", "0")) in ("1", "True", "true"):
                warnings.append("Splunk finalized the search early; coverage may be incomplete")
            if state.get("messages"):
                warnings.append("Splunk returned search messages; inspect the job before accepting coverage")
            rows = []
            while len(rows) < min(total, cap):
                response = self.client.get(
                    path + "/results",
                    params={
                        "output_mode": "json",
                        "count": min(self.config.page_size, cap - len(rows)),
                        "offset": len(rows),
                    },
                )
                response.raise_for_status()
                payload = response.json()
                if payload.get("messages"):
                    warnings.append("Splunk result messages present; inspect the job")
                batch = payload.get("results", [])
                if not batch:
                    raise RuntimeError("Splunk returned fewer results than advertised")
                rows.extend(batch[: cap - len(rows)])
            record.update(
                status="complete", total=total, returned=len(rows), truncated=total > cap, warnings=warnings
            )
            return SearchResult(sid, rows, total, total > cap, warnings)
        except BaseException:
            record["status"] = "failed"
            if not complete:
                try:
                    self.client.post(path + "/control", data={"action": "cancel"})
                except httpx.HTTPError:
                    pass
            raise

    def link(self, sid):
        if not self.config.web_url:
            return None
        return f"{self.config.web_url}/en-US/app/search/search?" + urlencode({"sid": sid})
