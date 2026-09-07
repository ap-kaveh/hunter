"""Versioned rule catalog; mappings are hypotheses, never ATT&CK certification."""

RULESET_VERSION = "2026.09.07.1"
FORTIOS = "https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/3b0ab1d1-8467-11f0-9bfd-6af4c3636dc7/FortiOS_7.2.12_Log_Reference.pdf"
FORTIWEB = "https://docs.fortinet.com/document/fortiweb/7.6.0/administration-guide/303842/logging"
LOGGING = "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
DISCOVERY = "https://attack.mitre.org/techniques/T1046/"


def rule(source, title, fields, thresholds, alternatives, references, attack=None):
    return dict(
        source=source,
        title=title,
        fields=fields,
        thresholds=thresholds,
        alternatives=alternatives,
        references=references,
        attack=attack,
    )


RULES = {
    "path_enumeration": rule(
        "waf",
        "Many requested paths",
        "src, host/policy, URL, _time",
        ["scan_min_paths", "scan_min_requests"],
        "Crawlers, authorized scanners, large applications",
        [FORTIWEB],
    ),
    "multiple_attack_types": rule(
        "waf",
        "Multiple vendor attack types",
        "type, attack_type",
        ["multi_attack_min_events"],
        "One request can trigger several signatures; authorized testing",
        [FORTIWEB],
    ),
    "high_severity_detection": rule(
        "waf",
        "High-severity WAF detection",
        "type, severity",
        [],
        "Signature false positives or blocked genuine attempts",
        [FORTIWEB],
    ),
    "sensitive_endpoint_volume": rule(
        "waf",
        "Sensitive endpoint volume",
        "URL",
        ["sensitive_min_requests", "sensitive_paths"],
        "Legitimate payment peaks or health checks",
        [LOGGING],
    ),
    "historical_rate_deviation": rule(
        "waf",
        "Rate above historical observed peak",
        "count, complete baseline",
        ["rate_multiplier", "rate_min_requests"],
        "Releases, campaigns, incomplete ingestion history",
        [LOGGING],
    ),
    "shared_signature_cluster": rule(
        "waf",
        "Shared signature across sources",
        "signature_subclass",
        ["campaign_min_sources"],
        "Common signature noise does not prove coordination",
        [FORTIWEB],
    ),
    "waf_error_probe": rule(
        "waf",
        "Many paths with mostly HTTP client errors",
        "traffic HTTP status, URL",
        ["waf_error_min_events", "waf_error_min_ratio", "scan_min_paths"],
        "Broken clients, dead links, crawlers and authorized scanners",
        [FORTIWEB, LOGGING],
    ),
    "waf_server_error_burst": rule(
        "waf",
        "Repeated HTTP server errors",
        "traffic HTTP status",
        ["waf_server_error_min_events"],
        "Backend outage or deployment failure; not necessarily hostile",
        [LOGGING],
    ),
    "waf_auth_rejection_burst": rule(
        "waf",
        "Repeated HTTP 401/403 responses",
        "traffic HTTP status",
        ["waf_auth_reject_min_events"],
        "Expired client credentials, forbidden resources or WAF blocks. Application auth logs needed to establish brute force",
        [LOGGING],
    ),
    "waf_alert_only_detection": rule(
        "waf",
        "Repeated alert-only WAF detections",
        "type=attack, action",
        ["waf_alert_min_events"],
        "Monitor-only policies or signature noise; other controls may still block",
        [FORTIWEB],
    ),
    "fw_many_ports": rule(
        "firewall",
        "Many destination ports",
        "traffic srcip, dstport, devid, vd",
        ["fw_scan_min_ports", "fw_scan_min_events"],
        "Authorized scanners, NAT aggregation or peer-to-peer clients",
        [FORTIOS, DISCOVERY],
        "T1046 (hypothesis)",
    ),
    "fw_many_destinations": rule(
        "firewall",
        "Many destination addresses",
        "traffic srcip, dstip, devid, vd",
        ["fw_scan_min_destinations", "fw_scan_min_events"],
        "Proxies, service discovery, NAT or approved scanners",
        [FORTIOS, DISCOVERY],
        "T1046 (hypothesis)",
    ),
    "fw_deny_burst": rule(
        "firewall",
        "Repeated denied traffic",
        "type=traffic, action=deny",
        ["fw_deny_min_events"],
        "Internet background noise or routing/policy mistakes",
        [FORTIOS],
    ),
    "fw_ips_high": rule(
        "firewall",
        "High-severity IPS detections",
        "subtype=ips, severity",
        [],
        "Signature error, authorized test or blocked genuine attack",
        [FORTIOS],
    ),
    "fw_malware_detection": rule(
        "firewall",
        "Antivirus detection",
        "subtype=virus, virus/virusid",
        [],
        "Security test files or a blocked malicious transfer; execution is unproven",
        [FORTIOS],
    ),
    "fw_admin_failures": rule(
        "firewall",
        "Repeated failed administrator logins",
        "type=event, subtype=system, action=login, status=failed, srcip",
        ["fw_admin_fail_min_events"],
        "Stale automation credentials or administrator error",
        [LOGGING],
    ),
    "fw_config_change": rule(
        "firewall",
        "Configuration object changed",
        "type=event, cfgpath, action=Add/Edit/Delete, devid; srcip optional",
        [],
        "Planned maintenance or approved deployment; requires change-record review",
        [FORTIOS, LOGGING],
    ),
}


def catalog(config):
    return [
        dict(
            id=key,
            **entry,
            enabled=key not in config.disabled_rules
            and (entry["source"] != "firewall" or config.firewall_enabled),
            settings={name: getattr(config, name) for name in entry["thresholds"]},
        )
        for key, entry in RULES.items()
    ]
