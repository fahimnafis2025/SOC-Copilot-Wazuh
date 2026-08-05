from apps.agentic.runtime.base import BaseModule
from apps.agentic.services.alerts import create_alert_with_context

def _sev(level):
    try:
        lvl = int(level)
    except Exception:
        return "Low"
    if lvl >= 12:
        return "Critical"
    if lvl >= 8:
        return "High"
    if lvl >= 5:
        return "Medium"
    return "Low"

def _artifact(value, a_type, a_name, a_role):
    return {"name": a_name, "type": a_type, "role": a_role, "value": str(value)}

def _build_description(name, host, user, rule, data, alert):
    lines = ["**Wazuh Detection:** %s" % name]
    rid = rule.get("id")
    rlvl = rule.get("level")
    if rid or rlvl:
        lines.append("- Rule: %s (level %s)" % (rid or "n/a", rlvl or "n/a"))
    if host:
        lines.append("- Host: %s" % host)
    if user:
        lines.append("- User/Account: %s" % user)
    field_map = [
        ("srcip", "Source IP"), ("dstip", "Destination IP"),
        ("srcport", "Source Port"), ("dstport", "Destination Port"),
        ("srcuser", "Source User"), ("dstuser", "Target User"),
        ("win.eventdata.subjectUserName", "Subject User"),
        ("win.eventdata.targetUserName", "Target User"),
        ("win.system.eventID", "Windows Event ID"), ("command", "Command"),
    ]
    for key, label in field_map:
        val = data.get(key)
        if val:
            lines.append("- %s: %s" % (label, val))
    mitre = rule.get("mitre") or {}
    if mitre.get("id"):
        lines.append("- MITRE ATT&CK: %s" % ", ".join(str(x) for x in mitre.get("id")))
    if mitre.get("tactic"):
        lines.append("- Tactic(s): %s" % ", ".join(str(x) for x in mitre.get("tactic")))
    if mitre.get("technique"):
        lines.append("- Technique(s): %s" % ", ".join(str(x) for x in mitre.get("technique")))
    if alert.get("full_log"):
        lines.append("")
        lines.append("**Raw log:**")
        lines.append(str(alert.get("full_log"))[:1000])
    return "\n".join(lines)

class Module(BaseModule):
    NAME = "Wazuh Alerts"
    DESC = "Ingests Wazuh alerts pushed via the custom-asp Kibana webhook and creates SIRP Cases."
    STREAM_NAME = "Wazuh-Alerts"
    THREAD_NUM = 1

    def run(self, message):
        src = message or {}
        raw = src.get("raw_event", src) or {}
        rule = raw.get("rule", {}) or {}
        data = raw.get("data", {}) or {}
        name = src.get("alert_name") or rule.get("description") or "Wazuh Alert"
        severity = src.get("severity") or _sev(rule.get("level"))
        host = src.get("host") or "unknown"
        user = src.get("user") or data.get("srcuser") or data.get("dstuser") or ""
        ts = src.get("timestamp")
        rule_id = str(src.get("rule_id") or rule.get("id") or "wazuh")
        desc = _build_description(name, host, user, rule, data, raw)
        correlation_uid = "wazuh-%s-%s" % (rule_id, host)
        tags = ["wazuh"]
        mitre = src.get("mitre") or rule.get("mitre") or {}
        for tid in (mitre.get("id") or []):
            tags.append(str(tid))
        artifacts = []
        seen = set()
        def _add(value, a_type, a_name, a_role):
            key = (str(value), a_type)
            if value and key not in seen:
                seen.add(key)
                artifacts.append(_artifact(value, a_type, a_name, a_role))
        ind = src.get("indicators", {}) or {}
        for ip in ind.get("ip_addresses", []) or []:
            _add(ip, "IP Address", "Source IP", "Related")
        for dom in ind.get("domains", []) or []:
            _add(dom, "Other", "Domain", "Related")
        for h in ind.get("file_hashes", []) or []:
            _add(h, "Hash", "File Hash", "Related")
        _add(data.get("srcip"), "IP Address", "Source IP", "Actor")
        if host and host != "unknown":
            _add(host, "Hostname", "Hostname", "Affected")
        if user:
            _add(user, "User Name", "User Name", "Actor")
        case_defaults = {
            "title": "[%s] %s on %s" % (severity, name, host),
            "severity": severity,
            "description": desc,
            "tags": tags,
            "correlation_uid": correlation_uid,
        }
        alert_fields = {
            "title": name,
            "severity": severity,
            "desc": desc,
            "rule_id": "Wazuh-Rule-%s" % rule_id,
            "rule_name": name,
            "correlation_uid": correlation_uid,
            "raw_data": raw,
        }
        if ts:
            alert_fields["first_seen_time"] = ts
            alert_fields["last_seen_time"] = ts
        create_alert_with_context(
            case_defaults=case_defaults,
            alert_fields=alert_fields,
            artifacts=artifacts,
            enrichments=[],
            schedule_analysis=True,
            analysis_trigger="alert_created",
        )
