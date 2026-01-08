from __future__ import annotations

from typing import Any, Dict, List, Optional


def _to_int(x: Any) -> Optional[int]:
    """Best-effort int conversion. Returns None if conversion fails."""
    try:
        if x in (None, ""):
            return None
        return int(x)
    except (ValueError, TypeError):
        return None


def _to_float(x: Any) -> float:
    """Best-effort float conversion. Returns 0.0 if conversion fails."""
    try:
        if x in (None, ""):
            return 0.0
        return float(x)
    except (ValueError, TypeError):
        return 0.0


def clamp_cvss(x: Any, lo: float = 0.0, hi: float = 10.0) -> float:
    """
    Convert CVSS to float and clamp to [0, 10].

    Note:
    Your synthetic dataset includes values like -0.3 and 10.3.
    Clamping prevents weird visualization scaling and risk inflation.
    """
    v = _to_float(x)
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def normalize(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize raw scan JSON to a stable schema used by build_graph().

    Output schema:
    {
      "scan": {...},
      "hosts": [
        {
          "ip": "...",
          "hostname": "...",
          "os": "...",
          "services": [{"port": 22, "protocol":"tcp", "service":"ssh"}],
          "vulnerabilities": [
            {"plugin_id":..., "name":..., "severity":..., "cvss":..., "port":..., ...}
          ]
        }, ...
      ]
    }
    """
    out: Dict[str, Any] = {"scan": data.get("scan", {}), "hosts": []}

    hosts = data.get("hosts", [])
    if not isinstance(hosts, list):
        raise ValueError("JSON format error: 'hosts' must be a list.")

    for h in hosts:
        # Try multiple possible fields for host identity
        ip = h.get("ip") or h.get("host") or h.get("name")
        if not ip:
            continue

        host_obj: Dict[str, Any] = {
            "ip": ip,
            "hostname": h.get("hostname") or h.get("fqdn") or h.get("host_name") or ip,
            "os": h.get("os") or h.get("operating_system") or "Unknown",
            "services": [],
            "vulnerabilities": [],
        }

        # ---- Services ----
        services = h.get("services", [])
        if isinstance(services, list):
            for s in services:
                port = _to_int(s.get("port"))
                if port is None:
                    continue
                proto = s.get("protocol") or s.get("proto") or "tcp"
                name = s.get("service") or s.get("name") or "unknown"
                host_obj["services"].append({"port": port, "protocol": proto, "service": name})

        # ---- Vulnerabilities / Findings ----
        vulns = h.get("vulnerabilities") or h.get("findings") or []
        if isinstance(vulns, list):
            for v in vulns:
                plugin_id = v.get("plugin_id") or v.get("pluginID") or v.get("id") or v.get("plugin")
                name = v.get("name") or v.get("title") or v.get("pluginName") or "Unnamed Finding"

                severity = v.get("severity") or "Low"
                cvss = clamp_cvss(v.get("cvss") or v.get("cvss3") or v.get("cvss3_base_score") or 0.0)
                port = _to_int(v.get("port"))

                host_obj["vulnerabilities"].append(
                    {
                        "plugin_id": plugin_id,
                        "name": name,
                        "severity": severity,
                        "cvss": cvss,
                        "port": port,  # can be None
                        "description": v.get("description") or v.get("desc") or "",
                        "recommendation": v.get("recommendation") or v.get("solution") or "",
                    }
                )

        # If no explicit services, derive from vuln ports (basic heuristic)
        if not host_obj["services"]:
            seen = set()
            for v in host_obj["vulnerabilities"]:
                if v["port"] is None:
                    continue
                key = ("tcp", v["port"])
                if key in seen:
                    continue
                seen.add(key)
                host_obj["services"].append({"port": v["port"], "protocol": "tcp", "service": "unknown"})

        out["hosts"].append(host_obj)

    return out
