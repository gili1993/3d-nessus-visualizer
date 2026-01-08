from __future__ import annotations

import networkx as nx
from sev_to_int import sev_to_int
from normalize import clamp_cvss


def calc_finding_risk(severity_int: int, cvss: float) -> float:
    """
    MVP risk formula.

    Idea:
    - CVSS captures exploit/impact (0..10)
    - severity_int captures vendor/tool classification (0..4)
    - We weight severity a bit more so Critical pops visually.
    """
    return round(cvss + (severity_int * 2.5), 2)


def build_graph(scan: dict, host_top_n_findings: int = 10) -> nx.Graph:
    """
    Build a NetworkX graph from normalized scan JSON.

    Graph hierarchy:
      Subnet -> Host -> Service
      Host   -> Finding

    Each node stores:
      kind: subnet/host/service/finding
      label: HTML string used for Plotly hover
      severity: normalized int 0..4 (host = max severity among findings)
      risk_score: finding risk (computed) + host risk (aggregated)
    """
    G = nx.Graph()

    # ---------- Subnet node ----------
    scope = scan.get("scan", {}).get("scope")
    if isinstance(scope, list) and scope:
        scope_str = ", ".join(scope)
    elif isinstance(scope, str) and scope:
        scope_str = scope
    else:
        scope_str = "scope:unknown"

    subnet_node = f"subnet:{scope_str}"
    G.add_node(subnet_node, kind="subnet", label=scope_str)

    # ---------- Hosts ----------
    for h in scan.get("hosts", []):
        ip = h.get("ip", "unknown-ip")
        hostname = h.get("hostname", ip)
        os_name = h.get("os", "Unknown")

        host_node = f"host:{ip}"
        G.add_node(
            host_node,
            kind="host",
            label=f"{ip}<br>{hostname}<br>{os_name}",
            severity=0,
            risk_score=0.0,
        )
        G.add_edge(subnet_node, host_node)

        # ---------- Services ----------
        for s in h.get("services", []):
            protocol = s.get("protocol", "tcp")
            port = s.get("port", 0)
            service_name = s.get("service", "unknown-service")

            svc_node = f"svc:{ip}:{protocol}:{port}"
            G.add_node(
                svc_node,
                kind="service",
                label=f"{ip}<br>{service_name} {protocol}/{port}",
            )
            G.add_edge(host_node, svc_node)

        # ---------- Findings ----------
        host_finding_risks: list[float] = []
        host_max_sev = 0

        for v in h.get("vulnerabilities", []):
            severity_label = v.get("severity", "Low")
            sev_i = sev_to_int(severity_label)

            cvss = clamp_cvss(v.get("cvss", 0.0))
            finding_risk = calc_finding_risk(sev_i, cvss)

            plugin_id = v.get("plugin_id", "unknown")
            port = v.get("port", "n/a")
            fin_node = f"fin:{ip}:{plugin_id}:{port}"

            G.add_node(
                fin_node,
                kind="finding",
                severity=sev_i,
                severity_label=severity_label,
                cvss=cvss,
                risk_score=finding_risk,
                plugin_id=plugin_id,
                port=port,
                label=(
                    f"{ip}<br>"
                    f"<b>{v.get('name')}</b><br>"
                    f"Severity: {severity_label} (norm {sev_i})<br>"
                    f"CVSS: {cvss}<br>"
                    f"<b>Risk:</b> {finding_risk}<br>"
                    f"Port: {port}"
                ),
            )
            G.add_edge(host_node, fin_node)

            host_finding_risks.append(finding_risk)
            host_max_sev = max(host_max_sev, sev_i)

        # ---------- Host aggregation ----------
        host_finding_risks.sort(reverse=True)
        top = host_finding_risks[:host_top_n_findings]
        host_risk = round(sum(top), 2)

        G.nodes[host_node]["risk_score"] = host_risk
        G.nodes[host_node]["severity"] = host_max_sev
        G.nodes[host_node]["label"] = (
            f"{ip}<br>{hostname}<br>{os_name}<br>"
            f"<b>Host Risk (top {host_top_n_findings}):</b> {host_risk}<br>"
            f"<b>Max Severity (norm):</b> {host_max_sev}"
        )

    return G
