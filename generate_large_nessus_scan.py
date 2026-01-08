import json
import random
from datetime import datetime

random.seed(42)

SEVERITIES = [
    ("Informational", 0.0),
    ("Low", 3.1),
    ("Medium", 5.6),
    ("High", 8.2),
    ("Critical", 9.8),
]

OS_TYPES = [
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows 10",
    "Windows 11",
    "Ubuntu 20.04",
    "Ubuntu 22.04",
    "RHEL 8",
    "RHEL 9",
    "Network Device",
]

SERVICES = [
    (22, "ssh"),
    (80, "http"),
    (443, "https"),
    (445, "smb"),
    (3389, "rdp"),
    (3306, "mysql"),
    (5432, "postgres"),
    (6379, "redis"),
]

VULN_TITLES = [
    "Outdated Software Version",
    "Weak TLS Configuration",
    "Unpatched Remote Code Execution",
    "Default Credentials Enabled",
    "SMB Signing Not Required",
    "RDP Network Level Authentication Disabled",
    "Weak SSH Key Exchange Algorithms",
    "Deprecated Protocol Enabled",
]


def generate_host(ip_last: int) -> dict:
    """
    Generate a synthetic host with random services and random findings.

    Note:
    This intentionally generates slightly invalid CVSS sometimes (e.g., -0.3 or 10.3)
    to test the robustness of normalize() + clamping logic.
    """
    ip = f"10.0.0.{ip_last}"
    os_name = random.choice(OS_TYPES)

    services = random.sample(SERVICES, k=random.randint(2, 5))
    service_objs = [{"port": p, "protocol": "tcp", "service": name} for p, name in services]

    vulns = []
    for _ in range(random.randint(2, 8)):
        sev, cvss = random.choice(SEVERITIES)
        port, svc = random.choice(services)
        vulns.append(
            {
                "plugin_id": random.randint(100000, 999999),
                "name": random.choice(VULN_TITLES),
                "severity": sev,
                "cvss": round(cvss + random.uniform(-0.5, 0.5), 1),
                "port": port,
                "description": f"{svc.upper()} service is affected by a known security issue.",
                "recommendation": "Apply vendor patches and follow hardening best practices.",
            }
        )

    return {
        "ip": ip,
        "hostname": f"host-{ip_last:03d}.corp.local",
        "os": os_name,
        "services": service_objs,
        "vulnerabilities": vulns,
    }


def generate_scan(host_count: int = 100) -> dict:
    """
    Generate a Nessus-like scan JSON payload with N hosts.
    """
    return {
        "scan": {
            "id": "NS-LARGE-2025-001",
            "scanner": "Synthetic Nessus",
            "date": datetime.utcnow().isoformat() + "Z",
            "scope": "10.0.0.0/24",
            "hosts_scanned": host_count,
        },
        "hosts": [generate_host(i) for i in range(1, host_count + 1)],
    }


if __name__ == "__main__":
    scan = generate_scan(100)

    # Keep your existing filename for compatibility (typo in name is OK for now)
    out_path = "nesus_large.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=2)

    print(f"[+] Generated {out_path} with {len(scan['hosts'])} hosts")
