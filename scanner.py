#!/usr/bin/env python3
"""
Docker Security Scanner – CIS Docker Benchmark
Autor: KarmaKami994
Beschreibung: Scannt laufende Docker Container auf Sicherheitsprobleme
              basierend auf dem CIS Docker Benchmark Standard.
"""

import docker
import json
import re
import os
from datetime import datetime
from jinja2 import Template

# ============================================================
# KONFIGURATION
# ============================================================

# Schlüsselwörter die auf Passwörter in Env-Variablen hinweisen
SECRET_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key",
    "apikey", "auth", "credential", "private_key", "pwd"
]

# Gefährliche Ports die nicht nach 0.0.0.0 exponiert sein sollten
DANGEROUS_PORTS = [22, 23, 3306, 5432, 6379, 27017, 9200, 5601]

# Severity Level Farben für HTML Report
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "PASS":     "#16a34a"
}

# ============================================================
# CIS BENCHMARK CHECKS
# ============================================================

def check_root_user(container, attrs):
    """
    CIS 4.1 – Ensure a user for the container has been created.
    Container sollten nicht als root (UID 0) laufen.
    Severity: HIGH
    """
    try:
        exec_result = container.exec_run("id -u")
        uid = exec_result.output.decode().strip()
        if uid == "0":
            return {
                "check_id": "CIS-4.1",
                "title": "Container läuft als root (UID 0)",
                "severity": "HIGH",
                "status": "FAIL",
                "detail": "Prozess läuft als root. Erstelle einen dedizierten User im Dockerfile.",
                "remediation": "Füge 'USER nonroot' im Dockerfile hinzu."
            }
    except Exception:
        pass
    return {
        "check_id": "CIS-4.1",
        "title": "Container läuft als root (UID 0)",
        "severity": "HIGH",
        "status": "PASS",
        "detail": "Container läuft nicht als root.",
        "remediation": ""
    }


def check_privileged_mode(container, attrs):
    """
    CIS 5.4 – Ensure privileged containers are not used.
    Privileged Container haben vollen Host-Zugriff.
    Severity: CRITICAL
    """
    privileged = attrs.get("HostConfig", {}).get("Privileged", False)
    if privileged:
        return {
            "check_id": "CIS-5.4",
            "title": "Container läuft im Privileged Mode",
            "severity": "CRITICAL",
            "status": "FAIL",
            "detail": "Privileged Mode gibt dem Container vollen Zugriff auf den Host.",
            "remediation": "Entferne '--privileged' aus dem docker run Befehl oder Compose File."
        }
    return {
        "check_id": "CIS-5.4",
        "title": "Container läuft im Privileged Mode",
        "severity": "CRITICAL",
        "status": "PASS",
        "detail": "Privileged Mode ist deaktiviert.",
        "remediation": ""
    }


def check_host_network(container, attrs):
    """
    CIS 5.9 – Ensure the host's network namespace is not shared.
    Host-Netzwerk umgeht Docker Netzwerk-Isolation.
    Severity: HIGH
    """
    network_mode = attrs.get("HostConfig", {}).get("NetworkMode", "")
    if network_mode == "host":
        return {
            "check_id": "CIS-5.9",
            "title": "Container teilt Host-Netzwerk",
            "severity": "HIGH",
            "status": "FAIL",
            "detail": "NetworkMode=host umgeht die Docker Netzwerk-Isolation.",
            "remediation": "Verwende ein dediziertes Docker-Netzwerk statt --network=host."
        }
    return {
        "check_id": "CIS-5.9",
        "title": "Container teilt Host-Netzwerk",
        "severity": "HIGH",
        "status": "PASS",
        "detail": "Container verwendet kein Host-Netzwerk.",
        "remediation": ""
    }


def check_memory_limit(container, attrs):
    """
    CIS 5.10 – Ensure memory usage for container is limited.
    Unbegrenzte Memory kann zu DoS führen.
    Severity: MEDIUM
    """
    memory = attrs.get("HostConfig", {}).get("Memory", 0)
    if memory == 0:
        return {
            "check_id": "CIS-5.10",
            "title": "Kein Memory-Limit gesetzt",
            "severity": "MEDIUM",
            "status": "FAIL",
            "detail": "Kein Speicherlimit definiert. Container kann den Host zum Absturz bringen.",
            "remediation": "Füge 'mem_limit: 512m' in docker-compose.yml hinzu."
        }
    return {
        "check_id": "CIS-5.10",
        "title": "Kein Memory-Limit gesetzt",
        "severity": "MEDIUM",
        "status": "PASS",
        "detail": f"Memory-Limit gesetzt: {memory // (1024*1024)} MB",
        "remediation": ""
    }


def check_dangerous_ports(container, attrs):
    """
    CIS 5.15 – Ensure only needed ports are open on the container.
    Gefährliche Ports sollten nicht nach 0.0.0.0 exponiert sein.
    Severity: HIGH
    """
    ports = attrs.get("HostConfig", {}).get("PortBindings", {}) or {}
    exposed = []
    for port, bindings in ports.items():
        if bindings:
            for binding in bindings:
                host_ip = binding.get("HostIp", "")
                host_port = int(binding.get("HostPort", 0))
                if host_ip == "0.0.0.0" and host_port in DANGEROUS_PORTS:
                    exposed.append(f"{host_port}")

    if exposed:
        return {
            "check_id": "CIS-5.15",
            "title": "Gefährliche Ports nach 0.0.0.0 exponiert",
            "severity": "HIGH",
            "status": "FAIL",
            "detail": f"Gefährliche Ports offen: {', '.join(exposed)}",
            "remediation": "Binde Ports an 127.0.0.1 statt 0.0.0.0 oder nutze einen Reverse Proxy."
        }
    return {
        "check_id": "CIS-5.15",
        "title": "Gefährliche Ports nach 0.0.0.0 exponiert",
        "severity": "HIGH",
        "status": "PASS",
        "detail": "Keine gefährlichen Ports nach aussen exponiert.",
        "remediation": ""
    }


def check_secrets_in_env(container, attrs):
    """
    CIS 5.25 – Ensure secrets are not stored in environment variables.
    Passwörter in Env-Variablen sind ein häufiger Sicherheitsfehler.
    Severity: CRITICAL
    """
    env_vars = attrs.get("Config", {}).get("Env", []) or []
    found_secrets = []

    for env in env_vars:
        key = env.split("=")[0].lower()
        value = env.split("=", 1)[1] if "=" in env else ""
        for keyword in SECRET_KEYWORDS:
            if keyword in key and value and value not in ("", '""', "''"):
                found_secrets.append(env.split("=")[0])
                break

    if found_secrets:
        return {
            "check_id": "CIS-5.25",
            "title": "Secrets in Umgebungsvariablen gefunden",
            "severity": "CRITICAL",
            "status": "FAIL",
            "detail": f"Verdächtige Variablen: {', '.join(found_secrets)}",
            "remediation": "Nutze Docker Secrets oder eine .env Datei die nicht in Git eingecheckt wird."
        }
    return {
        "check_id": "CIS-5.25",
        "title": "Secrets in Umgebungsvariablen gefunden",
        "severity": "CRITICAL",
        "status": "PASS",
        "detail": "Keine Secrets in Umgebungsvariablen gefunden.",
        "remediation": ""
    }


# ============================================================
# SCANNER HAUPTLOGIK
# ============================================================

def scan_container(container):
    """Führt alle CIS Checks für einen Container durch."""
    attrs = container.attrs
    checks = [
        check_root_user(container, attrs),
        check_privileged_mode(container, attrs),
        check_host_network(container, attrs),
        check_memory_limit(container, attrs),
        check_dangerous_ports(container, attrs),
        check_secrets_in_env(container, attrs),
    ]

    # Severity Score berechnen
    severity_score = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for check in checks:
        if check["status"] == "FAIL":
            severity_score[check["severity"]] += 1

    return {
        "name": container.name,
        "image": container.image.tags[0] if container.image.tags else "unknown",
        "status": container.status,
        "checks": checks,
        "severity_score": severity_score
    }


def scan_all_containers():
    """Scannt alle laufenden Container."""
    client = docker.from_env()
    containers = client.containers.list()

    print(f"\n🔍 Docker Security Scanner – CIS Benchmark")
    print(f"{'='*50}")
    print(f"Gefundene Container: {len(containers)}")
    print(f"Scan gestartet: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = []
    for container in containers:
        print(f"  Scanne: {container.name}...")
        result = scan_container(container)
        results.append(result)

        # Kurze Zusammenfassung pro Container
        score = result["severity_score"]
        print(f"  → CRITICAL: {score['CRITICAL']} | "
              f"HIGH: {score['HIGH']} | "
              f"MEDIUM: {score['MEDIUM']}")

    return results


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Docker Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; padding: 32px; }
  .header { text-align: center; margin-bottom: 40px; }
  .header h1 { font-size: 28px; font-weight: 700; color: #f8fafc; margin-bottom: 8px; }
  .header p { color: #94a3b8; font-size: 14px; }
  .summary { display: flex; gap: 16px; justify-content: center; margin-bottom: 40px; flex-wrap: wrap; }
  .summary-card { background: #1e293b; border-radius: 12px; padding: 20px 32px;
                  text-align: center; border: 1px solid #334155; min-width: 140px; }
  .summary-card .number { font-size: 36px; font-weight: 700; }
  .summary-card .label { font-size: 12px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .critical .number { color: #dc2626; }
  .high .number { color: #ea580c; }
  .medium .number { color: #d97706; }
  .pass .number { color: #16a34a; }
  .container-card { background: #1e293b; border-radius: 12px; margin-bottom: 24px;
                    border: 1px solid #334155; overflow: hidden; }
  .container-header { padding: 20px 24px; background: #263148; border-bottom: 1px solid #334155;
                       display: flex; align-items: center; gap: 12px; }
  .container-name { font-size: 18px; font-weight: 600; color: #f8fafc; }
  .container-image { font-size: 12px; color: #64748b; margin-top: 2px; }
  .badge { padding: 3px 10px; border-radius: 99px; font-size: 11px; font-weight: 600;
           text-transform: uppercase; letter-spacing: 0.05em; }
  .badge-running { background: #14532d; color: #86efac; }
  table { width: 100%; border-collapse: collapse; }
  th { padding: 12px 24px; text-align: left; font-size: 11px; text-transform: uppercase;
       letter-spacing: 0.08em; color: #64748b; border-bottom: 1px solid #334155; }
  td { padding: 14px 24px; border-bottom: 1px solid #1e293b; font-size: 14px; }
  tr:last-child td { border-bottom: none; }
  tr:hover { background: #263148; }
  .severity { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;
              letter-spacing: 0.05em; }
  .sev-CRITICAL { background: #450a0a; color: #fca5a5; }
  .sev-HIGH     { background: #431407; color: #fdba74; }
  .sev-MEDIUM   { background: #451a03; color: #fcd34d; }
  .sev-LOW      { background: #1a2e05; color: #86efac; }
  .sev-PASS     { background: #052e16; color: #86efac; }
  .status-FAIL { color: #f87171; font-weight: 600; }
  .status-PASS { color: #4ade80; font-weight: 600; }
  .detail { color: #94a3b8; font-size: 13px; }
  .remediation { color: #60a5fa; font-size: 12px; margin-top: 4px; }
  .footer { text-align: center; margin-top: 40px; color: #475569; font-size: 13px; }
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Docker Security Report</h1>
  <p>CIS Docker Benchmark · Generiert am {{ timestamp }} · Host: {{ hostname }}</p>
</div>

<div class="summary">
  <div class="summary-card critical">
    <div class="number">{{ total_critical }}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card high">
    <div class="number">{{ total_high }}</div>
    <div class="label">High</div>
  </div>
  <div class="summary-card medium">
    <div class="number">{{ total_medium }}</div>
    <div class="label">Medium</div>
  </div>
  <div class="summary-card pass">
    <div class="number">{{ total_pass }}</div>
    <div class="label">Passed</div>
  </div>
</div>

{% for container in results %}
<div class="container-card">
  <div class="container-header">
    <div>
      <div class="container-name">{{ container.name }}</div>
      <div class="container-image">{{ container.image }}</div>
    </div>
    <span class="badge badge-running">{{ container.status }}</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>Check ID</th>
        <th>Beschreibung</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Detail & Remediation</th>
      </tr>
    </thead>
    <tbody>
      {% for check in container.checks %}
      <tr>
        <td><code>{{ check.check_id }}</code></td>
        <td>{{ check.title }}</td>
        <td><span class="severity sev-{{ check.severity }}">{{ check.severity }}</span></td>
        <td><span class="status-{{ check.status }}">{{ check.status }}</span></td>
        <td>
          <div class="detail">{{ check.detail }}</div>
          {% if check.remediation %}
          <div class="remediation">💡 {{ check.remediation }}</div>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endfor %}

<div class="footer">
  Docker Security Scanner · CIS Docker Benchmark · github.com/KarmaKami994/docker-security-scanner
</div>
</body>
</html>
"""


def generate_html_report(results, output_path):
    """Generiert einen HTML Security Report."""
    total_critical = sum(r["severity_score"]["CRITICAL"] for r in results)
    total_high = sum(r["severity_score"]["HIGH"] for r in results)
    total_medium = sum(r["severity_score"]["MEDIUM"] for r in results)
    total_pass = sum(
        1 for r in results
        for c in r["checks"]
        if c["status"] == "PASS"
    )

    template = Template(HTML_TEMPLATE)
    html = template.render(
        results=results,
        timestamp=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        hostname=os.uname().nodename,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_pass=total_pass
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ HTML Report gespeichert: {output_path}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    results = scan_all_containers()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"/opt/docker-scanner/reports/report_{timestamp}.html"
    generate_html_report(results, report_path)
    print(f"\n📊 Zusammenfassung:")
    print(f"   Container gescannt: {len(results)}")
    for r in results:
        s = r["severity_score"]
        print(f"   {r['name']}: CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} MEDIUM={s['MEDIUM']}")
