# 🔐 Docker Security Scanner

Ein automatisierter Sicherheits-Scanner für Docker Container basierend auf dem
**CIS Docker Benchmark** Standard. Generiert professionelle HTML Security Reports
mit Severity Levels und Remediation Empfehlungen.

---

## 🎯 Projektziel

Automatische Erkennung von Sicherheitsproblemen in laufenden Docker Containern –
täglich via Cronjob, ohne manuellen Aufwand.

---

## 🛠️ CIS Benchmark Checks

| Check ID | Beschreibung | Severity |
|----------|-------------|----------|
| CIS-4.1 | Container läuft als root (UID 0) | HIGH |
| CIS-5.4 | Privileged Mode aktiv | CRITICAL |
| CIS-5.9 | Host-Netzwerk wird geteilt | HIGH |
| CIS-5.10 | Kein Memory-Limit gesetzt | MEDIUM |
| CIS-5.15 | Gefährliche Ports nach 0.0.0.0 exponiert | HIGH |
| CIS-5.25 | Secrets in Umgebungsvariablen | CRITICAL |

---

## 📊 Beispiel Report

Einen generierten Beispiel-Report findest du unter [`examples/report_example.html`](examples/report_example.html).

---

## 🚀 Installation & Verwendung

### Voraussetzungen
- Python 3.10+
- Docker läuft auf dem Host
- Zugriff auf `/var/run/docker.sock`

### Setup

```bash
git clone https://github.com/KarmaKami994/docker-security-scanner.git
cd docker-security-scanner
pip3 install -r requirements.txt --break-system-packages
```

### Scanner ausführen

```bash
python3 scanner.py
```

Der Report wird automatisch unter `reports/report_YYYYMMDD_HHMMSS.html` gespeichert.

### Automatisierung via Cronjob

```bash
crontab -e
```

Folgende Zeile hinzufügen für täglichen Scan um 06:00 Uhr:

```
0 6 * * * python3 /pfad/zu/scanner.py >> /pfad/zu/scanner.log 2>&1
```

---

## 🔒 Security Entscheidungen

### Warum CIS Docker Benchmark?
Der CIS Benchmark ist ein Industriestandard der von Security-Teams weltweit
verwendet wird. Eigene Checks wären willkürlich – CIS Checks sind peer-reviewed
und anerkannt.

### Warum HTML statt Markdown?
Ein HTML Report ist direkt im Browser lesbar, farbcodiert und professionell
präsentierbar. Markdown-Tabellen sind für Security Reports unpraktisch.

### Warum Reports nicht in Git?
Reports können sensible Informationen enthalten (Container-Namen, Env-Variablen).
Sie werden lokal gespeichert und nie in Git eingecheckt.

---

## 📚 Learnings

### Technisch
- **Docker SDK für Python** – programmatischer Zugriff auf die Docker Engine
  via `/var/run/docker.sock`
- **Jinja2 Templates** – saubere Trennung von Logik und Präsentation
- **CIS Benchmark** – Industriestandard für Container-Sicherheit
- **Cronjob Automatisierung** – Infrastructure als wiederkehrender Prozess

### Security
- **Privileged Mode** ist einer der gefährlichsten Docker-Konfigurationsfehler –
  er gibt dem Container vollen Zugriff auf den Host-Kernel
- **Secrets in Env-Variablen** sind ein häufiger Fehler in Docker Compose Files –
  erkennbar durch Keywords wie `PASSWORD`, `SECRET`, `TOKEN`
- **Memory Limits** verhindern DoS-Angriffe durch unkontrollierten
  Ressourcenverbrauch

---

## 📋 Roadmap / TODOs

- [ ] SSH-Key Authentifizierung statt HTTPS Token für Git
- [ ] Trivy Integration für CVE Scanning der Images
- [ ] Slack/Email Benachrichtigung bei CRITICAL Findings
- [ ] JSON Export für SIEM Integration (z.B. ELK Stack aus P1)
- [ ] Mehr CIS Benchmark Checks implementieren
