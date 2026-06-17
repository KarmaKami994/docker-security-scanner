# 🔐 DevSecOps CI/CD Security Pipeline

Erweiterung des Docker Security Scanner Projekts um eine automatisierte
GitHub Actions Pipeline, die das eigene Docker-Image und den Code bei
jedem Push automatisch auf Sicherheitsprobleme prüft.

---

## 🎯 Ziel

Demonstration des "Shift Left Security" Prinzips, Sicherheitsprobleme
werden bereits im Build-Prozess erkannt und blockiert, bevor unsicherer
Code in Produktion gelangen kann.

---

## 🏗️ Architektur

```
Push/Pull Request zu main
        │
        ▼
┌───────────────────────┐     ┌───────────────────────┐
│ Container Image Scan   │     │ Secret Scanning         │
│ (Trivy)                │     │ (Gitleaks CLI)          │
│                         │     │                         │
│ Build Image via Compose│     │ Checkout volle Historie│
│ Scan auf CVEs           │     │ Scan Code + Git Log     │
│ Gate: CRITICAL/HIGH     │     │ Gate: jeder Fund        │
└───────────────────────┘     └───────────────────────┘
        │                               │
        ▼                               ▼
   Pipeline gruen/rot              Pipeline gruen/rot
```

Beide Jobs laufen unabhängig und parallel. Schlägt einer der beiden fehl,
wird der gesamte Workflow als fehlgeschlagen markiert.

---

## 🛠️ Implementierte Sicherheitsebenen

### 1. Container Image Vulnerability Scanning (Trivy)

Das Docker-Image wird bei jedem Push gebaut und mit Trivy auf bekannte
CVEs in allen enthaltenen System- und Python-Paketen gescannt.

**Security Gate:** Der Workflow schlägt fehl, wenn Schwachstellen mit
Schweregrad CRITICAL oder HIGH gefunden werden (`exit-code: 1`).

**Tool:** [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action)

### 2. Secret Scanning (Gitleaks)

Der komplette Code und die gesamte Git-Historie werden auf versehentlich
eingecheckte Zugangsdaten (API-Keys, Passwörter, Tokens) durchsucht.

**Security Gate:** Der Workflow schlägt fehl, sobald auch nur ein
potenzielles Secret gefunden wird.

**Tool:** [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (direkte CLI Nutzung)

---

## 🐛 Debugging-Kapitel: Von Trivy CVEs bis zur Gitleaks Action

### Problem 1: Initiale CVEs im Basis-Image

Der erste Pipeline-Lauf schlug korrekt fehl, Trivy fand 12 Schwachstellen
(2 CRITICAL, 10 HIGH) im `python:3.12-slim` Basis-Image, primär in
System-Paketen wie `perl-base`, `libsqlite3-0` und `libncursesw6`, nicht
im eigenen Code.

**Analyse:** Manche CVEs hatten den Status `fix_deferred`, das bedeutet
Debian hat bewusst entschieden, vorerst keinen Fix bereitzustellen, ein
Warten auf ein Update würde hier nicht helfen.

**Lösung:** Wechsel des Basis-Images von `python:3.12-slim` (Debian-basiert)
zu `python:3.12-alpine` (Alpine-basiert, deutlich kleinere Paketbasis).
Ergebnis, alle CRITICAL/HIGH Findings verschwanden, der Build lief
fortan grün durch.

### Problem 2: Gitleaks Action erkannte Secrets nicht

Nach Hinzufügen der `gitleaks/gitleaks-action@v2` und einem absichtlich
eingecheckten Test-Secret (offizielles AWS Beispiel-Credential) meldete
die Pipeline `no leaks found`, trotz `fetch-depth: 0` im Checkout-Schritt.

**Analyse:** Mehrere Tests mit unterschiedlichen Fake-Secrets (AWS
Beispiel-Key, generischer GitHub Token) zeigten das gleiche Verhalten,
die Action meldete durchgehend nur `1 commits scanned`, unabhängig von
der tatsächlichen Historienlänge. Recherche deutete auf moegliche
Einschraenkungen der Action-Version hin (u.a. Lizenzanforderungen fuer
bestimmte Szenarien).

**Lösung:** Wechsel von der vorgefertigten Action zur direkten Nutzung
des Gitleaks CLI-Tools via `run` Schritt. Dies gab volle Kontrolle ueber
den Scan-Befehl und loeste das Problem vollstaendig, der korrigierte Lauf
fand zuverlaessig alle drei eingecheckten Test-Secrets über beide
Test-Commits hinweg (`9 commits scanned`, `leaks found: 3`).

### Problem 3: Bereinigung der Git-Historie

Nach erfolgreicher Demonstration mussten die Test-Secrets entfernt
werden. Ein einfacher neuer Commit hätte die Secrets in der Historie
zurückgelassen, sie wären über `git log` weiterhin sichtbar gewesen.

**Lösung:** Nutzung von `git filter-repo --invert-paths` um die
Demo-Datei rückwirkend aus allen Commits zu entfernen, gefolgt von einem
`git push --force` um die bereinigte Historie auf GitHub zu
synchronisieren. Verifiziert durch erneuten Gitleaks-Scan
(`no leaks found`).

**Wichtige Erkenntnis:** Force-Pushes die die Historie umschreiben sind
nur bei rein persoenlichen Repositories ohne weitere Mitwirkende
unkritisch durchfuehrbar. In Team-Umgebungen erfordert dies Koordination
mit allen Beteiligten.

---

## 📚 Learnings

### Technisch

GitHub Actions Workflows benoetigen fuer das Erstellen/Aendern von
`.github/workflows/` Dateien einen Personal Access Token mit explizitem
`workflow` Scope, der Standard `repo` Scope reicht dafuer nicht aus.

Vorgefertigte GitHub Actions sind praktisch, aber nicht immer transparent
in ihrem internen Verhalten. Bei unerwarteten Ergebnissen lohnt sich der
Wechsel zur direkten CLI-Nutzung des zugrundeliegenden Tools fuer volle
Kontrolle und Nachvollziehbarkeit.

Der `exit-code` Parameter von Sicherheits-Scannern entscheidet ob eine
Pipeline nur Findings sichtbar macht (Reporting) oder aktiv unsichere
Builds blockiert (Security Gate). Letzteres ist der eigentliche Kern von
DevSecOps Automatisierung.

### Security

Ein Secret das einmal committed wurde, bleibt in der Git-Historie
sichtbar, auch wenn die Datei in einem spaeteren Commit geloescht wird.
Echte Bereinigung erfordert das Umschreiben der Historie und im Fall
eines echten (nicht simulierten) Leaks zusaetzlich die Rotation des
betroffenen Secrets beim jeweiligen Anbieter.

Container-Sicherheit betrifft nicht nur eigenen Code, sondern die
komplette Supply Chain inklusive Basis-Images. Ein kleineres,
fokussierteres Basis-Image (Alpine) reduziert die Angriffsflaeche
messbar.

---

## 🚀 Naechste Schritte (geplant)

- [ ] IaC Scanning fuer Dockerfile und docker-compose.yml (Hadolint/Checkov)
- [ ] Pipeline-Ergebnisse als GitHub Step Summary sichtbar machen
- [ ] Screenshots der gruenen/roten Pipeline-Laeufe ergaenzen
