# Changelog

All notable changes to FusionOps are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.3.0] — 2026-05-29

### Added
- **Remediation agent** (`agents/remediation_agent.py`) — generates ordered
  action plan with specific commands, effort estimates, and audit trail entry
- **Product landing page** served at root URL `/`
- **`POST /triage`** standalone endpoint — run triage on cached detection
- **`FullAnalysisResult`** now includes `remediation` field alongside
  `detection` and `triage`
- **AWS production deployment** — permanent URL at `http://fusionops.tinlance.com`
- **CONTRIBUTING.md**, **SECURITY.md**, **CHANGELOG.md** — repo hygiene

### Changed
- `fusionops_api.py` — all detection endpoints now return three-part result
- Dashboard updated to display remediation actions and audit trail

### Fixed
- Dashboard 307 redirect resolved — direct HTML response route added
- `.env` loading now correctly sets `FUSIONOPS_ENV=production`

---

## [0.2.0] — 2026-05-28

### Added
- **Triage agent** (`agents/triage_agent.py`) — classifies every detection by
  priority (`CRITICAL/HIGH/MEDIUM/LOW/INFO`), category, and recommended action
- **`FullAnalysisResult`** schema — combines detection + triage in one response
- **Live SOC dashboard** (`dashboard/index.html`) — polls `/events` every 5s,
  severity-coded feed, event detail panel, audit trail
- **PCAP upload endpoint** (`POST /detect/pcap`) fully activated via
  `parse_pcap()` function in `pcap_to_threatfade.py`
- **`GET /events`** endpoint — rolling in-memory event log for dashboard
- **`config/settings.py`** — Pydantic settings with `.env` support

### Changed
- FusionOps now runs on port 8080; ThreatFade on port 8000
- API calls ThreatFade via HTTP (separate service) — no direct imports

---

## [0.1.0] — 2026-05-27

### Added
- Initial FusionOps repository under Tinlance GitHub organization
- **FastAPI wrapper** (`api/fusionops_api.py`) around ThreatFade C2 engine
- **`POST /detect/json`** — analyse entropy time-series signals
- **`POST /detect/scenario`** — run named simulation scenarios
- **`GET /health`** — liveness check with ThreatFade status
- **Repository structure**: `api/`, `agents/`, `config/` folders
- **Apache 2.0** open-core licence
- **README** with architecture diagram, validation results, OSS contributions

---

## ThreatFade Engine Validation (Powering FusionOps)

| Date | Malware | Z-Score | Packets | Result |
|---|---|---|---|---|
| March 2026 | Merlin QUIC C2 | **14.76** | 490,565 | ✅ Detected |
| March 2026 | Cobalt Strike | 7.01 | — | ✅ Detected |
| March 2026 | IcedID | 3.89 | — | ✅ Detected |
