# FusionOps — Agentic SecOps + AIOps Convergence Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-teal.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Powered by ThreatFade](https://img.shields.io/badge/Powered%20by-ThreatFade-00E5C8)](https://github.com/LloydCoder/tinlance-threatfade)
[![Made by Tinlance](https://img.shields.io/badge/Made%20by-Tinlance%20Limited-FF4D6D)](https://tinlance.com)

> **One brain for threat detection and autonomous response.**  
> FusionOps correlates C2 threats with IT anomalies and closes the loop — automatically.

---

## What Is FusionOps?

FusionOps is an agentic SecOps + AIOps platform built on top of the [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade) C2 detection engine.

Where ThreatFade **detects**, FusionOps **acts**.

```
Network traffic → ThreatFade detects C2 evasion → FusionOps triage agent classifies
→ Remediation agent suggests/executes fix → Dashboard logs audit trail
```

### Why FusionOps?

- **Signature-based tools miss C2 evasion.** FusionOps uses entropy + z-score analysis validated against real Merlin QUIC C2 malware (z-score 14.76, 490K packets, 0% false positives).
- **SecOps and ITOps are siloed.** FusionOps fuses them into one agentic loop.
- **AI agents create new attack surfaces.** FusionOps monitors LLM and agentic AI channels — not just traditional network traffic.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           FusionOps (this repo)          │
│                                         │
│  ┌──────────┐    ┌───────────────────┐  │
│  │  FastAPI  │───▶│   Triage Agent    │  │
│  │   layer   │    │  (classify alert) │  │
│  └──────────┘    └────────┬──────────┘  │
│         ▲                  │             │
│         │         ┌────────▼──────────┐  │
│         │         │ Remediation Agent │  │
│         │         │  (suggest / fix)  │  │
│         │         └────────┬──────────┘  │
│         │                  │             │
│         │         ┌────────▼──────────┐  │
│         │         │    Dashboard UI   │  │
│         │         │  (live event log) │  │
│         │         └───────────────────┘  │
└─────────┼───────────────────────────────┘
          │  HTTP calls /detect/ endpoints
          ▼
┌─────────────────────────────────────────┐
│   ThreatFade (separate repo)            │
│   github.com/LloydCoder/tinlance-       │
│   threatfade                            │
│                                         │
│   Entropy + Z-score + Rules engine      │
│   Validated: Merlin QUIC (z=14.76)      │
└─────────────────────────────────────────┘
```

FusionOps calls ThreatFade as an **external HTTP service** — no code is copied between repos. ThreatFade upgrades propagate to FusionOps automatically.

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Tinlance/fusionops.git
cd fusionops
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set your ThreatFade API URL
```

### 3. Start ThreatFade (in its own terminal)

```bash
# In your ThreatFade repo
uvicorn fusionops_api:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Start FusionOps

```bash
uvicorn api.fusionops_api:app --host 0.0.0.0 --port 8080 --reload
```

### 5. Open the API docs

```
http://localhost:8080/docs
```

---

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service liveness check |
| `GET` | `/events` | Last N detection events |
| `POST` | `/detect/json` | Analyse JSON signal data |
| `POST` | `/detect/scenario` | Run named simulation scenario |
| `POST` | `/detect/pcap` | Upload PCAP for analysis |
| `POST` | `/triage` | Run triage agent on a detection result |

---

## Open-Core Model

| Feature | Free (this repo) | Paid (Enterprise) |
|---------|-----------------|-------------------|
| C2 entropy + z-score detection | ✅ | ✅ |
| Single alert triage agent | ✅ | ✅ |
| PCAP upload analysis | ✅ | ✅ |
| Multi-agent remediation loop | ❌ | ✅ |
| Self-healing automation | ❌ | ✅ |
| SIEM / SOAR / Slack integrations | ❌ | ✅ |
| LLM + agentic AI channel monitoring | ❌ | ✅ |
| Compliance dashboard (SOC 2 / GDPR) | ❌ | ✅ |

---

## Validation

FusionOps is powered by ThreatFade, validated against real malware:

| Malware | Z-Score | Packets | Result |
|---------|---------|---------|--------|
| Merlin QUIC C2 | **14.76** | 490,565 | ✅ Detected |
| Cobalt Strike | 7.01 | — | ✅ Detected |
| IcedID | 3.89 | — | ✅ Detected |

**False positive rate: 0%**

---

## Open-Source Contributions

Tinlance has merged PRs into the top security OSS tools:

| Repo | Stars | Contribution |
|------|-------|-------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 24K★ | Nigerian fintech credential detector |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 15K★ | 5 Nigerian fintech detectors |
| [Semgrep](https://github.com/returntocorp/semgrep) | 11K★ | Day-one merge — rule in global scans |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 10K★ | Secret detection rules |
| [Slither](https://github.com/crytic/slither) | 5K★ | Nigerian fintech credential detection |

---

## Roadmap

- [x] ThreatFade C2 detection engine (validated)
- [x] FastAPI wrapper + REST endpoints
- [x] PCAP upload + real-time analysis
- [ ] Triage agent (in progress)
- [ ] Remediation agent
- [ ] Dashboard UI
- [ ] AWS production deployment
- [ ] SIEM integrations (Splunk, Elastic)
- [ ] LLM/agentic AI channel monitoring

---

## Built By

**Tinlance Limited** (RC: 7962164) — Nigeria 🇳🇬  
Engineering AI and cybersecurity products for the frontier.

- 🌐 [tinlance.com](https://tinlance.com)
- 🐙 [github.com/Tinlance](https://github.com/Tinlance)
- 🐦 [@lloydcoder](https://x.com/lloydcoder)

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

> The multi-agent remediation loop, self-healing automation, and enterprise integrations are proprietary and not included in this open-core release.