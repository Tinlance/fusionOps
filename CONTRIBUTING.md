# Contributing to FusionOps

Thank you for your interest in contributing to FusionOps!

FusionOps is an open-core project. The detection engine, triage agent, and
remediation plan generator are open-source under Apache 2.0. Enterprise
auto-execution and SIEM integrations are proprietary.

---

## Ways to Contribute

### Bug Reports
Open an issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
Include your Python version, OS, and the full error message.

### Feature Requests
Open an issue using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).
Describe the use case, not just the solution.

### Code Contributions
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Write tests for your changes
4. Run the test suite: `pytest agents/ -v`
5. Submit a pull request with a clear description

---

## Development Setup

```bash
git clone https://github.com/Tinlance/fusionOps.git
cd fusionOps
pip install -r requirements.txt
cp .env.example .env
```

You also need ThreatFade running locally:

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
pip install fastapi "uvicorn[standard]" python-multipart pydantic scapy numpy scipy
uvicorn fusionops_api:app --host 0.0.0.0 --port 8000 --reload
```

---

## What We Welcome

- Improvements to triage agent detection logic
- New scenario types for `detect/scenario`
- Better error handling and edge case coverage
- Documentation improvements
- Language translations for the dashboard UI
- Integration examples (Splunk, Elastic, SOAR platforms)

## What We Don't Accept

- Changes to the enterprise tier features (proprietary)
- Modifications that remove the `open_core_note` attribution
- Breaking changes to the `FullAnalysisResult` schema without discussion

---

## Code Style

- Follow PEP 8
- Type hints on all public functions
- Docstrings on all classes and public methods
- Keep functions under 50 lines where possible

---

## Questions?

Open a GitHub Discussion or email **hello@tinlance.com**

Built with 💚 by Tinlance Limited — Nigeria 🇳🇬
