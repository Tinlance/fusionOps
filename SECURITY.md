# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.3.x (current) | ✅ Active support |
| 0.2.x | ⚠️ Critical fixes only |
| 0.1.x | ❌ End of life |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately:

- **Email:** hello@tinlance.com
- **Subject:** `[SECURITY] FusionOps - <brief description>`
- **PGP:** Available on request

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgement:** Within 48 hours
- **Status update:** Within 7 days
- **Fix timeline:** Within 30 days for critical issues
- **Credit:** We publicly credit reporters in the CHANGELOG (with permission)

---

## Security Architecture

FusionOps is designed with the following security principles:

- **No persistent secrets:** API keys and tokens loaded from environment variables only
- **Input validation:** All endpoints validated with Pydantic models
- **Temp file cleanup:** PCAP uploads are deleted immediately after processing
- **No code execution:** Detection engine performs statistical analysis only — no eval/exec
- **CORS:** Configurable per deployment — lock down `allow_origins` in production
- **Zero data retention:** In-memory event log only — no data written to disk in open-core tier

---

## Known Limitations (Open-Core)

- No API key authentication in open-core tier (Enterprise feature)
- In-memory event log resets on service restart
- No rate limiting in open-core tier

---

## Responsible Disclosure

FusionOps is a cybersecurity tool. We take security seriously and appreciate
responsible disclosure. We will not pursue legal action against researchers
who report vulnerabilities in good faith.

© 2026 Tinlance Limited
