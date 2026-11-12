# Password Security Assessment System

A local Flask educational cybersecurity application for assessing password strength, policy compliance, password reuse/history, hash formats, and organizational password-risk posture. It supports single-account and CSV batch assessments, audit/event records, framework-to-feature mapping, and six report types with PDF and Excel export.

> **Important:** Use synthetic sample credentials only. This is a university project prototype, not an enterprise credential-auditing product, formal compliance assessment, or production authentication service.

## Implemented capabilities

- Password strength estimation with zxcvbn (a conservative local fallback is used only if the dependency is unavailable).
- Approximate character-pool entropy estimate; not a crack-time guarantee.
- Local common-password blocklist plus dictionary-word, repeated-character, and sequential-pattern heuristics.
- Configurable length, character-class, maximum-age, and password-history-depth policy settings.
- Password reuse detection across CSV batch rows, previously assessed accounts, and the same account's stored history.
- HMAC-SHA256 keyed password fingerprints; no plaintext password or raw password hash is stored in assessment/audit tables.
- Hash-format heuristics, Argon2id/bcrypt verification, and Argon2id/bcrypt demo hash generation.
- Four risk levels (Low, Medium, High, Critical) using a transparent project-defined score.
- Single-account and CSV batch assessment (`username,password` required; `password_age_days,hash` optional).
- Audit log and security event monitoring with severity and filtering.
- Admin login and password change; first-run demo account must be changed immediately.
- Selected control mapping for NIST SP 800-63B, OWASP Authentication/Password Storage guidance, ISO/IEC 27001 concepts, and CIS Controls v8.
- Six separate report outputs: Password Security, Password Policy Compliance, Password Strength, Hash Algorithm, Risk Assessment, and Executive Summary. Each is exportable as PDF or Excel.

## Setup

Python 3.10+ is recommended.

### Windows PowerShell
```powershell
cd password-security-assessment
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

### Linux / macOS
```bash
cd password-security-assessment
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

First-run login: `admin` / `ChangeMe123!`. Change this immediately after first login. The app creates a local `.secret_key` and `instance/assessment.db` automatically.

## CSV format

```csv
username,password,password_age_days,hash
employee001,syntheticExample!2026,45,
employee002,AnotherSynthetic!2026,210,
```

Do not upload real employee credentials. Passwords are handled in memory; only keyed HMAC fingerprints and aggregate assessment metadata are persisted. The HMAC key is derived from the app's local Flask secret key. Protect `.secret_key` and the `instance` directory.

## Report definitions

1. **Password Security Report:** assessment totals and overall posture.
2. **Password Policy Compliance Report:** compliant/non-compliant counts and compliance rate.
3. **Password Strength Report:** average strength score and weak/strong assessment counts.
4. **Hash Algorithm Report:** observed hash-format distribution; unprovided hashes are counted as not assessed.
5. **Risk Assessment Report:** Low/Medium/High/Critical distribution.
6. **Executive Summary Report:** high-level risk and policy indicators plus recent event count.

Reports are based on retained assessment metadata. Individual plaintext passwords are intentionally unavailable for reports.

## Compliance mapping limitations

The Compliance Mapping page maps selected project features to relevant framework themes. Statuses are explicitly marked partial where controls are not complete. The project does **not** claim NIST, OWASP, ISO 27001, or CIS certification or full compliance. In particular, actual MFA, a complete compromised-password service, enterprise identity integration, comprehensive CIS safeguards, and a full ISO information security management system are outside this prototype.

## Security and technical limitations

- Hash identification based on a prefix or length is heuristic and cannot prove an algorithm. Only Argon2id and bcrypt encoded hashes are verified.
- Password strength, entropy, and risk scores are estimates. The risk thresholds are project-defined, not official NIST/OWASP scoring.
- Password history is implemented for accounts assessed by this application. It is not connected to an organization's identity provider or password database.
- The app has admin-only access and records login success/failure events. It does not implement production-grade MFA, role provisioning, CSRF protection, rate limiting, centralized monitoring, or secure deployment hardening. Do not expose the Flask development server publicly.
- The password expiry setting is an organization-configurable project policy. It should not be interpreted as a universal recommendation to force periodic password changes.
- HMAC fingerprints are pseudonymous security data, not anonymous data. Protect the secret key and database.

## Tests

Run the pure assessment-module tests:
```bash
python -m unittest discover -s tests -v
```

Run Python syntax checks:
```bash
python -m compileall -q .
```

The full Flask/browser integration suite should be run on the target machine after installing `requirements.txt`. This build environment may not have package-index/network access, so an inability to install dependencies here is not a project test failure.

## Project structure

```text
app.py
config.py
modules/
  password_strength.py
  hash_analyzer.py
  policy_checker.py
  risk_assessment.py
  recommendations.py
reports/
  pdf_report.py
  excel_report.py
templates/
static/
tests/
instance/       # generated locally; do not commit
.secret_key     # generated locally; do not commit
```
