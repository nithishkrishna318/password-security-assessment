# University Requirement Traceability

Statuses describe this educational prototype's implemented scope. **Partial** means a related feature exists but does not fully satisfy the broader organizational/security meaning of the requirement. Compliance-framework references are mappings, not certification claims.

| University requirement | Implementation / evidence | Status / limitation |
|---|---|---|
| Password strength assessment | `modules/password_strength.py`, `/assess` | Implemented; estimate only |
| Password entropy | `estimate_entropy()` | Implemented; rough character-pool estimate |
| Weak and common password detection | zxcvbn + local blocklist | Implemented; local list is not comprehensive |
| Password complexity | strength checks + `modules/policy_checker.py` | Implemented |
| Password reuse detection | HMAC fingerprints; `/assess`, `/batch` | Implemented for accounts assessed by this app |
| Password length compliance | configurable policy | Implemented |
| Hash algorithm identification | `modules/hash_analyzer.py` | Implemented heuristically; format cannot prove algorithm |
| Hash security analysis and strength comparison | hash risk classifications + comparison table | Implemented as educational comparison, not benchmark |
| Deprecated algorithm detection | MD5/SHA-1/SHA-256 format heuristics | Partial; detection is not definitive |
| Hash integrity / password verification | Argon2id and bcrypt verify utilities | Partial; other formats unsupported |
| Password storage method evaluation | hash comparison table and recommendations | Partial; no live external storage inspection |
| Minimum length, upper/lowercase, numeric, special rules | configurable policy page | Implemented |
| Password expiration policy | configurable maximum age + assessment input | Implemented as assessment policy; no identity-provider enforcement |
| Password history validation | keyed fingerprints and configurable history depth | Implemented for previously assessed accounts |
| Password reuse prevention | reuse is detected, risk-scored and flagged | Partial; no external account system to reject a credential at password-change time |
| Low / Medium / High / Critical risk | `modules/risk_assessment.py` | Implemented |
| Risk considers complexity, dictionary, repetition, sequences, age and hash | strength findings + policy + hash + age | Implemented as project-defined model |
| Security recommendations including MFA/password manager/hash upgrade | `modules/recommendations.py` | Implemented as recommendations; MFA is not actually provisioned |
| Password Security Report | `/reports`, PDF/Excel export | Implemented |
| Password Policy Compliance Report | `/reports`, PDF/Excel export | Implemented |
| Password Strength Report | `/reports`, PDF/Excel export | Implemented |
| Hash Algorithm Report | `/reports`, PDF/Excel export | Implemented from recorded hash metadata |
| Risk Assessment Report | `/reports`, PDF/Excel export | Implemented |
| Executive Summary Report | `/reports`, PDF/Excel export | Implemented |
| PDF and Excel export | `reports/` modules | Implemented |
| OWASP Password Security / Authentication alignment | `/compliance` | Partial selected mapping; not full compliance |
| NIST Password Guidelines alignment | `/compliance` | Partial selected mapping; not full compliance |
| ISO/IEC 27001 authentication/access control alignment | `/compliance` | Partial selected mapping; not an ISMS or certification |
| CIS Security Controls alignment | `/compliance` | Partial selected mapping; not a full safeguard assessment |
| Strong password creation and secure storage guidance | recommendations + hash tools | Implemented as guidance/demo tools |
| Modern hashing and salting | Argon2id/bcrypt demo hash generation | Implemented in demo utility |
| MFA | recommendations | Partial; no actual MFA enrollment/login factor |
| Regular password audits | single and CSV batch assessments | Implemented for supplied synthetic data |
| Password entropy / complexity / policy / hash / risk controls | modules and pages | Implemented within prototype scope |
| Audit logging | `audit_logs` table, Reports page | Implemented; metadata only |
| Access control | admin login-required routes | Partial; single admin role model, no granular RBAC/user provisioning |
| Security event monitoring | `security_events`, `/monitoring` | Partial; event log/filter dashboard, not real-time SIEM/alerting |
| Organizational assessment | CSV batch upload | Implemented for offline CSV samples; no enterprise directory integration |

## Validation evidence

- `python -m compileall -q .` — passed in the build environment.
- `python -m unittest discover -s tests -v` — 8 core module tests passed.
- Full Flask/browser integration testing was not run in the build environment because package installation was unavailable. Install `requirements.txt` and run the app locally before submission.
