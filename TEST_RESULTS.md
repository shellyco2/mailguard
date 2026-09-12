# Final test results

Validated 2026-09-12 against the clean submission copy.

| Suite | Result |
|---|---:|
| Backend scoring, API protection, and Safe Browsing | 58 passed |
| Apps Script extraction and result-card UX | 19 passed |
| Total | **77 passed, 0 failed** |

Two dependency deprecation warnings relate to the current Starlette/httpx test stack. No test failed. Tests use mocks and synthetic inputs; no Google secrets or real emails are needed.

## Reproduce

From the repository root: `pnpm test` (or `node --test tests/apps-script.test.cjs`).

From `backend`, after installing `requirements-dev.txt` into the local virtual environment: `python -m pytest -q -p no:cacheprovider` using that environment's Python.

## Heuristic calibration

These eight examples exercise the unchanged scoring rules without external reputation evidence. They are regression checks, not a measured detection benchmark.

| Synthetic example | Score / 100 | Verdict | Confidence |
|---|---:|---|---|
| corporate | 0 | Low Risk | Low |
| newsletter | 1 | Low Risk | Low |
| different_reply | 8 | Low Risk | Low |
| urgency_only | 5 | Low Risk | Low |
| credential_phishing | 67 | Suspicious | Medium |
| financial_request | 68 | Suspicious | High |
| malicious_link | 45 | Suspicious | Low |
| multiple_strong | 100 | High Risk | High |

## Previously verified deployment results

- Public `/health`: HTTP 200.
- `/analyze` without the shared key or with an incorrect key: HTTP 401.
- Google's synthetic phishing URL: reputation match, 72/100, High Risk (70 reputation points + 2 HTTP points).
- `https://example.com/`: no reputation match, 0/100, Low Risk.
- No URLs: no external lookup, 0/100, Low Risk.
- The requested credential-phishing message: 67/100, Suspicious, Medium confidence from heuristics; actual Gmail headers/reputation can add evidence.

The packaging pass did not redeploy or change the running backend. Automated CardService mocks verify structure, strings, escaping, and RTL isolation; they do not substitute for visual verification in Gmail. Follow the README demo for the final presentation check.
