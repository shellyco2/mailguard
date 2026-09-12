# MailGuard

## Overview

MailGuard adds an email risk check to Gmail's side panel. Open a message and click **Analyze Email** to see a score out of 100, a verdict, confidence, the main reasons behind the result, and a suggested next step.

The main card stays short. Expand **Analysis details** to see how links were checked, the Safe Browsing status, and additional signals. The score is rule-based and explainable, not a probability that an email is malicious.

## How it works

Opening an email shows its sender, Reply-To address when present, and subject. Nothing is sent for analysis until you click the button.

The add-on reads the selected message using Gmail's temporary access token, then sends the relevant fields to a FastAPI backend on Vercel. The backend runs the scoring rules, checks link reputation with Google Safe Browsing, and returns the result for Gmail to display.

Verdicts range from **Low Risk** to **Moderate Risk**, **Suspicious**, and **High Risk**. Confidence describes how much supporting evidence comes from different categories. It is separate from risk: a strong signal can produce a high score with low confidence, and an email with no signals is not necessarily safe.

## What MailGuard checks

- **Sender and Reply-To:** different domains can be worth checking, but are also common in legitimate mailing services.
- **Authentication headers:** reported SPF, DKIM, and DMARC failures add evidence. Related failures are grouped to avoid counting the same issue several times.
- **Suspicious language:** urgency, credential requests, and financial requests. Combinations matter more than isolated phrases.
- **URL structure:** IP-address links, misleading domains, internationalized names, and unusual hostname patterns. Long tracking links carry very little weight on their own.
- **Safe Browsing reputation:** a known potential threat adds a strong signal. No match never lowers the score or proves that a link is safe.

Rules count once, related categories have point limits, and the total stops at 100. The weights are in `backend/scoring.py`; the reputation signal is added in `backend/reputation.py`.

Safe Browsing uses the official v5 URL search API for up to 50 distinct URLs. A three-second deadline keeps a slow lookup from holding up the result. If the check fails, MailGuard still returns the rule-based analysis and marks reputation checking as unavailable. Temporary caching reduces repeat requests.

## Architecture

```text
Gmail -> Apps Script CardService -> user clicks Analyze Email
  -> HTTPS POST /analyze -> Vercel FastAPI backend
  -> deterministic scoring + Google Safe Browsing v5
  -> JSON result -> Gmail result card
```

`Code.gs` handles Gmail events, message extraction, and cards. `appsscript.json` defines permissions and allowed outbound requests. In `backend/`, `main.py` exposes the endpoints, `models.py` defines the data contract, and the scoring and reputation modules produce the result. Tests live in `backend/tests/` and `tests/`.

The backend runs on Vercel Hobby. There is no AI, database, or persistent message storage. The [health endpoint](https://mailguard-api.vercel.app/health) is public; `/analyze` requires an API key.

## Privacy and security

Vercel receives the sender, Reply-To, subject, plain-text body, extracted URLs, and available Authentication-Results header. Gmail tokens, message IDs, and raw HTML are not sent to the backend. Attachment contents are not downloaded or scanned.

Google Safe Browsing receives up to 50 full URLs, including query parameters, but no message body or sender information. URLs can contain personal identifiers, so the add-on explains external processing before analysis. **MailGuard checks URL structure and reputation; it never opens or fetches destination websites.**

The shared MailGuard key is stored in Vercel and Apps Script Script Properties. The separate Google key is restricted to Safe Browsing and stored only in Vercel. Neither belongs in source files. Hosted analysis rejects missing or incorrect keys, and Gmail access is limited to the current message rather than the whole mailbox.

Application logs exclude message contents, URLs, and secrets. Hosting services may retain operational metadata. Safe Browsing results can be incomplete or incorrect; matching warnings include Google attribution.

## Setup

### Run the backend locally

Install Python 3.12+, Node.js 22+, and pnpm 11.19.0. From the repository root:

```powershell
pnpm install --frozen-lockfile
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m uvicorn main:app --reload --host 127.0.0.1
```

Use `http://127.0.0.1:8000/docs` to submit `example-email.json`. Local analysis works without a configured shared key. Without the Google key, reputation checking is unavailable; the other checks still run.

### Deploy to Vercel

1. Create a Vercel project with Root Directory `backend`.
2. Enable **Safe Browsing API** in a Google Cloud project. Create a key restricted to `safebrowsing.googleapis.com`.
3. In Vercel, add production Secrets `MAILGUARD_API_KEY` (a strong random shared key) and `SAFE_BROWSING_API_KEY` (the Google key).
4. Deploy with publicly reachable endpoints. Verify `/health` responds successfully and `/analyze` returns 401 without the shared key. Redeploy after changing environment variables.

### Connect Gmail

1. Create an Apps Script project. Enable Apps Script API access in user settings if needed.
2. From the repository root, copy `.clasp.example.json` to `.clasp.json`, enter your **Script ID**, and run `pnpm exec clasp login`.
3. In **Project Settings > Script Properties**, add `MAILGUARD_BACKEND_URL` with your HTTPS origin and `MAILGUARD_API_KEY` with the shared Vercel key. Keep the Google key out of Apps Script.
4. Set `appsscript.json`'s `urlFetchWhitelist` to your backend origin with a trailing slash, then run `pnpm exec clasp push`.
5. In **Deploy > Test deployments**, install the Google Workspace Add-on for your Gmail account and complete authorization. Reload Gmail and open MailGuard from the side panel.

## Demo and testing

Send yourself a few test messages and analyze them without opening their links:

- Subject **Urgent**, body **Please review the slides immediately.** Usually returns 5/100 and Low Risk.
- Subject **Urgent: verify your account**, body **Enter your password immediately: http://192.0.2.1/login**. The language and link rules produce 67/100, Suspicious.
- A message containing `http://testsafebrowsing.appspot.com/s/phishing.html`. The verified backend result was 72/100, High Risk, with a Safe Browsing reason.

Actual headers, extra links, and current reputation data can change the result. Expand **Analysis details** to check whether reputation checking completed.

The last recorded suite passed **77 tests**: 58 backend and 19 Apps Script. Run `pnpm test` from the root and `python -m pytest -q` with the backend virtual environment active. Tests use synthetic data and mock Google; no credentials are needed. See [TEST_RESULTS.md](TEST_RESULTS.md) for details.

## Limitations

MailGuard does not scan attachments or open linked websites. Language rules cover a small English phrase list, and authentication headers are not independently verified. Safe Browsing may miss new threats or flag legitimate links, and only the first 50 distinct URLs are checked.

This is a prototype, not a production email-security system. Scores help explain warning signs, but do not establish safety or replace checking an unexpected request through a trusted channel. Safe Browsing is used under its non-commercial offering.

## Part 2 - Product Review

The second part of the assignment includes the product review and gap analysis, test plan, and BI & monitoring definition.

[View Part 2 - Product Review](docs/Part_2_Product_Review.pdf)
