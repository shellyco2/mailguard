# MailGuard - Part 1

MailGuard is a Gmail Workspace Add-on that helps readers assess an email before acting. Click **Analyze Email** to see a risk score, verdict, confidence, prioritized reasons, and a recommended action. **Analysis details** explains link checks, supporting signals, and limitations.

Built as a Product Analyst assignment, MailGuard combines explainable rules with Google Safe Browsing. **The score represents evidence points, not a probability or a guarantee of safety.** This is a prototype, not a production email-security gateway.

## Architecture

```text
Gmail -> Apps Script CardService -> user clicks Analyze Email
  -> HTTPS POST /analyze -> Vercel FastAPI backend
  -> deterministic scoring + Google Safe Browsing v5
  -> JSON result -> Gmail result card
```

The backend runs on Vercel Hobby, without AI, a database, or persistent message storage. Its [health endpoint](https://mailguard-api.vercel.app/health) is public; analysis requires an API key.

| Files | Responsibility |
|---|---|
| `Code.gs`, `appsscript.json` | Gmail events, extraction, cards, scopes, and outbound allowlist |
| `backend/main.py`, `models.py` | API endpoints and bounded data contract |
| `backend/scoring.py` | Heuristic weights, verdicts, confidence, and actions |
| `backend/reputation.py`, `safe_browsing_wire.py` | Safe Browsing lookup, response decoding, and temporary cache |
| `backend/tests/`, `tests/` | Backend and Apps Script tests |

Gmail's opened-message event displays Sender, optional Reply-To, Subject, and the button. Analysis starts only after a click. The add-on uses the event's temporary token and message ID to retrieve the selected message, rather than assuming the first message in a thread. HTML is read for link extraction but is not sent to the backend. Attachment extraction is disabled.

## Scoring approach

Each heuristic counts once. Category caps prevent repeated or related evidence from dominating; the strongest rules receive points first. The final score is capped at 100.

| Category | Main rules | Cap |
|---|---|---:|
| Authentication | SPF or DKIM failure: 20; both: 25; DMARC failure: 30, as one combined signal. DMARC pass reduces other failures to 5. Softfail/permerror alone: 8. Missing/temporary errors: 0. | 30 |
| Sender | Different Sender and Reply-To domains: 8; legitimate services can also do this. | 8 |
| URL structure | IP addresses, misleading domains, or user-info before @: 25 each; punycode: 12; complex hostname: 5; account/login path on an already concerning link: 10. Shorteners, HTTP, malformed URLs, and long links add only 1-3 points each. | 45 |
| Language | Urgency: 5; credential requests: 10; financial requests: 10; two or more groups together: 15 bonus. Generic "sign in" alone earns nothing. | 30 |
| Reputation | Safe Browsing threat match: 70, once per email. | 70 |

Misleading-domain detection includes a sender at `example.com` linking to `example.com.attacker.test`. Ordinary login paths and legitimate subdomains do not automatically trigger it. Exact rules remain readable in `backend/scoring.py`.

Verdicts are **0-19 Low Risk**, **20-44 Moderate Risk**, **45-69 Suspicious**, and **70-100 High Risk**. Recommended actions become more cautious as risk increases.

The card shows up to two meaningful reasons for Low/Moderate Risk and three for Suspicious/High Risk. Weaker and remaining signals appear in collapsed details, keeping the main decision easy to scan.

## Confidence

Confidence describes the strength and breadth of evidence, separately from risk:

- **High:** three categories with at least eight points, including two with at least 20.
- **Medium:** two categories with at least eight points, including one with at least 20.
- **Low:** otherwise.

Reputation counts as another category. Categories approximate independent evidence; they are not statistically independent measurements. An email with no signals can have Low confidence, while a single reputation match can produce High Risk with Low confidence. Neither metric measures certainty.

## Google Safe Browsing

The backend uses the official **v5 URL search API** for the first **50 distinct extracted URLs**. MailGuard checks URL structure and asks Google for reputation; it **never opens or fetches destination websites**.

A **three-second deadline**, without redirects or retries, limits lookup delay. Errors, invalid responses, missing configuration, and timeouts fall back to heuristic analysis. **No match never reduces the score or proves safety.** Analysis details distinguishes matches, no matches, absent links, unavailable checks, and partial coverage.

A bounded in-memory cache stores hashed batch identifiers, match status, and expiry, not raw URLs. Matches and no-matches follow Google's cache duration, capped at 30 minutes, and disappear on restart. The Gmail result is a snapshot from the analysis click.

Warnings include Google attribution and acknowledge possible errors. Safe Browsing can miss threats or flag legitimate sites; this project uses its non-commercial offering.

## Privacy and security

| Destination | Data sent |
|---|---|
| Vercel backend | Sender, Reply-To, Subject, plain-text body, extracted URLs, available Authentication-Results header, and an empty attachments list. The MailGuard key is sent in an HTTPS header. |
| Google Safe Browsing | Up to 50 full URLs, including query parameters, and a separate Google API key. No email body, sender fields, Gmail token, or MailGuard key. |

Gmail tokens, message IDs, and raw HTML are not sent to Vercel. Attachment contents are neither downloaded nor scanned. URLs may contain personal or sensitive query parameters; the pre-analysis notice explains external processing.

- `MAILGUARD_API_KEY` is stored in Vercel and Apps Script Script Properties. Hosted `/analyze` rejects missing/incorrect keys and refuses analysis if its key is unconfigured.
- `SAFE_BROWSING_API_KEY` is restricted to Safe Browsing and stored as a Vercel Secret, never in Apps Script or source files.
- Application logs exclude message contents, URLs, secrets, and raw exceptions. Validation errors do not echo input; hosting infrastructure may retain operational metadata.
- Gmail permissions cover the current message and external requests, without mailbox-wide read access. Oversized messages are rejected rather than silently scored from incomplete data.

## Setup

### Local development

Install Python 3.12+, Node.js 22+, and pnpm 11.19.0. From the repository root:

```powershell
pnpm install --frozen-lockfile
pnpm test
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python -m uvicorn main:app --reload --host 127.0.0.1
```

Submit `example-email.json` through `http://127.0.0.1:8000/docs`. Local development allows analysis without a configured shared key; reputation checking is unavailable without its Google key. Automated tests mock Google and require no credentials.

### Backend deployment

1. Create a Vercel project with Root Directory `backend`; `vercel.json` selects native FastAPI.
2. Enable **Safe Browsing API** in a Google Cloud project and create a key restricted to `safebrowsing.googleapis.com`.
3. Add production Secrets `MAILGUARD_API_KEY` (a strong random shared key) and `SAFE_BROWSING_API_KEY` in Vercel settings. Keep values out of source files and Git.
4. Deploy with publicly reachable endpoints. Verify `/health` returns `{"status":"ok"}` and `/analyze` rejects missing/incorrect keys with 401. Test authorized analysis with synthetic data. Environment changes require redeployment.

### Gmail Add-on

1. Create an Apps Script project and enable Apps Script API access in user settings if needed.
2. Copy `.clasp.example.json` to `.clasp.json` and enter your **Script ID**. Run `pnpm exec clasp login` and complete Google authorization.
3. In **Project Settings > Script Properties**, set `MAILGUARD_BACKEND_URL` to your backend HTTPS origin and `MAILGUARD_API_KEY` to its shared key. The Google key belongs only in Vercel.
4. Update `appsscript.json`'s `urlFetchWhitelist` to your origin with a trailing slash. Run `pnpm exec clasp push`; only the script and manifest are uploaded.
5. Select **Deploy > Test deployments**, install the Google Workspace Add-on for your Gmail account, and authorize it. Reload Gmail, open an email, and select MailGuard from the side panel.

Use your own backend and credentials for a separate installation. This setup is a test installation, not a public Marketplace release.

## Demo

Send synthetic messages to yourself and analyze them without opening their links:

| Demo | Input | Expected result |
|---|---|---|
| Benign urgency | Subject `Urgent`; body `Please review the slides immediately.` | Ordinarily 5/100, Low Risk, Low confidence. |
| Credential phishing | Subject `URGENT: Verify your account immediately`; body `Your account will be suspended within 24 hours. Verify your identity immediately by signing in and confirming your password. Login here: http://192.0.2.1/login` | Heuristics: 67/100, Suspicious, Medium confidence. |
| Reputation match | Body containing `http://testsafebrowsing.appspot.com/s/phishing.html` | Previously verified: 72/100, High Risk, with a Google Safe Browsing reason. |

Expand **Analysis details** to demonstrate link-check status. Actual headers, extra links, and current Google data can change scores. "Check unavailable" means heuristics completed without a reputation result, not that Google found no threat.

## Tests

**77 tests passed:** 58 backend and 19 Apps Script, with two dependency deprecation warnings. See [TEST_RESULTS.md](TEST_RESULTS.md) for calibration and reproduction details.

Coverage includes benign/phishing scenarios, scoring caps, confidence, current-message extraction, API-key protection, input limits, all verdict cards, RTL text, and reputation matches, failures, timeouts, limits, caching, and Protobuf decoding. Tests use synthetic data and mocks; they verify behavior, not real-world detection accuracy. Recorded live checks also verified health, key rejection, and reputation outcomes.

## Limitations, trade-offs, and future improvements

- **Explainability versus accuracy:** hand-chosen rules are easy to inspect but lack a representative benchmark. Next steps are a labeled corpus, precision/recall measurement, and false-positive review.
- **Limited context:** English phrases can misread quotations or benign requests. Authentication headers are not independently verified, and domain comparison does not resolve organizational relationships. Broader language and context handling would improve coverage.
- **Reputation versus privacy:** full-URL checks disclose URLs to Google, cover at most 50 links, and can return stale cached results. Large requests can fail gracefully. Privacy-preserving lookups and broader compatibility tests are potential improvements.
- **Demo versus production:** one shared key, Hobby quotas, and cold starts suit a prototype. A multi-user product needs per-user authentication, rate limiting, abuse controls, retention policies, and security review. Commercial use also requires reviewing Safe Browsing terms.
- **Scope and interface:** attachments, destination-page inspection, automatic blocking, AI, and databases are outside Part 1. CardService limits layout flexibility; collapsed details balance readability with transparency.

References: [v5 URL search](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search), [Google's warning guidance](https://developers.google.com/safe-browsing/reference/Appropriate.Usage), [CardService](https://developers.google.com/apps-script/reference/card-service).
