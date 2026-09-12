# MailGuard - Part 1

MailGuard is a Gmail Workspace Add-on that helps a reader assess an email before acting. Open an email, click **Analyze Email**, and see a risk score, verdict, confidence, up to three prioritized reasons, and a recommended action. Expand **Analysis details** for limitations, supporting signals, and the Safe Browsing status.

This Product Analyst assignment uses explainable rules and Google Safe Browsing. **The score is evidence points, not a probability or a guarantee of safety.** It is a prototype, not a production email-security gateway.

## Architecture

```text
Gmail current-message event
  -> Apps Script CardService card
  -> user clicks Analyze Email
  -> HTTPS POST /analyze on Vercel
  -> FastAPI: deterministic rules + Google Safe Browsing v5 URL search
  -> JSON result -> Gmail result card
```

There is no AI, database, message storage, or attachment scanning. The deployed backend uses Vercel Hobby. Google Safe Browsing was enabled without billing for this non-commercial assignment. The public health endpoint is https://mailguard-api.vercel.app/health; analysis requires a private API key.

### Repository map

```text
Code.gs                         Gmail events, extraction, API call, result cards
appsscript.json                 Gmail triggers, scopes, outbound allowlist
.clasp.example.json             Template for your local Apps Script project link
package.json / pnpm-lock.yaml    Pinned clasp tooling and JavaScript test command
backend/
  main.py                       GET /health and protected POST /analyze
  models.py                     Bounded input/output contract
  scoring.py                    Deterministic heuristic scoring
  reputation.py                 Safe Browsing lookup, cache, and additional signal
  safe_browsing_wire.py          Small Protobuf response decoder
  requirements*.txt             Python dependencies and test dependencies
  vercel.json                   Native FastAPI deployment configuration
  example-email.json            Synthetic analysis payload
  tests/                        Scoring, API, reputation, and binary fixture tests
tests/apps-script.test.cjs       Mocked Apps Script integration and card tests
TEST_RESULTS.md                  Final validation and calibration results
SUBMISSION_AUDIT.md              Publication scope and security audit
```

## Reading the current email

`onGmailMessageOpen(e)` receives Gmail's opened-message event and displays Sender, optional Reply-To, Subject, and the button. Clicking calls `onAnalyzeEmail(e)`, which activates the temporary token with `GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken)` and retrieves exactly `e.gmail.messageId` using `GmailApp.getMessageById`. It does not assume the first message in a thread is the selected message.

HTML is read to extract HTTP(S) links from hrefs, but only plain text and extracted URLs are sent. An explanation before the button describes external processing. Attachment extraction is disabled. The optional attachment-metadata input remains for compatibility and does not affect scoring.

## Scoring

Each heuristic counts once. Strongest rules consume a category's cap first; repeated words and links do not accumulate points. Returned signal points reflect those caps. The final combined score is capped at 100.

| Category | Evidence points | Cap |
|---|---|---:|
| Authentication | SPF or DKIM fail: 20; both: 25; DMARC fail: 30, as one combined signal. DMARC pass reduces other failures to 5. Softfail/permerror alone: 8. Missing/temporary errors: 0. | 30 |
| Sender | Different full Sender and Reply-To domains: 8; legitimate services can do this. | 8 |
| URL structure | IP address: 25; user-info before @: 25; sender domain embedded at the start of another hostname: 25; punycode: 12; unusually complex hostname: 5; account/login path on an already concerning link: 10. Shortener: 3; HTTP: 2; malformed URL: 2; length over 200 characters: 1. | 45 |
| Language | Urgency: 5; credential request: 10; financial request: 10; two or more groups together: 15 bonus. Generic "sign in" alone earns nothing. | 30 |
| Reputation | Google Safe Browsing threat match: 70, once per email. | 70 |

A complex hostname has at least six labels, a label at least 40 characters long, or a label with four hyphens. Misleading-domain detection is narrow: a sender at `example.com` linking to `example.com.attacker.test`. Ordinary login paths and legitimate subdomains do not automatically trigger that rule.

Verdicts: **0-19 Low Risk**, **20-44 Moderate Risk**, **45-69 Suspicious**, **70-100 High Risk**. Actions range from staying cautious to avoiding links, attachments, and credentials until independently verified. A no-match reputation result never reduces the score.

The card shows at most two meaningful reasons for Low/Moderate Risk and three for Suspicious/High Risk, sorted by points. Signals below five points and remaining reasons appear only in collapsed details. ASCII punctuation and Unicode direction isolation keep the score readable in RTL Gmail. CardService's native typography, icons, sections, and supported formatting provide the layout; there is no custom CSS.

## Confidence

Confidence describes supporting evidence, separately from risk:

- **High:** at least three categories with eight or more points, including two with at least 20.
- **Medium:** at least two categories with eight or more points, including one with at least 20.
- **Low:** otherwise.

A reputation match is one additional category; repeated rules within a category are not independent sources. These categories approximate independence, not statistical independence. A clean email can have Low confidence because absence of these signals is not proof of safety. A single strong reputation match can likewise have High Risk and Low confidence.

## Google Safe Browsing

The backend calls official `GET https://safebrowsing.googleapis.com/v5/urls:search`, using at most the first **50 distinct extracted URLs**. MailGuard analyzes URL structure and asks Google for reputation; it **never opens or fetches destination websites**. API errors, missing configuration, invalid responses, and timeouts fall back to heuristic analysis. Analysis details distinguishes match, no match, no URLs, and unavailable checks, including partial coverage.

A **three-second total deadline**, no redirects, and no retries bound the lookup delay. The live endpoint returns Protobuf; Google's Protobuf runtime decodes the small response schema, tested against a recorded response for Google's synthetic phishing test URL.

A bounded per-process memory cache holds hashed batch identifiers, match status, and expiry, not raw URLs. It caches both matches and no-matches for Google's `cacheDuration`, capped at 30 minutes. Cache contents disappear on worker restart; no persistent database is used. The Gmail result is a snapshot taken when Analyze Email was clicked.

Google-based warnings include attribution and a notice that results may be incomplete or incorrect. Safe Browsing can miss threats and can flag legitimate sites. It is used under its non-commercial offering.

## External data and security

| Destination | Data sent |
|---|---|
| MailGuard backend on Vercel | Sender, Reply-To, Subject, plain-text body, extracted URLs, available Authentication-Results header; an empty attachments list. MailGuard API key in an HTTPS header. |
| Google Safe Browsing | Up to 50 full extracted URLs, including any query parameters, and the separate Google API key in a header. No email body, sender fields, Gmail token, or MailGuard API key. |

Gmail access tokens, message IDs, and raw HTML are not sent to the backend. No attachment contents are downloaded or scanned. Full URLs may contain personal identifiers or sensitive query parameters; users should understand this sharing before analyzing mail.

- `MAILGUARD_API_KEY` lives in Vercel environment settings and Apps Script Script Properties. Constant-time comparison protects `/analyze`; `/health` is public.
- `SAFE_BROWSING_API_KEY` is restricted to the Safe Browsing API and held only as a Vercel Secret and runtime memory. Google manages the original credential. Never place its value in Apps Script or files.
- Hosted analysis fails closed when the MailGuard API key is missing. Local development without a configured key is intentionally allowed on the loopback server only.
- The application does not log bodies, URLs, tokens, keys, or raw exceptions. Validation errors do not echo rejected input. Hosting infrastructure may retain operational metadata under its own policies.
- Narrow Gmail scopes cover add-on execution, current-message metadata, current-message user-action access, and external requests. No mailbox-wide read scope is requested.
- Extraction rejects excessive input instead of silently scoring incomplete content: 100,000 plain-text characters, 1,000,000 HTML characters, 200 URLs of up to 4,096 characters, and bounded headers.

## Setup

### 1. Local development

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

Use `http://127.0.0.1:8000/docs` to submit `example-email.json`. Local reputation checks are unavailable without a key; do not copy the production Google key into local files. Automated tests mock Google and need no credentials or external requests.

### 2. Vercel and Google setup

1. Create or sign in to Vercel Hobby. Create a project whose Root Directory is `backend`; `vercel.json` selects native FastAPI. Keep payment details unset.
2. In your Google Cloud project, enable **Safe Browsing API**. Create a dedicated API key restricted to `safebrowsing.googleapis.com`. If billing or payment is required, stop; this assignment does not authorize it.
3. In Vercel project settings, add production Secrets `MAILGUARD_API_KEY` (a strong random shared key) and `SAFE_BROWSING_API_KEY` (the restricted Google key). Enter values through the secure settings UI, not commands, source files, or Git.
4. Deploy the backend. Ensure production endpoints are publicly reachable while `/analyze` remains protected by its own key. Environment changes require redeployment.
5. Verify `/health` returns `{"status":"ok"}` and `/analyze` rejects a missing/wrong key with 401. Use synthetic data for the authorized test, supplying the shared key through a secret-aware API client.

The checked-in default URL belongs to the assignment deployment and is public configuration, not a credential. For a separate installation, use your own backend and keys. Do not reuse another deployment's private credentials.

### 3. Gmail Apps Script setup

1. Create an empty Apps Script project. Enable Apps Script API access in your Apps Script user settings if needed.
2. From the repository root, copy `.clasp.example.json` to `.clasp.json`. Replace the placeholder with your **Script ID**, not a deployment ID. This local file is ignored by Git.
3. Run `pnpm exec clasp login` and complete Google sign-in and permission approval yourself.
4. In Apps Script **Project Settings > Script Properties**, set `MAILGUARD_BACKEND_URL` to your backend HTTPS origin and `MAILGUARD_API_KEY` to the shared Vercel key. Do not add the Google Safe Browsing key here.
5. If using a different backend, update `appsscript.json`'s `urlFetchWhitelist` to that origin with a trailing slash. The Script Property overrides the default URL in `Code.gs`.
6. Run `pnpm exec clasp push`. Review any manifest-overwrite prompt; the upload allowlist includes only `Code.gs` and `appsscript.json`.
7. In the Apps Script editor, select **Deploy > Test deployments**, choose the Google Workspace Add-on test deployment, and install it for the same Gmail account. Complete any Google authorization yourself.
8. Reload Gmail, open an email, open MailGuard from the side panel, and click **Analyze Email**. This is a test installation, not a public Marketplace release.

## Demo

Reload Gmail after code updates. Send synthetic test messages to yourself and analyze them without opening their links:

| Demo | Input | Expected |
|---|---|---|
| Benign urgency | Subject `Urgent`; body `Please review the slides immediately.` | Ordinarily 5/100, Low Risk, Low confidence; no links to check. |
| Credential phishing | Subject `URGENT: Verify your account immediately`; body `Your account will be suspended within 24 hours. Verify your identity immediately by signing in and confirming your password. Login here: http://192.0.2.1/login` | Heuristics: 67/100, Suspicious, Medium confidence. |
| Reputation match | Body containing `http://testsafebrowsing.appspot.com/s/phishing.html` | Live synthetic backend test: 72/100, High Risk; Google Safe Browsing top reason and attribution. |

Expand **Analysis details** to show how links are checked and the Link reputation status. Actual email headers, additional extracted links, and Google's current reputation data may change the final score. An unavailable status means the heuristic result still completed; it does not mean Google found no match.

## Tests and validation

Final suite: **77 passed** (58 backend, 19 Apps Script), with two dependency deprecation warnings and no failures. See [TEST_RESULTS.md](TEST_RESULTS.md).

Coverage includes eight calibration scenarios, authentication correlation, category caps, confidence independence, URL extraction, current-message access, API-key rejection, input limits, no content echo, all verdict cards, RTL text, reputation statuses, matches, no match, timeout, API errors, no URLs, 50-URL cap, deduplication, caching, and the live-format Protobuf fixture. Google is mocked in automated tests; the fixture contains only a synthetic test URL.

These tests verify behavior, not real-world detection accuracy. Previously completed live checks verified health 200, incorrect/missing shared key 401, reputation test match 72/100, no-match 0/100, and no-URL 0/100. Final packaging does not modify those deployed services.

## Limitations, trade-offs, and future improvements

- Hand-chosen weights and synthetic examples make the decision understandable, but are not a representative accuracy evaluation. Future work: a labeled corpus, precision/recall measurement, and false-positive review before adjusting weights.
- English phrase rules can match quotations or benign requests and miss context, other languages, or paraphrases. Future work: broader language coverage and quote-aware extraction.
- Supplied authentication headers are not independently verified; forwarding and forged headers can mislead. Full-domain matching does not resolve public suffixes or organizational relationships.
- URL parsing and the small Protobuf schema prioritize simplicity. Relative/obscure links and some lookalikes may be missed. Only 50 distinct links get reputation checks; very large GET requests can fail and fall back gracefully. Future work: broader schema/compatibility tests and privacy-preserving reputation lookups.
- Full-URL reputation checks improve known-threat detection but disclose URLs to Google. Cached results can be stale until expiry. No match never proves safety.
- Attachment scanning, destination-page inspection, automatic blocking, AI, and databases are out of scope. The application does not fetch linked sites.
- One shared API key is adequate for this demo, but not a multi-tenant product. Future work: per-user authentication, rate limiting, abuse controls, a retention policy, and a security review.
- Vercel Hobby keeps the assignment lightweight but has quotas and cold starts. Google Safe Browsing is non-commercial; commercialization requires reviewing terms and alternatives.
- CardService offers native Gmail integration but limits typography and layout. Collapsed detail keeps the main decision readable while preserving caveats.

References: [Safe Browsing v5 URL search](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search), [Google's usage and warning guidance](https://developers.google.com/safe-browsing/reference/Appropriate.Usage), [CardService](https://developers.google.com/apps-script/reference/card-service).
