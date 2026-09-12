# Submission audit

Checked 2026-09-12. The submission repository was built from an explicit file allowlist and initialized with an empty Git history. It has no commits or remotes yet and has not been published.

- No real credentials, API-key values, OAuth tokens, private keys, personal account addresses, or local machine paths were detected in the submission files.
- Existing local credential-bearing files were found outside this repository and excluded. They were neither copied nor staged. Keep the original working directory private.
- Checks combined known credential-value comparisons with patterns for Google/GitHub tokens, JWTs, private keys, and machine paths. Synthetic test keys and URL query strings are intentionally fake test data, not live credentials.
- Local clasp project links, OAuth sessions, environment files, Vercel project links, dependencies, caches, and machine-specific helpers are excluded by `.gitignore`.
- Backend application and test files are byte-identical to the working implementation. The only application-code removal is the unused Apps Script health diagnostic. No deployment or scoring behavior was changed.
- Stale deployment helpers, obsolete container configuration, accumulated status notes, local secret-copy helpers, and an outdated example response are omitted.
- The public backend URL, Google service URLs, and synthetic test URL are intentional public configuration/test data.
- The Protobuf fixture contains Google's response for its public synthetic phishing test URL; it contains no private email or key.

The scan covers this clean repository, not every private file on the developer's machine. Pattern checks cannot prove the absence of every possible secret; inspect the staged file list before publishing. No old Git history was imported, so there are no historical commits to clean.
