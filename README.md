# MAC'LAY Workspace

Free, open-source online code editor with accounts, saved snippets, an AI assistant and an owner dashboard.
One small Node.js server, a built-in SQLite database, **no npm packages to install**.

## Run it

You need **Node.js 22.13 or newer**.

```bash
npm start                     # http://localhost:3000
```

1. Open the site and create an account.
2. Make yourself the owner (gives you the ⚙ dashboard button):
   ```bash
   node server.js --make-owner you@example.com
   ```
3. Reload the page.

Your data lives in `data/maclay.db`. Back that folder up.

## Settings (`.env`)

Copy `.env.example` to `.env`. Everything is optional.

| Variable | What it does |
|---|---|
| `PORT` | Port to listen on (default 3000) |
| `DATA_DIR` | Where the database is stored. Point it at a persistent disk when hosting |
| `PRODUCTION=1` | Use when served over HTTPS. Makes cookies `Secure`, enables HSTS, disables dev auto-owner |
| `TRUST_PROXY=1` | Behind a reverse proxy (Railway, Render, nginx…): use `X-Forwarded-For` for the real visitor IP |
| `ANTHROPIC_API_KEY` | Turns on MAC AI. The key stays on the server |
| `AI_DAILY_LIMIT` | AI messages per user per day (default 40; owners are exempt) |
| `AI_MODELS` | Comma-separated model IDs the page may request. Update if Anthropic retires one |
| `JUDGE0_URL`, `JUDGE0_API_KEY`, `JUDGE0_API_HOST` | Turns on C / C++ / Java / PHP / Bash / SQL execution via Judge0 |
| `OWNER_EMAIL` | Local development only: the first sign-up with this email becomes owner |

JavaScript, Python and HTML always run in the visitor's own browser.

## What is protected

- Passwords: scrypt with a random salt per user; never stored or logged in plain text.
- Sessions: random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie; only its hash is stored. Password change signs out other devices. Suspending a user ends their sessions immediately.
- CSRF: every write needs a custom header and a same-site `Origin`.
- Brute force: per-IP rate limits, plus a 15-minute lock after 5 wrong passwords on one email.
- Owner dashboard: role is checked **on the server for every admin request** (non-owners get a 404). Destructive actions ask for the owner's password again.
- Data: users can only read and change their own snippets; 100 KB per snippet, 2 MB and 200 snippets per user.
- Output: user-supplied text is escaped before it is shown; AI replies are escaped too.
- Headers: Content-Security-Policy, `frame-ancestors 'none'`, `nosniff`, HSTS in production.
- Static files are served only from `public/` (path traversal blocked).

## Known limits (be honest with your users)

- **No email verification and no "forgot password" email.** Reset a password with
  `node server.js --reset-password you@example.com NewPassword123`.
- Rate-limit counters live in memory, so they reset when the server restarts and are per-instance.
- The Content-Security-Policy has to allow inline scripts and `eval`, because the editor runs the visitor's own code and the page uses inline handlers. Code that a visitor runs executes in their browser with their own session, so **don't run code you don't trust**.
- Analytics count a visitor by a daily-rotating hash of IP + browser; no cookies, no raw IPs stored, no location.
- One SQLite file is plenty for thousands of users, but it means one server instance.

## Tests

```bash
npm test      # 33 checks: accounts, snippets, quota, CSRF, owner permissions, sessions
```

## Layout

```
server.js        API + static server + CLI
public/index.html  the whole front end
test/api.test.js
data/            created at first run (database)
```

MIT licensed.
