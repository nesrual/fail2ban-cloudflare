# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Glue that makes [Fail2ban](https://www.fail2ban.org/) ban/unban IPs at the
Cloudflare edge (Cloudflare API V4, IP Access Rules) instead of only at the local
firewall. Deployed by copying its files into a Fail2ban install — there is no
build, package, or automated test suite. Handles IPv4 and IPv6.

## Architecture — the ban/unban flow

Four files chain together through Fail2ban's filter/action model:

1. **`nginx-roboo.conf`** (Fail2ban *filter*, → `filter.d/`) — `failregex = ^<HOST> .*$`
   matches the client IP as the first token of each line in an Nginx access log.
   It is meant to read a challenge log written by [Roboo](https://github.com/yuri-gushin/Roboo)
   (`/var/log/nginx/challenged.log`), so a match means "this IP was challenged".
   `<HOST>` matches IPv4 and IPv6 (nginx logs raw, unbracketed v6), so the filter
   needs no change for IPv6.

2. **`cloudflare.conf`** (Fail2ban *action*, → `action.d/`) — on `actionban`/
   `actionunban` it runs `ruby cloudflare_api_manager.rb ban|unban <ip>`. It passes
   only `<ip>`; the script derives the address family itself, so there is no
   `[Init?family=inet6]` branching here. `/path/to/ruby` and `/path/to/...rb` are
   edited per-deployment.

3. **`cloudflare_api_manager.rb`** (the API client) — called with `ban <ip>` or
   `unban <ip>`:
   - Derives the Cloudflare target from the address: single IPv4 → `ip`, single
     IPv6 → `ip6`, CIDR → `ip_range` (Cloudflare accepts only /16,/24 for v4 and
     /32,/48,/64 for v6). Values are normalized through `IPAddr` so ban and unban
     send an identical string.
   - `ban`: POSTs a `block` access rule. Treats a "duplicate rule" error as success.
   - `unban`: **GETs rules filtered by `configuration.value=<ip>` and deletes by
     the returned id.** There is NO local state file — unban discovers the rule id
     from Cloudflare. (The old `cb_ban.txt` approach is gone; do not reintroduce it.)
   - Exits non-zero with a message on any real error (so Fail2ban sees failures);
     retries 429/5xx with exponential backoff.

4. **`cloudflare.env.example`** — template for the credential/scope file.

## Configuration model (important)

Credentials do **not** live in the script. `cloudflare_api_manager.rb` loads
`/etc/fail2ban/cloudflare.env` (override via `CLOUDFLARE_ENV_FILE`), then lets real
environment variables override the file. Keys:

- `CLOUDFLARE_API_TOKEN` — preferred; sent as `Authorization: Bearer`. Falls back
  to `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` (legacy `X-Auth-*` global key) only
  if the token is unset.
- Endpoint scope: `CLOUDFLARE_ZONE_ID` → `/zones/{id}/...` (preferred, least
  privilege); else `CLOUDFLARE_ACCOUNT_ID` → `/accounts/{id}/...`; else the legacy
  `/user/firewall/access_rules/rules` (still works, no longer documented by Cloudflare).

When editing the script, keep it stdlib-only (no gems) and Ruby 2.4+ compatible.
Note `URI.encode` was removed in Ruby 3.0 — use `URI.encode_www_form` (as the code
now does); the pre-2026 version used `URI.encode` and crashed on modern Ruby.

## Testing a change

There is a dependency-free test suite (no gems/Bundler) that stubs `Net::HTTP`,
so it needs no network or credentials:

```sh
ruby test/cloudflare_api_manager_test.rb   # or: rake  (lint + test)
```

It covers `target_and_value` (v4/v6/CIDR targets, prefix limits, bad input),
`auth_headers`, `rules_path`, `load_config`, and the `ban`/`unban` request
building + response handling (including duplicate-tolerance and retry). The
`main(ARGV) if $PROGRAM_NAME == __FILE__` guard is what lets the script be
required without executing — keep it when refactoring. CI runs the suite across
Ruby versions via `.github/workflows/test.yml`.

End-to-end still needs a real (or throwaway) Cloudflare zone; ban then unban an IP
and confirm the rule appears/disappears under Security → WAF → Tools → IP Access
Rules.

## Deployment gotchas (see README for detail)

- Whitelist Cloudflare's own IP ranges in the jail `ignoreip`, or a Cloudflare
  edge IP can get banned (esp. when Nginx is behind Cloudflare without
  `ngx_http_realip_module`).
- **Roboo is effectively unmaintained** (Flash/SWF dead; `Math::Pari` hard to
  build). The challenge layer, not this glue, is the fragile part — the action
  works against any jail, not just Roboo.
