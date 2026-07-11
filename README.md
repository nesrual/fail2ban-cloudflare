# fail2ban-cloudflare — for Cloudflare API V4

Block abusive clients at **Cloudflare's edge** using [Fail2ban](https://www.fail2ban.org/),
instead of only at your own firewall. When a client trips a Fail2ban jail, this
project adds a Cloudflare **IP Access Rule** so the client is challenged/blocked
by Cloudflare before it ever reaches your server — and removes the rule again
when the ban expires.

It ships with a filter for [Roboo](https://github.com/yuri-gushin/Roboo) (an
Nginx HTTP-flood challenge layer), but the Cloudflare action works with **any**
Fail2ban jail. **IPv4 and IPv6 are both supported.**

---

## Table of contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Step 1 — The challenge layer (Nginx + Roboo)](#step-1--the-challenge-layer-nginx--roboo)
  - [Step 2 — Create a Cloudflare API token](#step-2--create-a-cloudflare-api-token)
  - [Step 3 — Store credentials outside the script](#step-3--store-credentials-outside-the-script)
  - [Step 4 — Install the manager script](#step-4--install-the-manager-script)
  - [Step 5 — Install the Fail2ban filter, action, and jail](#step-5--install-the-fail2ban-filter-action-and-jail)
  - [Step 6 — Verify end to end](#step-6--verify-end-to-end)
- [Configuration reference](#configuration-reference)
- [How an IP maps to a Cloudflare rule](#how-an-ip-maps-to-a-cloudflare-rule)
- [IPv6](#ipv6)
- [Whitelisting Cloudflare's own IPs](#whitelisting-cloudflares-own-ips)
- [Troubleshooting](#troubleshooting)
- [Alternatives to Roboo](#alternatives-to-roboo)
- [Development and tests](#development-and-tests)
- [Security notes](#security-notes)

---

## How it works

The moving parts form a pipeline. Each stage hands off to the next:

```
                      ┌──────────────────────────────────────────────┐
   attacker           │                  your server                 │
   ───────►  Cloudflare edge  ───────►  Nginx + Roboo                 │
             (challenge/block)          │   │                        │
                    ▲                   │   └─ writes challenged.log ─┼──┐
                    │                   └────────────────────────────┘  │
                    │                                                    ▼
                    │                              Fail2ban  ◄── nginx-roboo.conf (filter)
                    │                                 │          counts challenge lines per IP
                    │                                 │          maxretry reached → ban
                    │                                 ▼
                    │                          cloudflare.conf (action)
                    │                                 │  runs: ruby cloudflare_api_manager.rb ban <ip>
                    │                                 ▼
                    └───────  Cloudflare API V4  ◄── cloudflare_api_manager.rb
                              (IP Access Rules)       adds/removes the block rule
```

1. **Nginx + Roboo** present a JavaScript challenge to clients. A client that
   solves it is proxied to your app; one that keeps getting challenged is,
   almost always, a bot. Roboo itself writes no log — you point an Nginx
   `access_log` at `challenged.log` so every *challenge* is recorded there, with
   the client IP as the first field of the line.

2. **Fail2ban** watches `challenged.log`. The bundled **filter**
   (`nginx-roboo.conf`) matches every line and extracts the client IP. When one
   IP accumulates more than `maxretry` challenge lines within the jail's window,
   Fail2ban bans it.

3. On ban, Fail2ban runs the **action** (`cloudflare.conf`), which invokes the
   **manager script** (`cloudflare_api_manager.rb`) with `ban <ip>`. On unban (or
   when `bantime` expires) it runs the same script with `unban <ip>`.

4. The **manager script** calls the **Cloudflare API V4** to create a `block`
   IP Access Rule for that address (or delete it on unban). From then on
   Cloudflare handles the client at the edge, taking the load off your server.

### Banning and unbanning are stateless

The script keeps **no local database of bans**. On `ban` it creates a rule; on
`unban` it asks Cloudflare *"which block rule matches this IP?"* (a filtered
`GET`) and deletes the one it finds. This means:

- Nothing to corrupt, lock, or grow without bound.
- You can `unban` an IP that was banned by a different machine or by hand in the
  dashboard.
- Ban and unban always agree on the address, because the script normalizes it
  the same way both times.

---

## Repository layout

| File | Role | Installed to |
|------|------|--------------|
| `cloudflare_api_manager.rb` | Ruby client that calls the Cloudflare API to ban/unban | anywhere the Fail2ban user can run it |
| `cloudflare.conf` | Fail2ban **action**: runs the script on ban/unban | Fail2ban `action.d/` |
| `nginx-roboo.conf` | Fail2ban **filter**: matches Roboo challenge-log lines | Fail2ban `filter.d/` |
| `cloudflare.env.example` | Template for the credentials/scope file | copy to `/etc/fail2ban/cloudflare.env` |
| `test/`, `Rakefile` | Test suite (no external gems) | dev only |

---

## Requirements

- **Fail2ban 0.10 or later** — 0.10 (2017) is the first release with IPv6
  support; current stable is 1.1.x. IPv4-only setups work on older versions too.
- **Ruby 2.4 or later** — the script uses only the standard library (no gems,
  no `bundle install`).
- **A Cloudflare account** with your site(s) proxied through Cloudflare (orange
  cloud), and the **Zone ID** of each site you want to protect.
- **A challenge/attack source that produces log lines** — the bundled filter
  expects a Roboo challenge log, but you can point the `cloudflare` action at any
  jail (e.g. `sshd`, `nginx-limit-req`) and skip Roboo entirely.

---

## Installation

> If you only want edge-banning for an existing jail (say `sshd`) and don't need
> Roboo, **skip Step 1** and in Step 5 set `banaction = cloudflare` on that jail.

### Step 1 — The challenge layer (Nginx + Roboo)

> ⚠️ **Roboo is effectively unmaintained.** It was last meaningfully updated
> years ago, its default **SWF/Flash** challenge is dead (Flash EOL 2020, so use
> the `JS` mode), and one of its Perl dependencies (`Math::Pari`) is notoriously
> hard to build on modern toolchains. If you can get it running, it works; if you
> can't, see [Alternatives to Roboo](#alternatives-to-roboo) — the rest of this
> project does not depend on Roboo specifically, only on a log of "this IP was
> challenged" lines.

Roboo is an embedded-Perl handler for Nginx. Getting it running requires three
things: an Nginx built with the Perl module, Roboo's Perl dependencies, and an
Nginx config that runs the handler and logs challenges.

**1a. Build/verify Nginx with the embedded Perl module.** Roboo runs as
`perl Roboo::handler;`, which needs `ngx_http_perl_module`. Check with:

```sh
nginx -V 2>&1 | tr ' ' '\n' | grep -i perl      # look for --with-http_perl_module
```

If it's missing, install a package that includes it (Debian/Ubuntu:
`nginx-extras`) or compile Nginx with `--with-http_perl_module`.

**1b. Install Roboo's Perl dependencies:**

```sh
# Debian/Ubuntu package names shown; CPAN equivalents in parentheses
sudo apt-get install libcrypt-random-perl \
                     libmath-pari-perl \
                     libnet-ip-perl
# (CPAN: Crypt::Random, Math::Pari, Net::IP::Match::Regexp)
```

**1c. Install `Roboo.pm`** from the [Roboo repo](https://github.com/yuri-gushin/Roboo)
into a directory on Nginx's Perl path and require it:

```nginx
# in the http { } block
perl_modules /etc/nginx/perl/lib;    # directory containing Roboo.pm
perl_require Roboo.pm;
```

**1d. Configure the challenge and the log Fail2ban will read.** The key line is
the `access_log` inside the Roboo `location` block — *that* file is what the
Fail2ban filter watches. Based on Roboo's own
[`nginx.conf-example`](https://github.com/yuri-gushin/Roboo/blob/master/nginx.conf-example):

```nginx
server {
    listen 80;
    server_name www.example.com;
    access_log /dev/null;                       # server default: log nothing

    location / {
        perl Roboo::handler;                    # run the challenge on every request
        set $Roboo_challenge_modes "JS,gzip";   # use JS — SWF/Flash is dead

        error_page 555 = @proxy;                # already-verified clients -> backend

        # >>> THIS is the file Fail2ban reads <<<
        access_log /var/log/nginx/challenged.log;
    }

    location @proxy {
        proxy_pass http://127.0.0.1:8080;       # your real app
        access_log /var/log/nginx/verified.log;
    }
}
```

How it works: `location /` runs Roboo on every request. A client that already
holds a valid challenge cookie causes the handler to return **555**, which
`error_page 555 = @proxy` reroutes to your backend (logged to `verified.log`). A
client without a valid cookie is served the challenge and logged to
`challenged.log`. So a line in `challenged.log` genuinely means "this IP was
(re)challenged", which is exactly what the jail counts.

**1e. Reload and confirm the log fills up:**

```sh
sudo nginx -t && sudo systemctl reload nginx
curl -s http://www.example.com/ >/dev/null      # a cookie-less request = a challenge
tail -f /var/log/nginx/challenged.log           # you should see your IP appear
```

**1f. If Nginx sits *behind* Cloudflare**, `$remote_addr` is Cloudflare's edge IP,
not the real client — so you'd log and ban Cloudflare. Restore the real client IP
with the realip module:

```nginx
# http { } block — fetch current ranges from https://www.cloudflare.com/ips/
set_real_ip_from 173.245.48.0/20;
# ... (all Cloudflare IPv4 and IPv6 ranges) ...
real_ip_header CF-Connecting-IP;
```

### Step 2 — Create a Cloudflare API token

Prefer a **scoped API token** over the legacy global key (which grants full
account access).

1. Go to **https://dash.cloudflare.com/profile/api-tokens → Create Token → Create Custom Token**.
2. Permission: **Zone → Firewall Services → Edit**.
3. Zone Resources: restrict to the specific zone(s) you're protecting.
4. Create the token and copy it.
5. Copy each zone's **Zone ID** from that zone's **Overview** page in the dashboard.

> The legacy global key (account email + `X-Auth-Key`) still works as a fallback,
> but a token is strongly preferred — see [Security notes](#security-notes).

### Step 3 — Store credentials outside the script

Credentials do **not** live in the script anymore. Put them in a root-only env
file, which the script auto-loads:

```sh
sudo install -m 0600 -o root -g root cloudflare.env.example /etc/fail2ban/cloudflare.env
sudo editor /etc/fail2ban/cloudflare.env
```

Set at least:

```sh
CLOUDFLARE_API_TOKEN=your_token_here
CLOUDFLARE_ZONE_ID=your_zone_id_here
```

The default path is `/etc/fail2ban/cloudflare.env`; override it with the
`CLOUDFLARE_ENV_FILE` environment variable. Real environment variables take
precedence over the file, which is handy for one-off manual runs. See
[Configuration reference](#configuration-reference) for every option.

### Step 4 — Install the manager script

Put `cloudflare_api_manager.rb` somewhere the Fail2ban user (usually `root`) can
execute, and make sure Ruby is installed:

```sh
sudo install -m 0755 cloudflare_api_manager.rb /usr/local/bin/cloudflare_api_manager.rb
ruby --version    # must be 2.4+
```

### Step 5 — Install the Fail2ban filter, action, and jail

**5a. Filter** — copy into `filter.d/`:

```sh
sudo install -m 0644 nginx-roboo.conf /etc/fail2ban/filter.d/nginx-roboo.conf
```

**5b. Action** — copy into `action.d/` and fix the two `/path/to` placeholders so
they point at your `ruby` binary and the installed script:

```sh
sudo install -m 0644 cloudflare.conf /etc/fail2ban/action.d/cloudflare.conf
sudo editor /etc/fail2ban/action.d/cloudflare.conf
#   actionban   = /usr/bin/ruby /usr/local/bin/cloudflare_api_manager.rb ban <ip>
#   actionunban = /usr/bin/ruby /usr/local/bin/cloudflare_api_manager.rb unban <ip>
```

**5c. Jail** — add to `/etc/fail2ban/jail.local` (preferred over editing
`jail.conf`, which package upgrades overwrite):

```ini
[nginx-roboo]
enabled   = true
port      = all
filter    = nginx-roboo
banaction = cloudflare
logpath   = /var/log/nginx/challenged.log
maxretry  = 250
bantime   = 3600
findtime  = 600
# don't ban Cloudflare's own edge IPs (see the whitelisting section)
ignoreip  = 127.0.0.1/8 ::1
```

This watches `challenged.log`; any IP with more than `maxretry` (250) challenge
lines within `findtime` (600s) is blocked at Cloudflare for `bantime` (3600s),
then automatically unbanned.

### Step 6 — Verify end to end

Before trusting the jail, exercise the script by hand:

```sh
# create a block rule (prints the new rule id)
ruby /usr/local/bin/cloudflare_api_manager.rb ban 203.0.113.10

# IPv6 works too (uses the ip6 target automatically)
ruby /usr/local/bin/cloudflare_api_manager.rb ban 2001:db8::1

# find the rule by IP and delete it (no local state involved)
ruby /usr/local/bin/cloudflare_api_manager.rb unban 203.0.113.10
```

Confirm in the dashboard under **Security → WAF → Tools → IP Access Rules** that
the rule appears and then disappears. On any failure the script prints a message
and exits non-zero, so Fail2ban records the problem in its log.

Then reload Fail2ban and watch it:

```sh
sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-roboo      # shows currently banned IPs
sudo tail -f /var/log/fail2ban.log
```

---

## Configuration reference

All settings are read from the environment, seeded from the env file (default
`/etc/fail2ban/cloudflare.env`, override with `CLOUDFLARE_ENV_FILE`). Real
environment variables override the file.

| Variable | Purpose |
|----------|---------|
| `CLOUDFLARE_API_TOKEN` | **Preferred** auth. Sent as `Authorization: Bearer`. Needs *Zone → Firewall Services → Edit* (or account-level *Firewall Access Rules → Edit*). |
| `CLOUDFLARE_ZONE_ID` | Apply rules to this zone → `/zones/{id}/...`. **Recommended, least-privilege scope.** |
| `CLOUDFLARE_ACCOUNT_ID` | Used only if `CLOUDFLARE_ZONE_ID` is unset. Applies rules account-wide → `/accounts/{id}/...`. |
| `CLOUDFLARE_EMAIL` | Legacy fallback (used only if `CLOUDFLARE_API_TOKEN` is unset). Sent as `X-Auth-Email`. |
| `CLOUDFLARE_API_KEY` | Legacy global key, paired with `CLOUDFLARE_EMAIL`. Sent as `X-Auth-Key`. |
| `CLOUDFLARE_ENV_FILE` | Override the env-file path (default `/etc/fail2ban/cloudflare.env`). |

**Scope precedence:** `CLOUDFLARE_ZONE_ID` → `CLOUDFLARE_ACCOUNT_ID` → legacy
user-level endpoint (`/user/firewall/access_rules/rules`, still works but no
longer documented by Cloudflare).

**Auth precedence:** `CLOUDFLARE_API_TOKEN` → `CLOUDFLARE_EMAIL` +
`CLOUDFLARE_API_KEY`. If neither is present the script exits with an error.

---

## How an IP maps to a Cloudflare rule

The script inspects the address you give it and picks the correct Cloudflare
`configuration.target` automatically:

| Input | Cloudflare target | Example value |
|-------|-------------------|---------------|
| Single IPv4 | `ip` | `203.0.113.10` |
| Single IPv6 | `ip6` | `2001:db8::1` |
| IPv4 CIDR | `ip_range` | `192.0.2.0/24` |
| IPv6 CIDR | `ip_range` | `2001:db8::/64` |

**CIDR prefix limits** (Cloudflare only accepts these): IPv4 **/16** and **/24**;
IPv6 **/32**, **/48**, **/64**. Any other prefix is rejected with a clear error.
Single addresses (the normal Fail2ban case) are unaffected. IPv6 values are
normalized (lowercase, compressed) so a ban and a later unban always match.

Every rule is created with `mode: block` and a `notes` field tagging it as
added by Fail2ban.

---

## IPv6

IPv6 is fully supported. Nothing special is required beyond an IPv6-capable host:

- **Fail2ban** has handled IPv6 since 0.10 (2017) and passes the bare v6 address
  to the action. With the default `allowipv6 = auto` in `fail2ban.conf`, it's
  enabled automatically when the host has IPv6.
- **The filter** already matches IPv6 — Nginx logs the raw v6 address (no
  brackets) as the first token, and `^<HOST>` captures both families.
- **The script** sends IPv6 addresses with the `ip6` target (and `ip_range` for
  IPv6 CIDRs), which is what the Cloudflare API requires.

The old advice to "disable IPv6" no longer applies and has been removed.

---

## Whitelisting Cloudflare's own IPs

When Nginx sits behind Cloudflare, be careful not to ban Cloudflare's edge:

- **Best fix:** configure `ngx_http_realip_module` (Step 1f) so logs contain the
  real client IP, not Cloudflare's.
- **Belt and braces:** add Cloudflare's ranges to the jail's `ignoreip`. Current
  lists live at **https://www.cloudflare.com/ips/** (both IPv4 and IPv6).

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `no credentials found` | The env file isn't at `/etc/fail2ban/cloudflare.env` (or `CLOUDFLARE_ENV_FILE` isn't set), or `CLOUDFLARE_API_TOKEN` is empty. |
| Ban prints an authorization / permission error | Token lacks *Firewall Services → Edit*, or the wrong `CLOUDFLARE_ZONE_ID`. |
| `invalid IP address` | The value passed wasn't a valid IP/CIDR — check the log format and filter. |
| `Cloudflare accepts only /16, /24 ...` | You tried to ban a CIDR with an unsupported prefix; use an allowed one or a single IP. |
| Fail2ban bans nothing | `challenged.log` isn't filling (the `access_log` line is missing from the Roboo `location`), or `maxretry` is too high for your traffic. Test with `fail2ban-regex /var/log/nginx/challenged.log /etc/fail2ban/filter.d/nginx-roboo.conf`. |
| Cloudflare's own IPs get banned | Real-IP not configured — see [Whitelisting Cloudflare's own IPs](#whitelisting-cloudflares-own-ips). |
| Ban works by hand but not from Fail2ban | The `/path/to` placeholders in `cloudflare.conf` are wrong, or the Fail2ban user can't read the env file / execute the script. Check `/var/log/fail2ban.log`. |
| `429 Too Many Requests` in output | You hit Cloudflare's API limit (~1,200 requests / 5 min per user). The script retries with backoff; if it persists, reduce ban churn or use a WAF IP List (see below). |

Handy commands:

```sh
fail2ban-client status nginx-roboo                     # current bans
fail2ban-client set nginx-roboo unbanip 203.0.113.10   # manual unban
fail2ban-regex /var/log/nginx/challenged.log \
               /etc/fail2ban/filter.d/nginx-roboo.conf # test the filter
```

---

## Alternatives to Roboo

Roboo is the historical front-end for this project but is no longer maintained.
Because the `cloudflare` action only needs a jail that produces ban-worthy log
lines, you have options:

- **Use Cloudflare's own challenge** (Managed Challenge / Turnstile) at the edge
  and point the `cloudflare` action at a different jail (e.g. `nginx-limit-req`,
  `nginx-botsearch`, `sshd`). Often the simplest modern setup.
- **Native Nginx rate limiting** (`limit_req`, `limit_conn`) writing to a log a
  custom filter matches — no Perl module required.
- **SEnginx**'s "HTTP Robot Mitigation" — the closest maintained descendant of
  Roboo's technique.

For high ban volumes, consider maintaining a **WAF IP List** plus a single custom
rule instead of one IP Access Rule per address — it scales better against
Cloudflare's per-user API rate limit. This script currently uses IP Access Rules,
which are the simplest primitive and ideal for typical Fail2ban volumes.

---

## Development and tests

The test suite is dependency-free (no gems, no Bundler) and runs on any Ruby the
script supports:

```sh
ruby test/cloudflare_api_manager_test.rb    # run the tests directly
rake                                        # syntax-check + tests
rake test                                   # tests only
rake lint                                   # ruby -c on the script
```

Tests stub `Net::HTTP`, so they need no network and no Cloudflare credentials.
CI runs them across several Ruby versions (see `.github/workflows/test.yml`).
The script exposes its logic as small functions and only runs `main` when invoked
directly, which is what makes it unit-testable.

---

## Security notes

- **Credentials live in `/etc/fail2ban/cloudflare.env` (mode 0600, root-owned),
  not in the script.** Keep it that way — the script is world-readable by design.
- **Prefer an API token scoped to a single zone with only
  *Firewall Services → Edit*.** The legacy global key can do anything on your
  account; if it leaks, so does everything. Tokens can be scoped and revoked
  independently.
- **The script verifies TLS** (default `VERIFY_PEER`) and never disables it.
- **Failures are loud:** any real error prints a message and exits non-zero, so a
  silently-failed ban shows up in the Fail2ban log rather than passing unnoticed.
```
