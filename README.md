# aap-for-dev101-workshop

App & API Protection (AAP) demo assets layered on top of the
[`dd101-for-developers-one-track`](https://github.com/DataDog/learning-center/tree/main/workshops/dd101-for-developers-one-track)
workshop's Storedog lab.

The workshop ships an unmodified Storedog stack (Spree backend, Next.js
frontend, Flask `store-discounts`, Flask `store-ads`, Postgres, Redis).
Set `DD_APPSEC_ENABLED=true` and `DD_APPSEC_SCA_ENABLED=true`,
then drive attack traffic with the scripts below.

---

## Suggested run order for a workshop demo

```bash
# 1. enable AAP everywhere (one-time per lab boot) after editing the docker compose yaml
docker compose down
docker compose up -d

# 2. drive payload traffic — targeted, varied detection categories
TARGET=http://<lab-host-ip> ./storedog-aap-demo.sh
```

---

## `storedog-aap-demo.sh`

A curl-based attack generator that exercises the AAP rule set with a
range of payloads. Every function is self-contained — pick the demos
you want, or run all nine end-to-end.

**What it does** — 9 demo functions, one per AAP detection category:

| Function | Triggers | Target endpoint(s) |
|---|---|---|
| `scanner` | `attack_attempt.crawler` | `/` with sqlmap / Nikto / ZAP / Nmap / shellshock user-agents |
| `sqli` | `attack_attempt.sql_injection` | Spree `/search`, `/products`, Flask `/discount`, JSON body on `/api/v2/storefront/account` |
| `xss` | `attack_attempt.xss` | reflected `<script>`, `<svg onload>`, `<img onerror>` payloads on search/product params |
| `lfi` | `attack_attempt.lfi` | `../../../etc/passwd` variants on frontend, ads, discounts, plus `Referer: file://` |
| `cmdi` | `attack_attempt.command_injection` | `;id`, `\|cat`, `$(whoami)`, shellshock probe |
| `ato` | `business_logic.users.login.{failure,success}` | 15 password attempts on `/api/v2/storefront/account/login` |
| `apidisc` | API Catalog inventory | hits 8 Spree storefront/platform JSON APIs |
| `knownbad` | IP reputation rules | `X-Forwarded-For` spoof (swap RFC 5737 IPs for real threat-intel IPs to actually fire) |
| `bizlogic` | custom business-logic rules | discount-code enumeration on `store-discounts` |

**Usage**

```bash
# all demos
TARGET=http://<lab-host-ip> ./storedog-aap-demo.sh

# subset
TARGET=http://<lab-host-ip> ./storedog-aap-demo.sh sqli xss ato
```

**Configurable env vars**

- `TARGET` — base URL (default `http://localhost`)
- `FRONTEND` / `DISCOUNTS` / `ADS` — per-service URLs (default
  `$TARGET:3000` / `:5001` / `:5002`). Override if the lab
  fronts everything through nginx on a single port.

**Payload safety** — every payload is non-destructive: no `DROP TABLE`,
no real RCE, no shell execution against a writable target. Payloads are
crafted to trip detection rules, not damage the lab.

**Where to look in Datadog**

```
Security → App & API Protection → Signals
```

