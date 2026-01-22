#!/bin/bash
# =============================================================================
# CSRF/TOS Regression Test Script
# =============================================================================
# Tests production-hardened CSRF handling and TOS enforcement:
#   1. Missing CSRF + authenticated → redirect /tos?error=csrf (NOT /login)
#   2. Missing CSRF + unauthenticated → redirect /login?error=session_expired
#   3. Successful accept → sets tos_accepted_at + tos_version, allows /settings
#   4. Cannot bypass TOS by hitting /settings directly before acceptance
#
# NOTE: This script makes multiple login attempts. The server rate limits login
#       to 10 attempts per minute per IP. Running this script multiple times
#       in quick succession may trigger rate limiting and cause test failures.
#       Wait at least 60 seconds between test runs.
# =============================================================================

set -o pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
DB_PATH="${DB_PATH:-app.db}"
# Use a fixed path for cookie jar to avoid mktemp issues
COOKIE_JAR="/tmp/csrf_tos_test_cookies_$$"
TEST_EMAIL="${TEST_EMAIL:-admin@demo.local}"
TEST_PASSWORD="${TEST_PASSWORD:-Demo123!Admin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

cleanup() {
    rm -f "$COOKIE_JAR"
}
trap cleanup EXIT

log_pass() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    ((pass_count++))
}

log_fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    ((fail_count++))
}

log_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# -----------------------------------------------------------------------------
# Helper: Perform login and store session cookie
# -----------------------------------------------------------------------------
do_login() {
    log_info "Logging in as $TEST_EMAIL..."

    # Create fresh cookie file
    rm -f "$COOKIE_JAR"

    # POST login and save cookie
    login_response=$(curl -s -w "\n%{http_code}" -c "$COOKIE_JAR" \
        "$BASE_URL/login" \
        --data "email=$TEST_EMAIL&password=$TEST_PASSWORD")

    http_code=$(echo "$login_response" | tail -1)

    # Small sync delay to ensure file is written
    sleep 0.1

    # 302 = redirect to dashboard = successful login
    if [[ "$http_code" == "302" || "$http_code" == "200" ]]; then
        # Verify cookie was actually set
        if [[ -f "$COOKIE_JAR" ]] && grep -q "session" "$COOKIE_JAR" 2>/dev/null; then
            log_info "Login successful"
            return 0
        else
            log_fail "Login succeeded but no session cookie saved (HTTP $http_code)"
            return 1
        fi
    else
        log_fail "Login failed (HTTP $http_code)"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Helper: Reset TOS acceptance in database (requires sqlite3)
# -----------------------------------------------------------------------------
reset_tos() {
    log_info "Resetting TOS acceptance for test user..."
    sqlite3 "$DB_PATH" "UPDATE users SET tos_accepted_at = NULL, tos_version = NULL WHERE email = '$TEST_EMAIL';" 2>/dev/null || {
        log_info "(Warning: could not reset TOS in DB - test may produce unexpected results)"
    }
}

# -----------------------------------------------------------------------------
# Helper: Check TOS acceptance status in database
# -----------------------------------------------------------------------------
check_tos_db() {
    local result
    result=$(sqlite3 "$DB_PATH" "SELECT tos_version, tos_accepted_at FROM users WHERE email = '$TEST_EMAIL';" 2>/dev/null) || result=""
    echo "$result"
}

echo ""
echo "============================================================================="
echo " CSRF/TOS Regression Tests"
echo "============================================================================="
echo " Base URL: $BASE_URL"
echo " Test User: $TEST_EMAIL"
echo "============================================================================="
echo ""

# =============================================================================
# TEST 1: Missing CSRF + unauthenticated → redirect /login?error=session_expired
# =============================================================================
echo "--- TEST 1: Missing CSRF (unauthenticated) → /login?error=session_expired ---"

# Clear cookies for fresh unauthenticated state
rm -f "$COOKIE_JAR"

# POST to /tos without session (unauthenticated, no CSRF)
response=$(curl -s -o /dev/null -w "%{redirect_url}" \
    -X POST "$BASE_URL/tos" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Accept: text/html" \
    -d "")

if [[ "$response" == *"/login"* && "$response" == *"session_expired"* ]]; then
    log_pass "Unauthenticated CSRF failure redirects to /login?error=session_expired"
else
    log_fail "Expected redirect to /login?error=session_expired, got: $response"
fi

# =============================================================================
# TEST 2: Missing CSRF + authenticated → redirect /tos?error=csrf (NOT /login)
# =============================================================================
echo ""
echo "--- TEST 2: Missing CSRF (authenticated) → /tos?error=csrf ---"
sleep 0.5  # Small delay between tests

# Login first
reset_tos
do_login

# GET /tos to establish we're on the TOS page (sets referer context)
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/tos" > /dev/null

# POST to /tos with session but WITHOUT CSRF token
response=$(curl -s -o /dev/null -w "%{redirect_url}" \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/tos" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Accept: text/html" \
    -H "Referer: $BASE_URL/tos" \
    -d "")

if [[ "$response" == *"/tos"* && "$response" == *"error=csrf"* ]]; then
    log_pass "Authenticated CSRF failure redirects to /tos?error=csrf"
else
    log_fail "Expected redirect to /tos?error=csrf, got: $response"
fi

# Verify NOT redirecting to login (critical check)
if [[ "$response" != *"/login"* ]]; then
    log_pass "Authenticated CSRF failure does NOT redirect to /login"
else
    log_fail "Authenticated user was incorrectly redirected to /login"
fi

# =============================================================================
# TEST 3: Cannot bypass TOS by hitting /settings directly before acceptance
# =============================================================================
echo ""
echo "--- TEST 3: TOS bypass protection (/settings before acceptance) ---"
sleep 0.5

# Reset TOS and login fresh
reset_tos
do_login

# Try to access /settings directly (should redirect to /tos)
response=$(curl -s -o /dev/null -w "%{redirect_url}" \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    "$BASE_URL/settings" \
    -H "Accept: text/html")

if [[ "$response" == *"/tos"* ]]; then
    log_pass "User without TOS acceptance is redirected from /settings to /tos"
else
    log_fail "Expected redirect to /tos from /settings, got: $response"
fi

# =============================================================================
# TEST 4: Successful TOS accept → sets DB fields + allows /settings
# =============================================================================
echo ""
echo "--- TEST 4: Successful TOS acceptance flow ---"
sleep 0.5

# Reset TOS and login fresh
reset_tos
do_login

# Get CSRF token from /tos page
tos_page=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/tos")
# Extract CSRF token (macOS compatible)
csrf_token=$(echo "$tos_page" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -1)

if [[ -z "$csrf_token" ]]; then
    log_fail "Could not extract CSRF token from /tos page"
else
    log_info "Extracted CSRF token (length: ${#csrf_token})"

    # POST acceptance with valid CSRF token (don't follow redirects)
    accept_response=$(curl -s -w "\n%{http_code}" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        "$BASE_URL/tos" \
        --data "csrf_token=$csrf_token" \
        -H "Accept: text/html")

    http_code=$(echo "$accept_response" | tail -1)

    # TOS acceptance should redirect (302)
    if [[ "$http_code" == "302" ]]; then
        log_pass "TOS acceptance POST succeeded (HTTP 302 redirect)"
    elif [[ "$http_code" == "200" ]]; then
        log_pass "TOS acceptance POST succeeded (HTTP 200)"
    else
        log_fail "TOS acceptance POST failed (HTTP $http_code)"
    fi

    # Check database for tos_accepted_at and tos_version
    db_result=$(check_tos_db)

    if [[ -n "$db_result" ]]; then
        tos_version=$(echo "$db_result" | cut -d'|' -f1)
        tos_accepted=$(echo "$db_result" | cut -d'|' -f2)

        if [[ -n "$tos_version" && -n "$tos_accepted" ]]; then
            log_pass "Database updated: tos_version=$tos_version, tos_accepted_at=$tos_accepted"
        else
            log_fail "Database not updated properly: tos_version='$tos_version', tos_accepted_at='$tos_accepted'"
        fi
    else
        log_fail "Could not query database for TOS status"
    fi

    # Now try to access /settings - should succeed (follow redirects)
    settings_response=$(curl -s -w "\n%{http_code}" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        "$BASE_URL/settings" \
        -H "Accept: text/html" \
        -L)

    http_code=$(echo "$settings_response" | tail -1)

    # Check if we landed on settings page (200) or got redirected to TOS (would show tos content)
    if [[ "$http_code" == "200" ]] && echo "$settings_response" | grep -q "Settings"; then
        log_pass "After TOS acceptance, /settings is accessible (HTTP 200)"
    elif [[ "$http_code" == "200" ]]; then
        # Could be landing on TOS page instead
        if echo "$settings_response" | grep -q "Terms of Service"; then
            log_fail "After TOS acceptance, still redirected to TOS page"
        else
            log_pass "After TOS acceptance, page accessible (HTTP 200)"
        fi
    else
        log_fail "After TOS acceptance, /settings returned HTTP $http_code"
    fi
fi

# =============================================================================
# TEST 5: Wrong CSRF token → redirect /tos?error=csrf
# =============================================================================
echo ""
echo "--- TEST 5: Wrong CSRF token (authenticated) → /tos?error=csrf ---"
sleep 0.5

reset_tos
do_login

# Get the TOS page to establish CSRF (read cookie from login)
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$BASE_URL/tos" > /dev/null

# POST with a wrong CSRF token
response=$(curl -s -o /dev/null -w "%{redirect_url}" \
    -b "$COOKIE_JAR" \
    "$BASE_URL/tos" \
    --data "csrf_token=INVALID_TOKEN_12345" \
    -H "Accept: text/html" \
    -H "Referer: $BASE_URL/tos")

if [[ "$response" == *"/tos"* && "$response" == *"error=csrf"* ]]; then
    log_pass "Wrong CSRF token redirects to /tos?error=csrf"
else
    log_fail "Expected redirect to /tos?error=csrf, got: $response"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================================================="
echo " RESULTS"
echo "============================================================================="
echo -e " ${GREEN}Passed:${NC} $pass_count"
echo -e " ${RED}Failed:${NC} $fail_count"
echo "============================================================================="

if [[ $fail_count -gt 0 ]]; then
    exit 1
else
    exit 0
fi
