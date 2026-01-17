#!/bin/bash

REPORT_DIR="reports"
REPORT_FILE="$REPORT_DIR/system_report_$(date +%F_%H-%M).txt"

mkdir -p "$REPORT_DIR"

risk_label () {
    case "$1" in
        HIGH) echo "[HIGH RISK]" ;;
        MEDIUM) echo "[MEDIUM RISK]" ;;
        LOW) echo "[LOW RISK]" ;;
        *) echo "[INFO]" ;;
    esac
}

get_sshd_value () {
    # Reads a value from sshd_config, last occurrence wins
    # Usage: get_sshd_value "PermitRootLogin"
    local key="$1"
    local file="/etc/ssh/sshd_config"
    grep -Ei "^\s*${key}\s+" "$file" 2>/dev/null | awk '{print $2}' | tail -n 1
}

check_ssh_setting () {
    # Usage: check_ssh_setting "PermitRootLogin" "no" "HIGH"
    local key="$1"
    local safe="$2"
    local bad_risk="$3"
    local value

    value="$(get_sshd_value "$key")"

    if [ -z "$value" ]; then
        echo "$key: Not set → $(risk_label MEDIUM)"
        return
    fi

    if [ "$value" = "$safe" ]; then
        echo "$key: $value → $(risk_label LOW)"
    else
        echo "$key: $value → $(risk_label "$bad_risk")"
    fi
}

{
echo "=============================="
echo " SYSTEM SECURITY BASELINE"
echo "=============================="
echo "Date: $(date)"
echo ""

echo "=== HOSTNAME & OS ==="
hostnamectl
echo ""

echo "=== KERNEL VERSION ==="
uname -r
echo ""

echo "=== CPU INFO ==="
lscpu | head -10
echo ""

echo "=== MEMORY INFO ==="
free -h
echo ""

echo "=== DISK USAGE ==="
df -h
echo ""

echo "=== NETWORK INTERFACES ==="
ip a
echo ""

echo "=== FIREWALL STATUS (UFW) ==="
if command -v ufw >/dev/null 2>&1; then
    STATUS="$(sudo ufw status | head -n 1)"
    echo "$STATUS"

    if echo "$STATUS" | grep -qi inactive; then
        echo "Firewall Risk: $(risk_label MEDIUM) Firewall inactive"
    else
        echo "Firewall Risk: $(risk_label LOW) Firewall active"
    fi
else
    echo "UFW not installed"
    echo "Firewall Risk: $(risk_label MEDIUM) No firewall detected"
fi
echo ""

echo "=== SSH CONFIGURATION & HARDENING ==="
if command -v sshd >/dev/null 2>&1; then
    echo "SSH Server: Installed"

    if [ -f /etc/ssh/sshd_config ]; then
        check_ssh_setting "PermitRootLogin" "no" "HIGH"
        check_ssh_setting "PasswordAuthentication" "no" "MEDIUM"
        check_ssh_setting "MaxAuthTries" "3" "MEDIUM"

        # Extra info (no risk label, but useful)
        PORT="$(get_sshd_value "Port")"
        [ -n "$PORT" ] && echo "Port: $PORT → $(risk_label INFO)" || echo "Port: Not set → $(risk_label INFO)"

        LGT="$(get_sshd_value "LoginGraceTime")"
        [ -n "$LGT" ] && echo "LoginGraceTime: $LGT → $(risk_label INFO)" || echo "LoginGraceTime: Not set → $(risk_label INFO)"
    else
        echo "sshd_config not found → $(risk_label MEDIUM)"
    fi

    systemctl is-active ssh >/dev/null 2>&1 \
        && echo "SSH Service: Running → $(risk_label INFO)" \
        || echo "SSH Service: Not running → $(risk_label INFO)"
else
    echo "SSH Server: Not installed (Common in WSL) → $(risk_label LOW)"
fi
echo ""

echo "=== PASSWORD POLICY CHECKS ==="
MAX_DAYS="$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}' | tail -n 1)"
MIN_DAYS="$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}' | tail -n 1)"
WARN_AGE="$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs | awk '{print $2}' | tail -n 1)"

echo "PASS_MAX_DAYS: ${MAX_DAYS:-Not set}"
echo "PASS_MIN_DAYS: ${MIN_DAYS:-Not set}"
echo "PASS_WARN_AGE: ${WARN_AGE:-Not set}"

# Simple baseline (you can tune later)
if [ -n "$MAX_DAYS" ] && [ "$MAX_DAYS" -gt 90 ]; then
    echo "Password Aging Risk: $(risk_label MEDIUM) Passwords expire too slowly (recommended <= 90 days)"
else
    echo "Password Aging Risk: $(risk_label LOW)"
fi

echo ""
echo "--- User Password Expiry (current user) ---"
sudo chage -l "$USER" 2>/dev/null | sed 's/^/  /'
echo ""

echo "=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running
echo ""

echo "=== LOGGED-IN USERS ==="
who
echo ""

echo "=== ALL USER ACCOUNTS ==="
cut -d: -f1 /etc/passwd

} | tee "$REPORT_FILE"

echo ""
echo "Report saved to: $REPORT_FILE"

