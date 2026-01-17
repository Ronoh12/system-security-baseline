#!/bin/bash

REPORT_DIR="reports"
REPORT_FILE="$REPORT_DIR/system_report_$(date +%F_%H-%M).txt"

mkdir -p "$REPORT_DIR"

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
    sudo ufw status
else
    echo "UFW not installed"
fi
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

