#!/data/data/com.termux/files/usr/bin/bash
# CyberSec - flood honeypot from phone (Termux on Android)
# Usage: ./mobile-flood.sh PUBLIC_IP [PORT] [COUNT]
# Example: ./mobile-flood.sh 49.36.123.45 9999 25
#
# Install in Termux first: pkg install netcat-openbsd

HOST="${1:?Usage: $0 PUBLIC_IP [PORT] [COUNT]}"
PORT="${2:-9999}"
COUNT="${3:-25}"

echo "===== CyberSec Mobile ATTACK ====="
echo "  Target: $HOST:$PORT"
echo "  Flood:  $COUNT connections"
echo ""

OPEN=0
for p in 22 80 443 3389 8080 "$PORT"; do
  if nc -z -w2 "$HOST" "$p" 2>/dev/null; then
    echo "  Port $p OPEN"
    OPEN=$((OPEN + 1))
  fi
done
if [ "$OPEN" -eq 0 ]; then
  echo "  No ports open - check port forward on router (TCP $PORT -> laptop)"
  echo "  On host run: .\\scripts\\run.ps1 extern"
  exit 1
fi

echo ""
echo "  Flooding honeypot..."
OK=0
for i in $(seq 1 "$COUNT"); do
  if nc -w2 "$HOST" "$PORT" </dev/null >/dev/null 2>&1; then
    OK=$((OK + 1))
  fi
  sleep 0.05
done

echo "  $OK/$COUNT connections succeeded"
echo ""
echo "  Watch host dashboard: http://127.0.0.1:3000"
echo "  ATTACK COMPLETE"
