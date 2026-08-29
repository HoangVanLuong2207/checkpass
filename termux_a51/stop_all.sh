#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  DỪNG TẤT CẢ SERVICES
# ============================================================

echo "Đang dừng tất cả processes..."

# Kill by PID files
PROJECT_DIR="$HOME/checkpass"
for pidfile in "$PROJECT_DIR"/.*.pid; do
    [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null && rm -f "$pidfile"
done

# Kill by process name
pkill -f "master_server.py" 2>/dev/null || true
pkill -f "satellite_worker.py" 2>/dev/null || true
pkill -f "cloudflared tunnel" 2>/dev/null || true

# Release wake lock
termux-wake-unlock 2>/dev/null || true

echo "Đã dừng tất cả."
