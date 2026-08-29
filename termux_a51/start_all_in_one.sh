#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  CHẠY CẢ MASTER + SATELLITE CÙNG LÚC TRÊN 1 ĐIỆN THOẠI
#  + Cloudflare tunnel để truy cập từ internet
# ============================================================
set -e

PROJECT_DIR="$HOME/checkpass"
cd "$PROJECT_DIR"

# ===================== CẤU HÌNH =====================

MASTER_PORT=8761
export MASTER_TOKEN="thay-doi-token-bi-mat-cua-ban"
export MASTER_DB="$PROJECT_DIR/master.db"

# Satellite config
export MASTER_URL="http://127.0.0.1:$MASTER_PORT"
export SATELLITE_ID="a51-local"
export WORKERS=4
export START_GAP=3.0
export TIMEOUT=20.0
export LEASE_MINUTES=60
export POLL_INTERVAL=10
export HEALTH_PORT=8765

# ===================== CHỐNG TẮT MÀN HÌNH =====================
termux-wake-lock 2>/dev/null || true

cleanup() {
    echo ""
    echo "[stop] Đang dừng tất cả..."
    jobs -p | xargs kill 2>/dev/null || true
    termux-wake-unlock 2>/dev/null || true
    echo "[stop] Đã dừng."
    exit 0
}
trap cleanup INT TERM

echo "========================================="
echo "  ALL-IN-ONE: MASTER + SATELLITE + TUNNEL"
echo "  Samsung A51"
echo "========================================="
echo ""

# 1. Master Server
echo "[1/3] Master Server (port $MASTER_PORT)..."
python master_server.py --port "$MASTER_PORT" --token "$MASTER_TOKEN" &
sleep 2

# 2. Satellite Worker
echo "[2/3] Satellite Worker ($WORKERS workers)..."
python satellite_worker.py &
sleep 1

# 3. Cloudflare Tunnel
echo "[3/3] Cloudflare Tunnel..."
echo ""
cloudflared tunnel --url "http://localhost:$MASTER_PORT" 2>&1 &

echo ""
echo "========================================="
echo "  TẤT CẢ ĐÃ KHỞI ĐỘNG!"
echo "  Nhấn Ctrl+C để dừng"
echo "========================================="
echo ""

# Đợi
wait
