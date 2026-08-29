#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  KHỞI ĐỘNG MASTER SERVER + CLOUDFLARE TUNNEL
#  Biến A51 thành SERVER truy cập được từ internet
# ============================================================
set -e

PROJECT_DIR="$HOME/checkpass"
cd "$PROJECT_DIR"

# ===================== CẤU HÌNH =====================

# Port nội bộ cho master server
MASTER_PORT=8761

# Token bí mật - ĐỔI THÀNH GIÁ TRỊ RIÊNG CỦA BẠN
export MASTER_TOKEN="thay-doi-token-bi-mat-cua-ban"

# Database file
export MASTER_DB="$PROJECT_DIR/master.db"

# ===================== CHỐNG TẮT MÀN HÌNH =====================
termux-wake-lock 2>/dev/null || true

# ===================== CHẠY =====================

echo "========================================="
echo "  MASTER SERVER + TUNNEL - SAMSUNG A51"
echo "========================================="
echo ""

# Tạo file PID để quản lý process
PIDFILE_MASTER="$PROJECT_DIR/.master.pid"
PIDFILE_TUNNEL="$PROJECT_DIR/.tunnel.pid"

# Dọn process cũ nếu có
cleanup() {
    echo ""
    echo "[stop] Đang dừng..."
    [ -f "$PIDFILE_MASTER" ] && kill "$(cat $PIDFILE_MASTER)" 2>/dev/null; rm -f "$PIDFILE_MASTER"
    [ -f "$PIDFILE_TUNNEL" ] && kill "$(cat $PIDFILE_TUNNEL)" 2>/dev/null; rm -f "$PIDFILE_TUNNEL"
    termux-wake-unlock 2>/dev/null || true
    echo "[stop] Đã dừng tất cả."
    exit 0
}
trap cleanup INT TERM

# 1. Khởi động Master Server (background)
echo "[1/2] Khởi động Master Server trên port $MASTER_PORT..."
python master_server.py --port "$MASTER_PORT" --token "$MASTER_TOKEN" &
MASTER_PID=$!
echo $MASTER_PID > "$PIDFILE_MASTER"
echo "  Master PID: $MASTER_PID"

# Đợi master sẵn sàng
sleep 2

# 2. Khởi động Cloudflare Tunnel (tạo URL public miễn phí)
echo "[2/2] Khởi động Cloudflare Tunnel..."
echo "  Đang tạo tunnel tới localhost:$MASTER_PORT..."
echo ""

cloudflared tunnel --url "http://localhost:$MASTER_PORT" 2>&1 &
TUNNEL_PID=$!
echo $TUNNEL_PID > "$PIDFILE_TUNNEL"

echo ""
echo "========================================="
echo "  ĐỢI CLOUDFLARE TẠO URL..."
echo "  URL sẽ hiện dạng: https://xxx-yyy.trycloudflare.com"
echo ""
echo "  Dùng URL đó làm MASTER_URL cho satellite"
echo "  Ví dụ: export MASTER_URL=https://xxx-yyy.trycloudflare.com"
echo "========================================="
echo ""

# Đợi cho tới khi Ctrl+C
wait $MASTER_PID $TUNNEL_PID 2>/dev/null
