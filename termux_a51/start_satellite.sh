#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  KHỞI ĐỘNG SATELLITE WORKER + CLOUDFLARE TUNNEL
#  Chạy trên Samsung A51 Termux
# ============================================================
set -e

PROJECT_DIR="$HOME/checkpass"
cd "$PROJECT_DIR"

# ===================== CẤU HÌNH =====================

# URL của Master Server (đổi thành URL thực tế của bạn)
# Nếu master chạy trên Render: https://ten-app.onrender.com
# Nếu master chạy local PC: http://IP_PC:8761
export MASTER_URL="http://127.0.0.1:8761"

# Token bí mật (phải giống MASTER_TOKEN trên master)
export MASTER_TOKEN="your-secret-token-here"

# ID định danh cho vệ tinh này
export SATELLITE_ID="a51-$(hostname)"

# Số worker song song (A51 có 8 core, RAM 6GB)
# Garena TCP login nhẹ CPU, chủ yếu chờ network
export WORKERS=6

# Khoảng cách giữa 2 lần bắt đầu login (giây)
export START_GAP=2.0

# Timeout mỗi lần login (giây)
export TIMEOUT=20.0

# Thời gian thuê chunk (phút)
export LEASE_MINUTES=60

# Khoảng cách poll khi hết việc (giây)
export POLL_INTERVAL=10

# Port cho health check endpoint
export HEALTH_PORT=8765
export HEALTH_HOST="0.0.0.0"

# ===================== CHỐNG TẮT MÀN HÌNH =====================

# Giữ Termux hoạt động khi tắt màn hình
termux-wake-lock 2>/dev/null || true

# ===================== CHẠY =====================

echo "========================================="
echo "  SATELLITE WORKER - SAMSUNG A51"
echo "========================================="
echo "  Master URL : $MASTER_URL"
echo "  Satellite  : $SATELLITE_ID"
echo "  Workers    : $WORKERS"
echo "  Start Gap  : ${START_GAP}s"
echo "  Timeout    : ${TIMEOUT}s"
echo "========================================="
echo ""

# Chạy satellite worker
python satellite_worker.py
