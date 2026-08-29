#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  SETUP SATELLITE WORKER TRÊN SAMSUNG A51 (TERMUX)
#  Chạy 1 lần duy nhất để cài đặt môi trường
# ============================================================
set -e

echo "========================================="
echo "  SETUP SATELLITE - SAMSUNG A51 (TERMUX)"
echo "========================================="

# 1. Cập nhật Termux packages
echo "[1/6] Cập nhật Termux..."
pkg update -y && pkg upgrade -y

# 2. Cài Python + các dependencies hệ thống
echo "[2/6] Cài Python và build tools..."
pkg install -y python python-pip git openssh openssl libffi clang build-essential

# 3. Cài cloudflared (tunnel ra internet)
echo "[3/6] Cài cloudflared tunnel..."
pkg install -y cloudflared 2>/dev/null || {
    echo "cloudflared không có trong pkg, cài bằng pip/binary..."
    # Tải binary ARM64 cho Android
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        curl -L -o "$PREFIX/bin/cloudflared" \
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
        chmod +x "$PREFIX/bin/cloudflared"
    else
        echo "CẢNH BÁO: Kiến trúc $ARCH - thử cài cloudflared-linux-arm"
        curl -L -o "$PREFIX/bin/cloudflared" \
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
        chmod +x "$PREFIX/bin/cloudflared"
    fi
}

# 4. Cài Python packages
echo "[4/6] Cài Python packages..."
pip install --upgrade pip
pip install cryptography openpyxl

# 5. Clone repo (hoặc copy files)
echo "[5/6] Tạo thư mục project..."
PROJECT_DIR="$HOME/checkpass"
mkdir -p "$PROJECT_DIR"

echo "[6/6] Kiểm tra..."
python --version
cloudflared --version 2>/dev/null && echo "cloudflared OK" || echo "CẢNH BÁO: cloudflared chưa sẵn sàng"

echo ""
echo "========================================="
echo "  SETUP XONG!"
echo "========================================="
echo ""
echo "Tiếp theo:"
echo "  1. Copy các file Python vào $PROJECT_DIR"
echo "  2. Chỉnh config trong start_satellite.sh"
echo "  3. Chạy: bash start_satellite.sh"
echo ""
