#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  KIỂM TRA TRẠNG THÁI SERVICES
# ============================================================

echo "========================================="
echo "  TRẠNG THÁI SERVICES"
echo "========================================="

# Check master
if pgrep -f "master_server.py" > /dev/null 2>&1; then
    echo "✅ Master Server  : ĐANG CHẠY (PID: $(pgrep -f master_server.py))"
else
    echo "❌ Master Server  : KHÔNG CHẠY"
fi

# Check satellite
if pgrep -f "satellite_worker.py" > /dev/null 2>&1; then
    echo "✅ Satellite Worker: ĐANG CHẠY (PID: $(pgrep -f satellite_worker.py))"
else
    echo "❌ Satellite Worker: KHÔNG CHẠY"
fi

# Check cloudflared
if pgrep -f "cloudflared" > /dev/null 2>&1; then
    echo "✅ Cloudflare Tunnel: ĐANG CHẠY (PID: $(pgrep -f cloudflared))"
else
    echo "❌ Cloudflare Tunnel: KHÔNG CHẠY"
fi

echo ""

# Check health endpoint
echo "--- Health Check ---"
curl -s http://127.0.0.1:8761/healthz -H "Authorization: Bearer ${MASTER_TOKEN:-no-token}" 2>/dev/null | python -m json.tool 2>/dev/null || echo "Master không phản hồi"
echo ""
curl -s http://127.0.0.1:8765/ 2>/dev/null | python -m json.tool 2>/dev/null || echo "Satellite health không phản hồi"

echo ""
echo "--- Tài nguyên ---"
echo "RAM: $(free -h 2>/dev/null | head -2 || echo 'N/A')"
echo "CPU: $(cat /proc/loadavg 2>/dev/null || echo 'N/A')"
echo "Disk: $(df -h ~ 2>/dev/null | tail -1 || echo 'N/A')"
