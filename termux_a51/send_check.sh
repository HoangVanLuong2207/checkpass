#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  GỬI ACC CHECK NHANH TỪ TERMINAL
#  Dùng: bash send_check.sh "user1|pass1
#         user2|pass2"
#  Hoặc: bash send_check.sh accounts.txt
# ============================================================

MASTER_URL="${MASTER_URL:-http://127.0.0.1:8761}"
TOKEN="${MASTER_TOKEN:-thay-doi-token-bi-mat-cua-ban}"

if [ -z "$1" ]; then
    echo "Cách dùng:"
    echo '  bash send_check.sh "user1|pass1'
    echo '  user2|pass2"'
    echo ""
    echo "  bash send_check.sh accounts.txt"
    echo ""
    echo "  bash send_check.sh accounts.txt https://xxx.trycloudflare.com"
    exit 1
fi

# Nếu tham số 2 là URL thì dùng nó
[ -n "$2" ] && MASTER_URL="$2"

# Nếu tham số 1 là file thì đọc nội dung
if [ -f "$1" ]; then
    ACCOUNTS=$(cat "$1")
    echo "Đọc từ file: $1 ($(echo "$ACCOUNTS" | wc -l) dòng)"
else
    ACCOUNTS="$1"
fi

echo "Gửi tới: $MASTER_URL/api/jobs"
echo ""

# Escape cho JSON
ACCOUNTS_JSON=$(echo "$ACCOUNTS" | python -c "import sys,json; print(json.dumps(sys.stdin.read()))")

RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"text\": $ACCOUNTS_JSON}" \
    "$MASTER_URL/api/jobs")

echo "Response: $RESPONSE" | python -m json.tool 2>/dev/null || echo "$RESPONSE"

# Lấy job_id
JOB_ID=$(echo "$RESPONSE" | python -c "import sys,json; print(json.loads(sys.stdin.read()).get('job_id',''))" 2>/dev/null)

if [ -n "$JOB_ID" ] && [ "$JOB_ID" != "None" ]; then
    echo ""
    echo "========================================="
    echo "  Job ID: $JOB_ID"
    echo "  Xem tiến trình:"
    echo "    curl -H 'Authorization: Bearer TOKEN' $MASTER_URL/api/jobs/$JOB_ID"
    echo "  Xem kết quả:"
    echo "    curl -H 'Authorization: Bearer TOKEN' $MASTER_URL/api/jobs/$JOB_ID/rows"
    echo "========================================="

    # Theo dõi tiến trình
    echo ""
    echo "Đang theo dõi tiến trình..."
    while true; do
        sleep 5
        STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" "$MASTER_URL/api/jobs/$JOB_ID" 2>/dev/null)
        JOB_STATUS=$(echo "$STATUS" | python -c "import sys,json; d=json.loads(sys.stdin.read()); print(f\"Status: {d.get('status')} | Results: {d.get('results',{}).get('count',0)}/{d.get('total',0)} (OK: {d.get('results',{}).get('ok',0)})\")" 2>/dev/null)
        echo "  $JOB_STATUS"

        DONE=$(echo "$STATUS" | python -c "import sys,json; print(json.loads(sys.stdin.read()).get('status',''))" 2>/dev/null)
        if [ "$DONE" = "done" ]; then
            echo ""
            echo "✅ Job hoàn thành!"
            echo ""
            echo "Kết quả:"
            curl -s -H "Authorization: Bearer $TOKEN" "$MASTER_URL/api/jobs/$JOB_ID/rows" | \
                python -c "
import sys, json
data = json.loads(sys.stdin.read())
for row in data.get('rows', []):
    status = row.get('status', '')
    icon = '✅' if status == 'OK' else '❌'
    print(f\"  {icon} {row.get('account','')} | {status} | UID: {row.get('uid','')} | {row.get('name','')} | Lv.{row.get('level','')}\")
" 2>/dev/null
            break
        fi
    done
fi
