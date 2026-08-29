# 🚀 Biến Samsung A51 thành Server Check Account Garena

## Kiến trúc

```
┌──────────────────────────────────────────────────────────┐
│                    INTERNET                               │
│                       │                                   │
│          https://xxx-yyy.trycloudflare.com                │
│                       │                                   │
│              ┌────────▼────────┐                          │
│              │ Cloudflare CDN  │  (miễn phí, ko cần       │
│              │   Tunnel Proxy  │   domain, ko cần port    │
│              └────────┬────────┘   forwarding)            │
│                       │                                   │
├───────────────────────┼──────────────────────────────────┤
│     SAMSUNG A51       │  (Termux)                         │
│              ┌────────▼────────┐                          │
│              │  Master Server  │  :8761                   │
│              │  (điều phối)    │                          │
│              └────────┬────────┘                          │
│                       │  claim/report                     │
│              ┌────────▼────────┐                          │
│              │ Satellite Worker│                          │
│              │ (check acc TCP) │                          │
│              └────────┬────────┘                          │
│                       │                                   │
│              ┌────────▼────────┐                          │
│              │ Garena Server   │  TCP :19000              │
│              │ (login check)   │                          │
│              └─────────────────┘                          │
└──────────────────────────────────────────────────────────┘
```

## Tổng quan 3 chế độ chạy

| Chế độ | Script | Mô tả |
|--------|--------|-------|
| **All-in-one** | `start_all_in_one.sh` | Master + Satellite + Tunnel trên 1 điện thoại |
| **Master only** | `start_master_tunnel.sh` | Chỉ master + tunnel (satellite ở máy khác) |
| **Satellite only** | `start_satellite.sh` | Chỉ worker (master ở Render/PC/máy khác) |

---

## Bước 1: Cài đặt Termux (chỉ làm 1 lần)

### 1.1 Cài Termux
- Tải **Termux** từ [F-Droid](https://f-droid.org/packages/com.termux/) (KHÔNG dùng bản Play Store - đã lỗi thời)
- Mở Termux, cho phép thông báo để chạy nền

### 1.2 Cài Termux:API (tùy chọn nhưng nên cài)
```bash
pkg install termux-api
```
(Cài thêm app **Termux:API** từ F-Droid để `termux-wake-lock` hoạt động)

### 1.3 Chạy script setup
```bash
# Tải repo hoặc copy files
pkg install -y git
git clone <URL_REPO_CUA_BAN> ~/checkpass
cd ~/checkpass/termux_a51

# Chạy setup
bash setup_termux.sh
```

**Hoặc cài thủ công:**
```bash
pkg update -y && pkg upgrade -y
pkg install -y python python-pip git openssl libffi clang build-essential

# Cài cloudflared
ARCH=$(uname -m)
curl -L -o $PREFIX/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
chmod +x $PREFIX/bin/cloudflared

# Python packages
pip install cryptography openpyxl
```

---

## Bước 2: Copy code vào điện thoại

### Cách A: Git clone
```bash
cd ~
git clone <URL_REPO> checkpass
```

### Cách B: SCP từ PC
```bash
# Trên Termux, bật SSH server:
pkg install openssh
sshd  # Chạy SSH server trên port 8022

# Trên PC (thay IP_DIEN_THOAI):
scp -P 8022 -r F:/checkpass/* user@IP_DIEN_THOAI:~/checkpass/
```

### Cách C: Dùng Termux storage
```bash
termux-setup-storage
# Copy files vào ~/storage/downloads/ rồi:
cp -r ~/storage/downloads/checkpass/* ~/checkpass/
```

---

## Bước 3: Cấu hình

### Đổi token bí mật
Mở file script tương ứng và đổi:
```bash
cd ~/checkpass/termux_a51
nano start_all_in_one.sh  # hoặc start_master_tunnel.sh
```
Tìm và đổi dòng:
```bash
export MASTER_TOKEN="thay-doi-token-bi-mat-cua-ban"
```
thành giá trị bí mật của bạn, ví dụ:
```bash
export MASTER_TOKEN="m4tKh4u$ieuM4nh123!"
```

### Điều chỉnh workers (tùy tải)
```bash
export WORKERS=4     # Bắt đầu với 4, tăng lên 6-8 nếu điện thoại OK
export START_GAP=3.0 # Giãn cách 3s giữa mỗi login TCP
```

---

## Bước 4: Chạy!

### Chế độ All-in-One (khuyên dùng khi mới bắt đầu)
```bash
cd ~/checkpass
bash termux_a51/start_all_in_one.sh
```

Output sẽ hiện:
```
[1/3] Master Server (port 8761)...
[master] Tổng bộ: http://0.0.0.0:8761 role=coordinator db=...
[2/3] Satellite Worker (4 workers)...
[satellite] a51-local khởi động: master=http://127.0.0.1:8761 workers=4 ...
[3/3] Cloudflare Tunnel...

  URL: https://random-words-here.trycloudflare.com   ← GHI LẠI URL NÀY!
```

### Test từ bất kỳ đâu
```bash
# Health check
curl -H "Authorization: Bearer thay-doi-token-bi-mat-cua-ban" \
     https://random-words-here.trycloudflare.com/healthz

# Gửi acc để check
curl -X POST \
     -H "Authorization: Bearer thay-doi-token-bi-mat-cua-ban" \
     -H "Content-Type: application/json" \
     -d '{"text": "user1|pass1\nuser2|pass2"}' \
     https://random-words-here.trycloudflare.com/api/jobs

# Xem kết quả (thay JOB_ID)
curl -H "Authorization: Bearer thay-doi-token-bi-mat-cua-ban" \
     https://random-words-here.trycloudflare.com/api/jobs/1

# Xem chi tiết từng acc
curl -H "Authorization: Bearer thay-doi-token-bi-mat-cua-ban" \
     https://random-words-here.trycloudflare.com/api/jobs/1/rows

# Export CSV
curl -H "Authorization: Bearer thay-doi-token-bi-mat-cua-ban" \
     -o results.csv \
     https://random-words-here.trycloudflare.com/api/jobs/1/export.csv
```

---

## Bước 5: Chạy nền (không cần giữ Termux mở)

### Dùng `tmux` (khuyên dùng)
```bash
pkg install tmux

# Tạo session
tmux new -s checkpass

# Chạy server trong tmux
bash termux_a51/start_all_in_one.sh

# Detach: nhấn Ctrl+B rồi D
# Giờ có thể tắt màn hình, server vẫn chạy

# Quay lại xem:
tmux attach -t checkpass
```

### Dùng `nohup`
```bash
nohup bash termux_a51/start_all_in_one.sh > ~/checkpass.log 2>&1 &
# Xem log:
tail -f ~/checkpass.log
```

---

## Giữ điện thoại không tắt / giữ Termux chạy nền

### Cài đặt Android
1. **Cài đặt > Pin > Tối ưu hóa pin** → Tìm Termux → chọn **Không tối ưu hóa**
2. **Cài đặt > Ứng dụng > Termux > Pin** → Tắt tất cả giới hạn nền
3. **Cài đặt > Màn hình > Hết giờ chờ màn hình** → đặt 30 phút hoặc dài hơn
4. **Notification Termux**: vuốt xuống, giữ thông báo Termux, chọn **Acquire wakelock**

### Trong Termux
```bash
# Giữ CPU hoạt động khi tắt màn hình
termux-wake-lock

# Khi muốn bỏ:
termux-wake-unlock
```

---

## API Reference

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/healthz` | Kiểm tra server còn sống |
| POST | `/api/jobs` | Tạo job check acc mới |
| GET | `/api/jobs/{id}` | Xem tóm tắt job |
| GET | `/api/jobs/{id}/rows` | Xem kết quả chi tiết |
| GET | `/api/jobs/{id}/export.csv` | Tải CSV kết quả |
| POST | `/api/claim` | Satellite lấy chunk |
| POST | `/api/report` | Satellite báo kết quả |
| POST | `/api/chunk/release` | Trả chunk chưa xong |

### Tạo job - Body JSON:
```json
{
  "text": "user1|pass1\nuser2|pass2\nuser3|pass3",
  "chunk_size": 100
}
```
Hoặc:
```json
{
  "accounts": ["user1|pass1", "user2|pass2"]
}
```

### Response tạo job:
```json
{
  "ok": true,
  "job_id": 1,
  "total": 3,
  "chunks": 1,
  "chunk_size": 100
}
```

### Response xem job:
```json
{
  "ok": true,
  "job_id": 1,
  "status": "done",
  "total": 3,
  "chunks": {"pending": 0, "claimed": 0, "done": 1},
  "results": {"count": 3, "ok": 2, "fail": 1}
}
```

---

## Troubleshooting

### ❌ `cloudflared: not found`
```bash
ARCH=$(uname -m)
echo "Kiến trúc: $ARCH"
# A51 = aarch64
curl -L -o $PREFIX/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
chmod +x $PREFIX/bin/cloudflared
```

### ❌ `cryptography` cài không được
```bash
# Cần build tools
pkg install -y clang build-essential openssl libffi python
CRYPTOGRAPHY_DONT_BUILD_RUST=1 pip install cryptography
```

### ❌ URL tunnel bị đổi mỗi lần chạy
Đúng rồi - tunnel miễn phí sẽ tạo URL ngẫu nhiên mới mỗi lần. Nếu cần URL cố định:
1. Đăng ký [Cloudflare Zero Trust](https://one.dash.cloudflare.com/) (miễn phí)
2. Tạo tunnel cố định:
```bash
cloudflared tunnel login
cloudflared tunnel create a51-server
cloudflared tunnel route dns a51-server check.yourdomain.com
cloudflared tunnel run a51-server
```

### ❌ Satellite báo "không kết nối được tổng bộ"
- Kiểm tra `MASTER_URL` đúng chưa
- Nếu cùng điện thoại: dùng `http://127.0.0.1:8761`
- Nếu khác máy: dùng URL tunnel hoặc IP LAN

### ❌ Garena từ chối login (mã lỗi)
- Giảm `WORKERS` xuống 2-3
- Tăng `START_GAP` lên 5-10s
- Đây là giới hạn từ Garena, không phải lỗi server

### ❌ Termux bị Android kill
- Xem mục **"Giữ điện thoại không tắt"** ở trên
- Trên Samsung: **Cài đặt > Chăm sóc pin và thiết bị > Pin > Giới hạn nền** → bỏ Termux ra

---

## Hiệu suất dự kiến trên A51

| Cấu hình | Accounts/phút | Ghi chú |
|-----------|--------------|---------|
| 2 workers, gap 5s | ~20 | An toàn, ít bị rate limit |
| 4 workers, gap 3s | ~50-70 | Cân bằng |
| 6 workers, gap 2s | ~100+ | Có thể bị Garena limit |
| 8 workers, gap 1s | ~150+ | Rủi ro cao bị block |

**Khuyên dùng**: bắt đầu `WORKERS=4, START_GAP=3.0` rồi tăng dần.

---

## Sơ đồ luồng dữ liệu

```
Bạn (PC/Điện thoại khác)
    │
    │  POST /api/jobs  {"text": "user1|pass1\n..."}
    ▼
Cloudflare Tunnel (https://xxx.trycloudflare.com)
    │
    ▼
Master Server (:8761) trên A51
    │  Chia accounts thành chunks ≤ 1000
    │  Lưu vào SQLite
    ▼
Satellite Worker (trên A51 hoặc máy khác)
    │  POST /api/claim  → nhận 1 chunk
    │  Check từng acc qua Garena TCP
    │  POST /api/report → trả kết quả
    ▼
Bạn
    GET /api/jobs/{id}       → xem tiến trình
    GET /api/jobs/{id}/rows  → xem chi tiết
    GET /api/jobs/{id}/export.csv → tải file
```
