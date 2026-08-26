# Hướng dẫn deploy lên Render.com

## Đã chuẩn bị xong gì

1. **`garena_tcp.py`** đã được copy từ thư mục lồng ra **thư mục gốc** (SHA-256 khớp bản gốc) để repo deploy tự chứa đầy đủ.
2. **`garena_tcp_login_chrome.py`**: tự tìm `garena_tcp.py` ở vị trí cũ (máy local) hoặc đặt cạnh file (trên Render) — vẫn kiểm tra SHA-256.
3. **`garena_api_test_chrome1.py`**:
   - Bind theo biến môi trường `PORT` / `HOST` của Render (mặc định local vẫn `127.0.0.1:8766`, không ảnh hưởng chạy tại máy).
   - Tự tắt mở Chrome khi chạy trên cloud (env `RENDER`).
   - Hỗ trợ mật khẩu truy cập qua env `API_TEST_PASSWORD` (Basic Auth) — trang web và API đều được chặn nếu chưa nhập đúng.
3. **`requirements.txt`** (chỉ cần `cryptography`), **`render.yaml`**, **`.gitignore`**.

## Các bước deploy

### 1. Đưa code lên GitHub

```powershell
cd "C:\Users\ADMIN'\Downloads\TOOL AUTO UP LEVEL (1)"
git init
git add .
git commit -m "Deploy Garena check tool to Render"
# Tạo repo mới trên GitHub rồi:
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

> `.gitignore` đã loại `accounts_probe.txt` (chứa mật khẩu) — tuyệt đối đừng commit file chứa tài khoản/mật khẩu nào.

### 2. Tạo Web Service trên Render

1. Vào https://dashboard.render.com → **New → Web Service**.
2. Kết nối repo GitHub vừa tạo.
3. Nếu có file `render.yaml`, Render tự đọc cấu hình. Kiểm tra:
   - **Runtime:** Python
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python garena_api_test_chrome1.py --no-browser --timeout 20`
4. Thêm biến môi trường:
   - `API_TEST_PASSWORD` = một mật khẩu bất kỳ (bắt buộc nên đặt, vì URL là công khai).
   - `PYTHON_VERSION` = `3.13.4` (nếu build báo không có phiên bản này thì đổi sang bản khác ≥ 3.10, ví dụ `3.12.7`, hoặc xóa biến này).
5. Bấm **Create Web Service** và chờ build.

### 3. Sử dụng

- Mở URL `https://<tên-service>.onrender.com/`.
- Trình duyệt sẽ hỏi User/Password: user nhập **bất kỳ**, password là giá trị `API_TEST_PASSWORD` bạn đã đặt.
- Trang web dùng y hệt bản local (kiểm tra lẻ + batch).

## Lưu ý quan trọng

- **Bảo mật:** đây là công cụ nhận mật khẩu Garena. Khi public lên internet:
  - Luôn đặt `API_TEST_PASSWORD`.
  - Không chia sẻ URL; ai có URL + mật khẩu đều dùng được.
  - Render lưu log build/deploy, không log nội dung request (tool đã tắt log HTTP).
- **Gói Free** ngủ sau ~15 phút không truy cập; batch đang chạy sẽ bị ngắt khi service ngủ hoặc deploy lại. Chạy batch dài nên nâng **Starter**.
- **IP datacenter:** Garena dễ kích hoạt captcha/challenge hơn với IP server (kết quả có thể hiện `challenge_required`). TCP login thường vẫn qua bình thường.
- **Batch lớn:** free plan chỉ có 512 MB RAM và CPU yếu; giữ workers nhỏ (2–4) và gap ≥ 3s để tránh bị Garena khóa tạm thời.
- Cập nhật code: `git push` là Render tự deploy lại.
