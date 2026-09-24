# checkpass

Master gọi `GET /healthz` của mỗi vệ tinh trong danh sách đã lưu ở trang quản trị mỗi 2 phút. Danh sách được đọc lại từ khóa `satellite_targets` trong bảng `app_settings` ở mỗi lượt, nên thay đổi danh sách không cần khởi động lại master. Danh sách trống sẽ không gọi vệ tinh nào. Cần lưu URL công khai của vệ tinh, ví dụ `[checkpass3] https://checkpass3-wt3z.onrender.com`.

## SP1S SSO và thanh toán Checkban

Người dùng Checkpass đăng nhập bằng tài khoản SP1S; license key cũ không còn được chấp nhận khi tích hợp SP1S được cấu hình. `MASTER_TOKEN` chỉ dành cho quản trị và vệ tinh.

Biến môi trường bắt buộc trên master:

- `AOVSHOP_API_URL`: URL backend AOVshop, không có `/api` ở cuối.
- `CHECKPASS_SERVICE_TOKEN`: chuỗi bí mật giống hệt backend AOVshop.
- `SP1S_FRONTEND_URL`: mặc định `https://sp1s.shop`.
- `CHECKPASS_PUBLIC_URL`: URL public của master, ví dụ `https://check.sp1s.shop`.

Backend AOVshop cần `CHECKPASS_SERVICE_TOKEN`, `CHECKPASS_ALLOWED_ORIGINS` và `CHECKPASS_URL`. Nên deploy backend trước để migration bổ sung cột tiền chính xác và các bảng SSO/billing chạy xong, sau đó deploy frontend SP1S, cuối cùng mới deploy master.

Tiền được lưu chính xác theo đơn vị 0,1 VND (`balance_tenths`). Chế độ số lượng tạm giữ `số tài khoản × 0,3đ` và quyết toán theo số OK. Chế độ thời gian có giá cố định `5.000đ / 30 phút`; quyền còn hiệu lực được tái sử dụng mà không trừ thêm.
