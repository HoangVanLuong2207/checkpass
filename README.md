# checkpass

Master gọi `GET /healthz` của mỗi vệ tinh trong danh sách đã lưu ở trang quản trị mỗi 2 phút. Vệ tinh thường và VVIP được quản lý bằng hai danh sách riêng (`satellite_targets`, `vvip_satellite_targets`), nên thay đổi danh sách không cần khởi động lại master. Service thường chạy `python service-litesel.py`; service VVIP chạy `python service-liteselVVIP.py` và chỉ claim hàng đợi VVIP.

## SP1S SSO và thanh toán Checkban

Người dùng Checkpass đăng nhập bằng tài khoản SP1S; license key cũ không còn được chấp nhận khi tích hợp SP1S được cấu hình. `MASTER_TOKEN` chỉ dành cho quản trị và vệ tinh.

Biến môi trường bắt buộc trên master:

- `AOVSHOP_API_URL`: URL backend AOVshop, không có `/api` ở cuối.
- `CHECKPASS_SERVICE_TOKEN`: chuỗi bí mật giống hệt backend AOVshop.
- `SP1S_FRONTEND_URL`: mặc định `https://sp1s.shop`.
- `CHECKPASS_PUBLIC_URL`: URL public của master, ví dụ `https://check.sp1s.shop`.

Backend AOVshop cần `CHECKPASS_SERVICE_TOKEN`, `CHECKPASS_ALLOWED_ORIGINS` và `CHECKPASS_URL`. Master và service VVIP cần dùng chung `VVIP_MASTER_TOKEN`, tách biệt với `MASTER_TOKEN` của vệ tinh thường. Nên deploy backend trước để migration bổ sung cột tiền chính xác và các bảng SSO/billing chạy xong, sau đó deploy frontend SP1S, cuối cùng mới deploy master.

Tiền được lưu chính xác theo đơn vị 0,1 VND (`balance_tenths`). Chế độ số lượng tạm giữ `số tài khoản × 0,3đ`, sau đó quyết toán `số đúng pass × 0,3đ + số Không thể log × 0,1đ`. Đúng pass gồm Đủ LV, Chưa đạt, Bị khóa và CTNV; Chưa thể check không tính phí. Chế độ thời gian thường có giá `5.000đ / 30 phút`; VVIP có hàng đợi và entitlement riêng với giá `10.000đ / 30 phút`.
