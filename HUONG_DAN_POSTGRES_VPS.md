# PostgreSQL VPS cho master server

Master ưu tiên PostgreSQL khi đặt `DATABASE_URL` (hoặc `POSTGRES_URL`). Nếu biến này không có thì hệ thống vẫn dùng Turso hoặc `master.db` như trước.

## Chuẩn bị database trên VPS

Tạo database và user trên PostgreSQL VPS:

```sql
CREATE USER checkpass WITH PASSWORD 'doi-mat-khau-dai-va-ngau-nhien';
CREATE DATABASE checkpass OWNER checkpass;
```

Chuỗi kết nối có dạng:

```text
postgresql://checkpass:MAT_KHAU@IP_HOAC_DOMAIN_VPS:5432/checkpass?sslmode=require
```

Nếu master và PostgreSQL cùng nằm trong mạng riêng của VPS, dùng private IP và bỏ `sslmode=require` khi PostgreSQL chưa cấu hình TLS.

## Cấu hình master

Trên Render, vào service `garena-master` → **Environment** → thêm:

```text
DATABASE_URL=postgresql://checkpass:MAT_KHAU@IP_HOAC_DOMAIN_VPS:5432/checkpass?sslmode=require
```

Redeploy service. Master tự tạo bảng và index khi khởi động. Nếu `DATABASE_URL` sai, master dừng khởi động để tránh âm thầm quay về database khác.

Khi dùng Render, VPS cần cho phép kết nối PostgreSQL từ service Render. Chỉ mở port 5432 khi cần thiết, đặt mật khẩu mạnh và ưu tiên tunnel/VPN hoặc TLS.

## Chuyển dữ liệu cũ từ `master.db`

Chạy ở máy đang giữ file SQLite cũ:

```powershell
python migrate_master_sqlite_to_postgres.py --sqlite master.db --database-url "postgresql://checkpass:MAT_KHAU@IP_VPS:5432/checkpass?sslmode=require"
```

Lệnh dừng nếu database đích đã có dữ liệu. Chỉ dùng `--replace` khi bạn muốn xóa dữ liệu PostgreSQL hiện tại rồi chép lại toàn bộ dữ liệu từ `master.db`.
