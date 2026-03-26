# OpenVPN Premium Management Panel (Django)

Hệ thống quản lý OpenVPN nâng cao được xây dựng trên nền tảng Django với giao diện Jazzmin chuyên nghiệp.

## Tính năng chính
- **Giao diện Quản trị Jazzmin**: Quản lý khách hàng, cấu hình và lịch sử trực quan.
- **Tích hợp Redis**: Quản lý OTP siêu tốc và caching hệ thống.
- **Hồ sơ Người dùng (Custom User)**: Theo dõi Lớp học, Gói đăng ký, Ngày hết hạn và Số dư.
- **Mạng LAN Nội bộ**: Hỗ trợ `client-to-client` cho phép giao tiếp LAN giữa các VPN clients.
- **Thông báo FCM**: Tích hợp Firebase Cloud Messaging cho WebPush.
- **Di chuyển Dữ liệu**: Công cụ nhập người dùng cũ và yêu cầu cập nhật thông tin khi đăng nhập lần đầu.

## Cài đặt & Sử dụng

### 1. Chuẩn bị Environment
Sử dụng Conda để cài đặt các phụ thuộc:
```bash
conda env create -f environment.yml
conda activate vpn_panel
```

### 2. Cấu hình
Mọi cấu hình hệ thống hiện được tập trung tại `vpn_project/settings.py` trong biến `VPN_SETTINGS`.

### 3. Di chuyển dữ liệu cũ
Để nhập danh sách người dùng cũ:
```bash
python manage.py import_users <duong_dan_file.txt>
```

### 4. Chạy hệ thống
```bash
python manage.py runserver 0.0.0.0:8000
```

## Cấu trúc thư mục
- `vpn_project/`: Cấu hình chính của Django.
- `vpn_panel/`: Logic quản lý VPN (Models, Views, Services).
- `templates/`: Giao diện người dùng (Vanilla Premium CSS).
- `static/`: Chứa file CSS, JS và hình ảnh.

## Liên hệ
- Tác giả: KienPC
- Dự án được tối ưu hóa cho hiệu suất cao và bảo mật.
